"""Integration registry, configuration (secrets write-only), runs, and evidence from passing checks."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.controls.models import Evidence
from keystone.core import secrets as crypto
from keystone.core.audit import log_event
from keystone.core.db import utcnow
from keystone.core.services import authorize, get_or_404, require_text, today
from keystone.frameworks.models import CommonControl

from .models import CheckResult, Integration
from .providers.asm_cloud import AwsSecurityHubProvider, DefenderForCloudProvider, GoogleSccProvider
from .providers.asm_edr import CrowdStrikeProvider, SentinelOneProvider, SophosProvider
from .providers.agents_software import AgentSoftwareProvider
from .providers.asm_mdm import JamfProProvider, KandjiProvider
from .providers.asm_microsoft import MicrosoftProvider
from .providers.asm_rmm import ConnectWiseAutomateProvider, DattoRmmProvider, NCentralProvider, NinjaOneProvider
from .providers.asm_vuln import QualysProvider, Rapid7Provider, TenableProvider
from .providers.aws import AwsProvider
from .providers.base import InventoryProvider, Outcome, Provider
from .providers.hr import HR_PROVIDERS, HrProvider
from .providers.ticketing import TICKET_PROVIDERS, TicketProvider
from .providers.entra import EntraProvider
from .providers.github import GitHubProvider
from .providers.website import WebsiteProvider

PROVIDERS: dict[str, Provider] = {p.key: p for p in (
    WebsiteProvider(), GitHubProvider(), AwsProvider(), EntraProvider(),
    # attack surface sources (keystone/asm): read-only inventory, decision 2026-11-16
    MicrosoftProvider(), CrowdStrikeProvider(), SentinelOneProvider(), SophosProvider(),
    NinjaOneProvider(), DattoRmmProvider(), NCentralProvider(), ConnectWiseAutomateProvider(),
    TenableProvider(), QualysProvider(), Rapid7Provider(),
    # device management (round 9): read-only device lists
    JamfProProvider(), KandjiProvider(),
    # Keystone's own agents as a vulnerability source (round 9): packages matched against downloaded OSV data
    AgentSoftwareProvider(),
    # cloud posture (round 3): read-only posture assessments
    AwsSecurityHubProvider(), DefenderForCloudProvider(), GoogleSccProvider(),
    # ticketing (round 3): the only connectors that write, and only new tickets
    *TICKET_PROVIDERS,
    # HR systems (round 3): read-only source for the People register
    *HR_PROVIDERS,
)}


def provider(key: str) -> Provider:
    if key not in PROVIDERS:
        raise ValueError(f"Unknown integration {key}")
    return PROVIDERS[key]


def _split(p: Provider, values: dict) -> tuple[dict, dict]:
    known = {f.name for f in p.fields}
    unknown = set(values) - known
    if unknown:
        raise ValueError(f"Unknown settings: {sorted(unknown)}")
    for f in p.fields:
        if f.options and f.name in values and values[f.name] not in {v for v, _ in f.options}:
            raise ValueError(f"{f.label}: choose one of the listed options.")
    config = {f.name: values[f.name] for f in p.fields if not f.secret and f.name in values}
    secrets = {f.name: values[f.name] for f in p.fields if f.secret and values.get(f.name)}
    return config, secrets


def save_integration(session: Session, actor, integration_id: int | None = None, *, provider_key: str | None = None, name: str | None = None, values: dict | None = None, schedule_hours: int | None = None, enabled: bool | None = None,
                     credential_expires_on=None, clear_credential_expiry: bool = False) -> Integration:
    """Create or update. Secret fields are write-only: omit them to keep the stored value."""
    authorize(session, actor, "integration.manage")
    if integration_id:
        i = get_or_404(session, Integration, integration_id)
    else:
        i = Integration(provider=provider(provider_key or "").key, name="", config={})
    p = provider(i.provider)
    config, secrets = _split(p, values or {})
    stored = json.loads(crypto.decrypt(i.secret_enc)) if i.secret_enc else {}
    merged_config = {**(i.config or {}), **config}
    hf = getattr(p, "host_field", None)
    if hf and i.id and (i.config or {}).get(hf) != merged_config.get(hf) and not secrets:
        stored = {}  # SC-SSRF-003: credentials are only ever sent to the server they were entered for
    merged_secrets = {**stored, **secrets}
    missing = [f.label for f in p.fields if f.required and not (merged_secrets.get(f.name) if f.secret else merged_config.get(f.name))]
    if missing:
        raise ValueError("Missing: " + ", ".join(missing) + (" (the server address changed, so enter the credentials again)" if hf and i.id and not stored else ""))
    i.name = require_text(name or i.name or p.name, "Name")
    i.config = merged_config
    i.secret_enc = crypto.encrypt(json.dumps(merged_secrets)) if merged_secrets else None
    if schedule_hours is not None:
        if not 1 <= schedule_hours <= 24 * 30:
            raise ValueError("Schedule must be between 1 hour and 30 days.")
        i.schedule_hours = schedule_hours
    if enabled is not None:
        i.enabled = enabled
    if clear_credential_expiry:
        i.credential_expires_on = None
    elif credential_expires_on is not None:
        if credential_expires_on < today() - timedelta(days=365) or credential_expires_on > today() + timedelta(days=3660):
            raise ValueError("Enter the date the key or secret expires (within the next ten years).")
        i.credential_expires_on = credential_expires_on
    session.add(i)
    session.flush()
    return i


def run(session: Session, actor, integration_id: int) -> list[CheckResult]:
    """Run all checks now. Passing checks file evidence on their controls; errors are never treated as passing."""
    if actor is not None:
        authorize(session, actor, "integration.manage")
    i = get_or_404(session, Integration, integration_id)
    p = provider(i.provider)
    now = utcnow()
    inventory = None
    try:
        secrets = json.loads(crypto.decrypt(i.secret_enc)) if i.secret_enc else {}
        if isinstance(p, InventoryProvider):  # attack surface source: collect now, store below; its own checks from the data
            inventory = p.collect_in(session, i.config or {}, secrets) if p.needs_session else p.collect(i.config or {}, secrets)
            outcomes = p.assess(inventory)
        elif isinstance(p, HrProvider):  # HR system: apply people to the register
            from keystone.people import hr_sync

            outcomes = [Outcome("people", "pass", hr_sync.describe(hr_sync.sync(session, i, p.collect(i.config or {}, secrets))))]
        else:
            outcomes = p.run(i.config or {}, secrets, session)
            if isinstance(p, TicketProvider):  # ticketing: read open tickets' status, open automatic ones
                from keystone.ticketing.service import describe_sync, sync

                outcomes.append(Outcome("sync", "pass", describe_sync(sync(session, i, p, secrets))))
        i.last_status, i.last_error = "ok", None
        i.consecutive_failures, i.last_success_at = 0, now
    except Exception as e:  # noqa: BLE001 - any provider failure becomes an 'error' result, never a pass
        msg = str(e)[:500] if isinstance(e, ValueError) else f"{type(e).__name__}: run failed"
        outcomes = []
        i.last_status, i.last_error = "error", msg
        i.consecutive_failures = (i.consecutive_failures or 0) + 1
        outcomes = [Outcome(c.key, "error", msg) for c in p.checks]
    i.last_run_at = now
    codes = {c.code: c for c in session.scalars(select(CommonControl))}
    valid_until = today() + timedelta(days=max(2, i.schedule_hours * 2 // 24 + 2))
    previous = {r.check_key: r.result for r in latest_results(session, i.id)}
    results = []
    for o in outcomes:
        d = p.check(o.key)
        r = CheckResult(integration_id=i.id, check_key=o.key, title=d.title, result=o.result, summary=o.summary, details=o.details or None, controls=list(d.controls), run_at=now)
        session.add(r)
        results.append(r)
        if o.result == "pass":
            title = f"Automated check: {d.title} ({i.name})"
            description = f"{o.summary}. Checked {now:%Y-%m-%d %H:%M} UTC by the {p.name} integration. The attached file holds what the check found."
            for code in d.controls:
                if code not in codes:
                    continue
                # SC-ERR-004: one evidence record per check and control, refreshed on each passing run.
                ev = session.scalar(select(Evidence).where(Evidence.common_control_id == codes[code].id, Evidence.title == title, Evidence.kind == "note"))
                if ev is None:
                    ev = Evidence(common_control_id=codes[code].id, title=title, kind="note", description=description, collected_on=today(), valid_until=valid_until)
                    session.add(ev)
                    session.flush()
                else:
                    ev.description, ev.collected_on, ev.valid_until = description, today(), valid_until
                _attach_result(session, ev, i, p, d, o, now)
        if previous.get(o.key) == "pass" and o.result == "fail":
            _check_started_failing(session, i, d, o, codes)
        elif previous.get(o.key) == "fail" and o.result == "pass":
            _check_passes_again(session, i, d)
    if inventory is not None:
        # Outside the provider's error handling on purpose: a database error fails the run and rolls it back.
        from keystone.asm import baselines, ingest

        counts = ingest.ingest(session, i.id, i.name, i.provider, inventory)
        evaluation = baselines.evaluate(session)
        summary = (f"{counts['devices']} device(s) ({counts['new_devices']} new), {counts['vulnerabilities']} open vulnerabilit(ies), "
                   f"{counts['identities']} identit(ies), {counts['settings']} setting(s); {evaluation['new_findings']} new finding(s)")
        if inventory.notes:
            summary += ". " + "; ".join(inventory.notes)[:400]
        r = CheckResult(integration_id=i.id, check_key="inventory", title="Data collected", result="pass", summary=summary[:2000], details=counts, controls=[], run_at=now)
        session.add(r)
        results.append(r)
    log_event(session, actor, "integration_run", "Integration", i.id, f"{i.name}: " + ", ".join(f"{r.check_key}={r.result}" for r in results))
    session.flush()
    return results


# ---- raw results as evidence, and alerts when a check changes ---------------------------------------------------------

def _attach_result(session: Session, ev: Evidence, i: Integration, p: Provider, d, o: Outcome, now) -> None:
    """File what the check found as JSON on the evidence, at most once a day per check (SHA-256 kept with the file).
    Only the outcome is written: never the integration's settings or credentials."""
    from keystone.core.attachments import Attachment, save_attachment

    name = f"check-{o.key}-{now:%Y-%m-%d}.json"
    if session.scalar(select(Attachment.id).where(Attachment.entity_type == "Evidence", Attachment.entity_id == ev.id, Attachment.filename == name)):
        return
    doc = {"integration": i.name, "integration_ref": i.ref, "provider": p.name, "check": o.key, "title": d.title, "result": o.result, "summary": o.summary,
           "details": o.details or {}, "controls": list(d.controls), "checked_at": now.isoformat(timespec="seconds") + "Z"}
    data = json.dumps(doc, indent=2, sort_keys=True, default=str).encode()
    att = save_attachment(session, None, name, data, "Evidence", ev.id, external_channel="integration")
    ev.attachment_id = att.id


FLAP_WINDOW = 10  # results looked at
FLAP_CHANGES = 4  # pass/fail changes within the window that make a check "flapping"


def flapping(session: Session, integration_id: int, check_key: str) -> bool:
    """A check that keeps flipping between pass and fail (usually a timing or permission problem, not a real change)."""
    rows = list(session.scalars(select(CheckResult.result).where(CheckResult.integration_id == integration_id, CheckResult.check_key == check_key,
                                                                CheckResult.result.in_(("pass", "fail"))).order_by(CheckResult.run_at.desc()).limit(FLAP_WINDOW)))
    return sum(1 for a, b in zip(rows, rows[1:], strict=False) if a != b) >= FLAP_CHANGES


def _check_task_key(i: Integration, check_key: str) -> str:
    return f"integration-check:{i.id}:{check_key}"[:60]


def _event_key(*parts) -> str:
    """A notification key for one event: unique per run, so a repeat isn't swallowed by an earlier one."""
    return hashlib.sha256("|".join(str(p) for p in (*parts, utcnow().isoformat())).encode()).hexdigest()[:64]


def _notify_users(session: Session, users, key: str, title: str, page: str) -> None:
    from keystone.notifications.models import Notification

    for u in users:
        k = key[:64]
        if session.scalar(select(Notification.id).where(Notification.user_id == u.id, Notification.key == k)) is None:
            session.add(Notification(user_id=u.id, key=k, kind="system", title=title[:500], page=page[:200], created_at=utcnow()))


def _managers(session: Session) -> list:
    from keystone.core.auth import User
    from keystone.core.rbac import has_permission

    return [u for u in session.scalars(select(User).where(User.active.is_(True))) if has_permission(u, "integration.manage")]


def _check_started_failing(session: Session, i: Integration, d, o: Outcome, codes: dict) -> None:
    """A check that passed last time fails now: a task for the owner of its first owned control (or the people who
    manage integrations), unless one is already open. Flapping checks get a note instead of a new task each time."""
    from keystone.core.auth import User
    from keystone.tasks.models import Task

    key = _check_task_key(i, o.key)
    open_task = session.scalar(select(Task).where(Task.template_key == key, Task.status.in_(("todo", "in_progress", "in_review"))))
    owner_id = next((codes[c].owner_id for c in d.controls if c in codes and codes[c].owner_id), None)
    owner = session.get(User, owner_id) if owner_id else None
    users = [owner] if owner is not None and owner.active else _managers(session)
    flap = flapping(session, i.id, o.key)
    page = "/integrations"
    if open_task is None and not flap:
        t = Task(title=f"Fix: {d.title} ({i.name}) started failing"[:300], template_key=key, frequency="once", status="todo", assignee_id=owner.id if owner and owner.active else None,
                 due_date=today() + timedelta(days=14),
                 description=f"The automated check passed on its previous run and fails now: {o.summary}"[:4000],
                 evidence_hint="When the check passes again, its evidence is filed automatically.")
        t.controls = [codes[c] for c in d.controls if c in codes]
        session.add(t)
        session.flush()
        page = f"/tasks?open={t.id}"
    elif open_task is not None:
        page = f"/tasks?open={open_task.id}"
    note = " (it keeps changing between pass and fail: check the integration's permissions or timing)" if flap else ""
    _notify_users(session, users, _event_key("check-fail", i.id, o.key), f"{d.title} ({i.name}) started failing{note}", page)


def _check_passes_again(session: Session, i: Integration, d) -> None:
    from keystone.core.auth import User
    from keystone.tasks.models import Task

    t = session.scalar(select(Task).where(Task.template_key == _check_task_key(i, d.key), Task.status.in_(("todo", "in_progress"))))
    if t is None or t.assignee_id is None:
        return
    u = session.get(User, t.assignee_id)
    if u is not None and u.active:
        _notify_users(session, [u], _event_key("check-ok", i.id, d.key), f"{d.title} ({i.name}) passes again: you can complete the task", f"/tasks?open={t.id}")


# ---- health -------------------------------------------------------------------------------------------------------

ESCALATE_AFTER = 3  # failed runs in a row before the ISMS managers are told too
CREDENTIAL_WARN_DAYS = 14


def health(i: Integration) -> dict:
    """How the integration is doing: overdue when its last good run is more than two schedules old."""
    now = utcnow()
    overdue = i.enabled and (i.last_success_at is None or i.last_success_at < now - timedelta(hours=i.schedule_hours * 2))
    days_left = (i.credential_expires_on - today()).days if i.credential_expires_on else None
    return {"consecutive_failures": i.consecutive_failures or 0, "escalated": (i.consecutive_failures or 0) >= ESCALATE_AFTER, "last_success_at": i.last_success_at,
            "overdue": bool(overdue and i.last_run_at is not None), "credential_expires_on": i.credential_expires_on, "credential_days_left": days_left,
            "credential_expiring": days_left is not None and days_left <= CREDENTIAL_WARN_DAYS}


def test(session: Session, actor, provider_key: str | None = None, values: dict | None = None, integration_id: int | None = None) -> list[dict]:
    """Dry run: run the checks with the given settings (stored secrets fill any left empty) without
    saving anything: no results, no evidence, no change to the integration."""
    authorize(session, actor, "integration.manage")
    stored_config: dict = {}
    stored_secrets: dict = {}
    if integration_id:
        i = get_or_404(session, Integration, integration_id)
        provider_key = i.provider
        stored_config = i.config or {}
        stored_secrets = json.loads(crypto.decrypt(i.secret_enc)) if i.secret_enc else {}
    p = provider(provider_key or "")
    config, secrets = _split(p, values or {})
    config, secrets = {**stored_config, **config}, {**stored_secrets, **secrets}
    missing = [f.label for f in p.fields if f.required and not (secrets.get(f.name) if f.secret else config.get(f.name))]
    if missing:
        raise ValueError("Missing: " + ", ".join(missing))
    inventory, msg = None, "Test failed"
    try:
        if isinstance(p, InventoryProvider):
            inventory = p.collect_in(session, config, secrets, preview=True) if p.needs_session else p.collect(config, secrets, preview=True)
            outcomes = []
        else:
            outcomes = p.run(config, secrets, session)
    except Exception as e:  # noqa: BLE001 - report, never pass
        msg = str(e)[:500] if isinstance(e, ValueError) else f"{type(e).__name__}: test failed"
        from .providers.base import Outcome

        outcomes = [Outcome(c.key, "error", msg) for c in p.checks]
    if isinstance(p, InventoryProvider):
        if inventory is None:  # the provider failed: outcomes holds nothing because inventory sources have no checks
            log_event(session, actor, "integration_test", "Integration", integration_id, f"Tested {p.name}: error")
            return [{"check_key": "inventory", "title": "Connection", "result": "error", "summary": msg}]
        log_event(session, actor, "integration_test", "Integration", integration_id, f"Tested {p.name}: ok")
        return [inventory_preview(inventory)] + ([permission_check(p, config, secrets)] if any(f.secret for f in p.fields) else [])
    log_event(session, actor, "integration_test", "Integration", integration_id, f"Tested {p.name}: " + ", ".join(f"{o.key}={o.result}" for o in outcomes))
    out = [{"check_key": o.key, "title": p.check(o.key).title, "result": o.result, "summary": o.summary} for o in outcomes]
    if not any(o.result == "error" for o in outcomes):
        out.append(permission_check(p, config, secrets))
    return out


def permission_check(p: Provider, config: dict, secrets: dict) -> dict:
    """Does the key do more than read? Asked of the tool itself where it can tell; otherwise the guide's last step.
    A failed permission check is reported as unknown, never as read-only."""
    import httpx

    item = {"check_key": "permissions", "title": "Key is read-only"}
    try:
        rep = p.permissions(config, secrets)
    except ValueError as e:
        return {**item, "result": "unknown", "summary": str(e)[:300]}
    except (KeyError, OSError, httpx.HTTPError) as e:
        return {**item, "result": "unknown", "summary": f"Couldn't check the key's permissions ({type(e).__name__})."}
    if rep is None:
        return {**item, "result": "unknown", "summary": "This tool doesn't let a key see its own permissions: follow the last step of the setup guide to check them."}
    return {**item, "result": rep.result, "summary": rep.summary, "extra": rep.extra}


def inventory_preview(inv) -> dict:
    """What a dry run of an attack surface source found. Field names only (never values), to check the mapping."""
    props: dict[str, int] = {}
    for d in inv.devices:
        for k in d.props:
            props[k] = props.get(k, 0) + 1
    summary = (f"Found {len(inv.devices)} device(s), {len(inv.vulns)} vulnerabilit(ies), {len(inv.identities)} identit(ies) and "
               f"{len(inv.settings)} setting(s). Properties reported: " + (", ".join(f"{k} ({n})" for k, n in sorted(props.items())) or "none"))
    if inv.notes:
        summary += ". " + "; ".join(inv.notes)
    return {"check_key": "inventory", "title": "Data found (nothing saved)", "result": "pass", "summary": summary[:3000], "fields": inv.sample_fields}


def latest_results(session: Session, integration_id: int) -> list[CheckResult]:
    last = session.scalar(select(CheckResult.run_at).where(CheckResult.integration_id == integration_id).order_by(CheckResult.run_at.desc()).limit(1))
    if last is None:
        return []
    return list(session.scalars(select(CheckResult).where(CheckResult.integration_id == integration_id, CheckResult.run_at == last)))


def latest_results_for_control(session: Session, control_id: int) -> list[CheckResult]:
    control = session.get(CommonControl, control_id)
    if control is None:
        return []
    code = control.code
    out = []
    for i in session.scalars(select(Integration).where(Integration.enabled.is_(True))):
        out += [r for r in latest_results(session, i.id) if code in (r.controls or [])]
    return out


def history(session: Session, integration_id: int, limit: int = 200) -> list[CheckResult]:
    return list(session.scalars(select(CheckResult).where(CheckResult.integration_id == integration_id).order_by(CheckResult.run_at.desc()).limit(limit)))


def due(session: Session) -> list[Integration]:
    now = utcnow()
    return [i for i in session.scalars(select(Integration).where(Integration.enabled.is_(True))) if i.last_run_at is None or i.last_run_at + timedelta(hours=i.schedule_hours) <= now]
