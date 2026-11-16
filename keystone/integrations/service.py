"""Integration registry, configuration (secrets write-only), runs, and evidence from passing checks."""

from __future__ import annotations

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
from .providers.asm_edr import CrowdStrikeProvider, SentinelOneProvider, SophosProvider
from .providers.asm_microsoft import MicrosoftProvider
from .providers.asm_rmm import ConnectWiseAutomateProvider, DattoRmmProvider, NCentralProvider, NinjaOneProvider
from .providers.asm_vuln import QualysProvider, Rapid7Provider, TenableProvider
from .providers.aws import AwsProvider
from .providers.base import InventoryProvider, Provider
from .providers.entra import EntraProvider
from .providers.github import GitHubProvider
from .providers.website import WebsiteProvider

PROVIDERS: dict[str, Provider] = {p.key: p for p in (
    WebsiteProvider(), GitHubProvider(), AwsProvider(), EntraProvider(),
    # attack surface sources (keystone/asm): read-only inventory, decision 2026-11-16
    MicrosoftProvider(), CrowdStrikeProvider(), SentinelOneProvider(), SophosProvider(),
    NinjaOneProvider(), DattoRmmProvider(), NCentralProvider(), ConnectWiseAutomateProvider(),
    TenableProvider(), QualysProvider(), Rapid7Provider(),
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
    config = {f.name: values[f.name] for f in p.fields if not f.secret and f.name in values}
    secrets = {f.name: values[f.name] for f in p.fields if f.secret and values.get(f.name)}
    return config, secrets


def save_integration(session: Session, actor, integration_id: int | None = None, *, provider_key: str | None = None, name: str | None = None, values: dict | None = None, schedule_hours: int | None = None, enabled: bool | None = None) -> Integration:
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
        if isinstance(p, InventoryProvider):  # attack surface source: collect now, store below
            inventory, outcomes = p.collect(i.config or {}, secrets), []
        else:
            outcomes = p.run(i.config or {}, secrets, session)
        i.last_status, i.last_error = "ok", None
    except Exception as e:  # noqa: BLE001 - any provider failure becomes an 'error' result, never a pass
        msg = str(e)[:500] if isinstance(e, ValueError) else f"{type(e).__name__}: run failed"
        outcomes = []
        i.last_status, i.last_error = "error", msg
        from .providers.base import Outcome

        outcomes = [Outcome(c.key, "error", msg) for c in p.checks]
    i.last_run_at = now
    codes = {c.code: c for c in session.scalars(select(CommonControl))}
    valid_until = today() + timedelta(days=max(2, i.schedule_hours * 2 // 24 + 2))
    results = []
    for o in outcomes:
        d = p.check(o.key)
        r = CheckResult(integration_id=i.id, check_key=o.key, title=d.title, result=o.result, summary=o.summary, details=o.details or None, controls=list(d.controls), run_at=now)
        session.add(r)
        results.append(r)
        if o.result == "pass":
            title = f"Automated check: {d.title} ({i.name})"
            description = f"{o.summary}. Checked {now:%Y-%m-%d %H:%M} UTC by the {p.name} integration."
            for code in d.controls:
                if code not in codes:
                    continue
                # SC-ERR-004: one evidence record per check and control, refreshed on each passing run.
                ev = session.scalar(select(Evidence).where(Evidence.common_control_id == codes[code].id, Evidence.title == title, Evidence.kind == "note"))
                if ev is None:
                    session.add(Evidence(common_control_id=codes[code].id, title=title, kind="note", description=description, collected_on=today(), valid_until=valid_until))
                else:
                    ev.description, ev.collected_on, ev.valid_until = description, today(), valid_until
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


def test(session: Session, actor, provider_key: str | None = None, values: dict | None = None, integration_id: int | None = None) -> list[dict]:
    """Dry run: run the checks with the given settings (stored secrets fill any left empty) without
    saving anything: no results, no evidence, no change to the integration."""
    authorize(session, actor, "integration.manage")
    stored_config, stored_secrets = {}, {}
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
            inventory, outcomes = p.collect(config, secrets, preview=True), []
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
        return [inventory_preview(inventory)]
    log_event(session, actor, "integration_test", "Integration", integration_id, f"Tested {p.name}: " + ", ".join(f"{o.key}={o.result}" for o in outcomes))
    return [{"check_key": o.key, "title": p.check(o.key).title, "result": o.result, "summary": o.summary} for o in outcomes]


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
    code = session.get(CommonControl, control_id).code
    out = []
    for i in session.scalars(select(Integration).where(Integration.enabled.is_(True))):
        out += [r for r in latest_results(session, i.id) if code in (r.controls or [])]
    return out


def history(session: Session, integration_id: int, limit: int = 200) -> list[CheckResult]:
    return list(session.scalars(select(CheckResult).where(CheckResult.integration_id == integration_id).order_by(CheckResult.run_at.desc()).limit(limit)))


def due(session: Session) -> list[Integration]:
    now = utcnow()
    return [i for i in session.scalars(select(Integration).where(Integration.enabled.is_(True))) if i.last_run_at is None or i.last_run_at + timedelta(hours=i.schedule_hours) <= now]
