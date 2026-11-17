"""Baselines (the organisation's requirements), evaluation into findings, exceptions, alerts and evidence."""

from __future__ import annotations

import smtplib
from collections import defaultdict
from datetime import date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.audit import log_event
from keystone.core.auth import User, expired
from keystone.core.db import utcnow
from keystone.core.rbac import Role
from keystone.core.services import authorize, get_or_404, require_text, today

from .models import ENTITIES, SEVERITIES, AsmDevice, AsmFinding, AsmIdentity, AsmSetting, Baseline
from .vocabulary import DEVICE_TYPES, PROPERTIES

OPERATORS = {"is_true": "is on", "is_false": "is off", "lte": "at most", "gte": "at least", "eq": "equals", "ne": "is not"}

# Recommended starting set. Organisations adjust scope, severity and thresholds.
RECOMMENDED = [
    ("Devices have an EDR agent", "device", "covered_by_edr", "is_true", None, {"device_types": ["workstation", "server"]}, "critical", ["KC-TEC-07", "KC-TEC-01"], "flag"),
    ("EDR agent active and healthy", "device", "edr_active", "is_true", None, {"device_types": ["workstation", "server"]}, "high", ["KC-TEC-07"], "ignore"),
    ("Disk encryption on", "device", "disk_encrypted", "is_true", None, {"device_types": ["workstation", "mobile"]}, "high", ["KC-TEC-01", "KC-TEC-24", "KC-PHY-09"], "flag"),
    ("Anti-malware up to date", "device", "av_up_to_date", "is_true", None, {"device_types": ["workstation", "server"]}, "high", ["KC-TEC-07"], "ignore"),
    ("Firewall on", "device", "firewall_on", "is_true", None, {"device_types": ["workstation"]}, "medium", ["KC-TEC-20", "KC-TEC-01"], "ignore"),
    ("Managed by RMM", "device", "covered_by_rmm", "is_true", None, {"device_types": ["workstation", "server"]}, "medium", ["KC-ORG-09", "KC-TEC-09"], "flag"),
    ("Scanned for vulnerabilities", "device", "covered_by_vuln", "is_true", None, {"device_types": ["workstation", "server"]}, "medium", ["KC-TEC-08"], "flag"),
    ("Seen in the last 14 days", "device", "last_seen_days", "lte", "14", {}, "medium", ["KC-ORG-09"], "ignore"),
    ("No security patches pending", "device", "patches_pending", "lte", "0", {"device_types": ["workstation", "server"]}, "medium", ["KC-TEC-08"], "ignore"),
    ("Critical vulnerabilities fixed within 7 days", "device", "oldest_critical_vuln_days", "lte", "7", {}, "critical", ["KC-TEC-08"], "ignore"),
    ("High vulnerabilities fixed within 30 days", "device", "oldest_high_vuln_days", "lte", "30", {}, "high", ["KC-TEC-08"], "ignore"),
    ("No vulnerabilities with a known exploit", "device", "exploitable_vulns", "lte", "0", {}, "critical", ["KC-TEC-08", "KC-ORG-07"], "ignore"),
    ("No active threats", "device", "threats_active", "lte", "0", {}, "critical", ["KC-TEC-07", "KC-ORG-25"], "ignore"),
    ("Compliant in device management", "device", "mdm_compliant", "is_true", None, {}, "medium", ["KC-TEC-01"], "ignore"),
    ("MFA registered for every enabled account", "identity", "mfa_registered", "is_true", None, {"enabled_only": True}, "critical", ["KC-TEC-05", "KC-ORG-17"], "flag"),
    ("No enabled accounts unused for 90 days", "identity", "last_sign_in_days", "lte", "90", {"enabled_only": True}, "medium", ["KC-ORG-18"], "ignore"),
    ("Tenant and cloud settings meet their targets", "setting", "compliant", "is_true", None, {}, "medium", ["KC-TEC-09", "KC-ORG-23"], "ignore"),
]


# ---- baseline configuration (integration.manage) ---------------------------------------------------------

def validate(entity: str, prop: str, op: str, value: str | None, scope: dict, severity: str, missing: str) -> None:
    if entity not in ENTITIES:
        raise ValueError(f"entity must be one of {ENTITIES}")
    spec = PROPERTIES.get(prop)
    if spec is None or spec[0] != entity:
        raise ValueError(f"{prop!r} is not a {entity} property.")
    if op not in OPERATORS:
        raise ValueError(f"operator must be one of {', '.join(OPERATORS)}")
    if spec[1] == "bool" and op not in ("is_true", "is_false"):
        raise ValueError("Use 'is on' or 'is off' for yes/no properties.")
    if spec[1] == "int":
        if op in ("is_true", "is_false"):
            raise ValueError("Use a comparison for numeric properties.")
        try:
            int(value or "")
        except ValueError:
            raise ValueError("Enter a whole number to compare with.") from None
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}")
    if missing not in ("flag", "ignore"):
        raise ValueError("missing must be flag or ignore")
    if not isinstance(scope, dict) or set(scope) - {"device_types", "os", "enabled_only", "categories"}:
        raise ValueError("Scope can limit by device_types, os, enabled_only or categories.")
    if set(scope.get("device_types", [])) - set(DEVICE_TYPES):
        raise ValueError(f"device types must be among {DEVICE_TYPES}")
    if len(scope.get("os", [])) > 10 or any(len(str(o)) > 40 for o in scope.get("os", [])):
        raise ValueError("At most 10 short OS names.")


def save_baseline(session: Session, actor, baseline_id: int | None = None, **fields) -> Baseline:
    authorize(session, actor, "integration.manage")
    b = get_or_404(session, Baseline, baseline_id) if baseline_id else Baseline(scope={}, controls=[], missing="flag", enabled=True, severity="medium")
    allowed = {"name", "entity", "property", "operator", "value", "scope", "severity", "controls", "missing", "enabled"}
    if set(fields) - allowed:
        raise ValueError(f"fields not editable here: {', '.join(sorted(set(fields) - allowed))}")
    merged = {k: getattr(b, k) for k in allowed} | fields
    merged["name"] = require_text(merged["name"], "Baseline name")[:200]
    validate(merged["entity"], merged["property"], merged["operator"], merged["value"], merged["scope"] or {}, merged["severity"], merged["missing"])
    from keystone.frameworks.models import CommonControl

    codes = {c.code for c in session.scalars(select(CommonControl))}
    if set(merged["controls"] or []) - codes:
        raise ValueError("Unknown control code: " + ", ".join(sorted(set(merged["controls"]) - codes)))
    for k, v in merged.items():
        setattr(b, k, v)
    session.add(b)
    session.flush()
    return b


def add_recommended(session: Session, actor) -> list[Baseline]:
    """Create the recommended baselines that don't exist yet (by name)."""
    authorize(session, actor, "integration.manage")
    have = {b.name for b in session.scalars(select(Baseline))}
    out = []
    for name, entity, prop, op, value, scope, sev, controls, missing in RECOMMENDED:
        if name not in have:
            out.append(save_baseline(session, actor, name=name, entity=entity, property=prop, operator=op, value=value, scope=scope, severity=sev, controls=controls, missing=missing))
    return out


def describe(b: Baseline) -> str:
    label = PROPERTIES[b.property][2]
    return f"{label} {OPERATORS[b.operator]}{f' {b.value}' if b.value is not None and b.operator not in ('is_true', 'is_false') else ''}"


# ---- evaluation ----------------------------------------------------------------------------------------

def _in_scope(b: Baseline, entity) -> bool:
    sc = b.scope or {}
    if b.entity == "device":
        if sc.get("device_types") and entity.device_type not in sc["device_types"]:
            return False
        if sc.get("os") and not any(o.lower() in (entity.os or "").lower() for o in sc["os"]):
            return False
        return not entity.retired
    if b.entity == "identity":
        if sc.get("enabled_only") and entity.properties.get("account_enabled") is False:
            return False
        return True
    if b.entity == "setting":
        return not sc.get("categories") or (entity.category or "") in sc["categories"]
    return False


def _value(b: Baseline, entity):
    if b.entity == "device":
        v = (entity.properties or {}).get(b.property)
        return v.get("value") if isinstance(v, dict) else None
    if b.entity == "identity":
        return (entity.properties or {}).get(b.property)
    return entity.compliant


def _meets(b: Baseline, value) -> bool:
    if b.operator == "is_true":
        return value is True
    if b.operator == "is_false":
        return value is False
    n = int(b.value or 0)
    try:
        v = int(value)
    except (TypeError, ValueError):
        return False
    return {"lte": v <= n, "gte": v >= n, "eq": v == n, "ne": v != n}[b.operator]


def _explain(b: Baseline, v) -> str:
    """A plain sentence for why an item misses the baseline."""
    if isinstance(v, bool):
        return "Not on" if b.operator == "is_true" else "On"
    limits = {"lte": "at most", "gte": "at least", "eq": "exactly", "ne": "anything but"}
    return f"Reported {v}; the baseline allows {limits.get(b.operator, '')} {b.value}".strip()


def _entities(session: Session, entity: str) -> list:
    model = {"device": AsmDevice, "identity": AsmIdentity, "setting": AsmSetting}[entity]
    return list(session.scalars(select(model)))


def _label(entity_type: str, e) -> str:
    return e.name if entity_type == "device" else e.upn if entity_type == "identity" else e.title


def evaluate(session: Session, actor=None) -> dict:
    """Compare every enabled baseline with the current data. Opens, refreshes and resolves findings; expires lapsed
    exceptions; files evidence for fully met baselines; alerts on new critical and high findings."""
    now, on = utcnow(), today()
    cache = {e: _entities(session, e) for e in ENTITIES}
    findings = {(f.baseline_id, f.entity_type, f.entity_id): f for f in session.scalars(select(AsmFinding))}
    new: list[AsmFinding] = []
    stats = {}
    for b in session.scalars(select(Baseline).where(Baseline.enabled.is_(True))):
        in_scope = [e for e in cache[b.entity] if _in_scope(b, e)]
        failing = 0
        for e in in_scope:
            key = (b.id, b.entity, e.id)
            v = _value(b, e)
            no_data = v is None
            bad = (no_data and b.missing == "flag") or (not no_data and not _meets(b, v))
            f = findings.get(key)
            if bad:
                failing += 1
                detail = "No connected tool reports this" if no_data else _explain(b, v)
                if f is None:
                    f = AsmFinding(baseline_id=b.id, entity_type=b.entity, entity_id=e.id, status="open", first_seen=now, last_seen=now, detail=detail, no_data=no_data)
                    session.add(f)
                    findings[key] = f
                    new.append(f)
                elif f.status == "resolved":
                    f.status, f.resolved_at, f.first_seen = "open", None, now
                    new.append(f)
                elif f.status == "excepted" and f.exception_until and f.exception_until < on:
                    f.status = "open"  # the exception lapsed
                    new.append(f)
                f.last_seen, f.detail, f.no_data = now, detail[:500], no_data
            elif f is not None and f.status in ("open", "excepted"):
                f.status, f.resolved_at = "resolved", now
        # Findings for entities that left the scope (or no longer exist) resolve too.
        ids = {e.id for e in in_scope}
        for (bid, et, eid), f in findings.items():
            if bid == b.id and eid not in ids and f.status in ("open", "excepted"):
                f.status, f.resolved_at = "resolved", now
        excepted = sum(1 for (bid, _, eid), f in findings.items() if bid == b.id and eid in ids and f.status == "excepted")
        stats[b.id] = {"in_scope": len(in_scope), "failing": failing, "excepted": excepted}
        _evidence(session, b, len(in_scope), failing - excepted, excepted)
    session.flush()
    _alert(session, new)
    if actor is not None:
        log_event(session, actor, "update", "AttackSurface", None, f"Baselines evaluated: {sum(s['failing'] for s in stats.values())} failing checks, {len(new)} new")
    return {"baselines": stats, "new_findings": len(new)}


def _evidence(session: Session, b: Baseline, in_scope: int, open_failing: int, excepted: int) -> None:
    """A baseline with no open gaps across at least one item is evidence for its controls (refreshed each run)."""
    from keystone.controls.models import Evidence
    from keystone.frameworks.models import CommonControl

    if in_scope == 0 or open_failing > 0:
        return
    title = f"Attack surface baseline met: {b.name}"
    desc = f"{in_scope} {b.entity}(s) checked against “{describe(b)}” from the connected tools; all meet it" + (f" ({excepted} with an approved exception)" if excepted else "") + f". Checked {utcnow():%Y-%m-%d %H:%M} UTC."
    for code in b.controls or []:
        c = session.scalar(select(CommonControl).where(CommonControl.code == code))
        if c is None:
            continue
        ev = session.scalar(select(Evidence).where(Evidence.common_control_id == c.id, Evidence.title == title, Evidence.kind == "note"))
        if ev is None:
            session.add(Evidence(common_control_id=c.id, title=title, kind="note", description=desc, collected_on=today(), valid_until=today() + timedelta(days=3)))
        else:
            ev.description, ev.collected_on, ev.valid_until = desc, today(), today() + timedelta(days=3)


def _alert(session: Session, new: list[AsmFinding]) -> None:
    """New critical and high findings: a notification for the device or account owner, or one summary per baseline for
    the ISMS managers when nobody owns it. Critical ones are also emailed straight away when email is set up."""
    from keystone.notifications.models import Notification

    if not new:
        return
    baselines = {b.id: b for b in session.scalars(select(Baseline))}
    users = [u for u in session.scalars(select(User).where(User.active.is_(True))) if not expired(u)]
    managers = [u.id for u in users if u.role == Role.ISMS_MANAGER.value] or [u.id for u in users if u.role == Role.ADMIN.value]
    active = {u.id for u in users}
    unowned: dict[int, int] = defaultdict(int)
    per_user: dict[int, list[str]] = defaultdict(list)

    def notify(uid: int, key: str, text: str, page: str) -> bool:
        exists = session.scalar(select(Notification.id).where(Notification.user_id == uid, Notification.key == key))
        if exists is None:
            session.add(Notification(user_id=uid, key=key, kind="asm", title=text[:500], page=page, created_at=datetime.now()))
            session.flush()
        return exists is None
    for f in new:
        b = baselines.get(f.baseline_id)
        if b is None or b.severity not in ("critical", "high"):
            continue
        model = {"device": AsmDevice, "identity": AsmIdentity, "setting": AsmSetting}[f.entity_type]
        e = session.get(model, f.entity_id)
        owner = getattr(e, "owner_user_id", None) if f.entity_type == "device" else getattr(e, "user_id", None) if f.entity_type == "identity" else None
        if owner in active:
            text = f"{b.severity.title()}: {_label(f.entity_type, e)} doesn't meet “{b.name}”"
            if notify(owner, f"asm:{f.id}:{f.first_seen:%Y%m%d%H%M%S%f}", text, f"/attack-surface?finding={f.id}") and b.severity == "critical":
                per_user[owner].append(text)
        else:
            unowned[b.id] += 1
    stamp = datetime.now()
    for bid, n in unowned.items():
        b = baselines[bid]
        text = f"{n} new {b.severity} finding(s): “{b.name}”"
        for m in managers:
            if notify(m, f"asm-new:{bid}:{stamp:%Y%m%d%H%M%S%f}", text, f"/attack-surface?baseline={bid}") and b.severity == "critical":
                per_user[m].append(text)
    session.flush()
    _email_now(session, per_user)
    from keystone.outbound.service import emit

    counts: dict[int, int] = defaultdict(int)
    for f in new:
        b = baselines.get(f.baseline_id)
        if b is not None and b.severity in ("critical", "high"):
            counts[b.id] += 1
    for bid, n in counts.items():
        b = baselines[bid]
        emit(session, "finding.opened", title=f"{n} new {b.severity} finding(s): {b.name}", severity=b.severity, page=f"/attack-surface?tab=findings&baseline={bid}")


def _email_now(session: Session, per_user: dict[int, list[str]]) -> None:
    from keystone.core.settings import get_settings
    from keystone.notifications import mailer
    from keystone.notifications import service as ntf

    s = ntf.smtp(session)
    if not per_user or not s.enabled or not s.from_address:
        return
    base = get_settings().public_url
    msgs = []
    for uid, lines in per_user.items():
        u = session.get(User, uid)
        if not u or not u.email:
            continue
        body = "New critical attack surface findings:\n\n" + "\n".join(f"- {line}" for line in lines[:50]) + (f"\n\nOpen Keystone: {base}/attack-surface\n" if base else "\n")
        msgs.append(mailer.build(s.from_address, s.from_name, u.email, f"Keystone: {len(lines)} new critical attack surface finding(s)", body))
    try:
        mailer.send(ntf._cfg(s), msgs)
    except (smtplib.SMTPException, OSError, ValueError) as e:  # best effort: the inbox notification is already stored
        s.last_error = ntf._describe(e)


# ---- exceptions (risk.accept; not the owner of the device or account) ---------------------------------------

MAX_EXCEPTION_DAYS = 366


def grant_exception(session: Session, actor, finding_id: int, reason: str, until: date) -> AsmFinding:
    authorize(session, actor, "risk.accept")
    f = get_or_404(session, AsmFinding, finding_id)
    if f.status != "open":
        raise ValueError("Only open findings can get an exception.")
    if until <= today() or until > today() + timedelta(days=MAX_EXCEPTION_DAYS):
        raise ValueError("The exception must end within a year.")
    owner = None
    if f.entity_type == "device":
        owner = getattr(session.get(AsmDevice, f.entity_id), "owner_user_id", None)
    elif f.entity_type == "identity":
        owner = getattr(session.get(AsmIdentity, f.entity_id), "user_id", None)
    if owner == actor.id:
        raise ValueError("Segregation of duties: you can't approve an exception for your own device or account.")
    f.status, f.exception_reason, f.exception_by_id, f.exception_until = "excepted", require_text(reason, "Reason")[:2000], actor.id, until
    session.flush()
    return f


def revoke_exception(session: Session, actor, finding_id: int) -> AsmFinding:
    authorize(session, actor, "risk.accept")
    f = get_or_404(session, AsmFinding, finding_id)
    if f.status != "excepted":
        raise ValueError("This finding has no exception.")
    f.status, f.exception_until = "open", None
    session.flush()
    return f
