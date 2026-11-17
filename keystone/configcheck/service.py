"""Configuration baselines: rules per platform, evaluation of hosts and firewalls, drift history, exceptions,
evidence and alerts; agent enrolment and reports; firewall configuration uploads.

Results are pass, fail, unknown (the value wasn't reported or couldn't be read: never shown as passing), na (a
prerequisite setting is off, e.g. SSH settings without an SSH server) or excepted (a failing rule with an approved,
time-limited exception).

Agents (agents/windows, agents/linux) are report-only: they read settings and post them here. Keystone never sends
them commands. Each agent exchanges the organisation's enrolment key for its own device token, which is stored here
only as a SHA-256 hash and can only post reports for that one device.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets as pysecrets
from collections import Counter
from datetime import date, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from keystone.core import secrets as crypto
from keystone.core.audit import log_event
from keystone.core.auth import User, expired
from keystone.core.db import utcnow
from keystone.core.rbac import Role
from keystone.core.services import authorize, get_or_404, require_text, today

from . import catalogue as cat
from . import parsers
from .models import ConfigAgentSettings, ConfigBaseline, ConfigFinding, ConfigRule, ConfigSnapshot, ConfigTarget

DEVICE_PREFIX = "kagt_"
ENROLMENT_PREFIX = "kenr_"
MAX_TARGETS = 5000
MAX_RULES = 200
MAX_EXCEPTION_DAYS = 366
SNAPSHOTS_KEPT = 500
STALE_FACTOR = 3  # an agent is stale after missing three reports in a row
FIREWALL_STALE_DAYS = 90  # an uploaded configuration older than this is shown as out of date


# ---- baselines and rules (integration.manage) --------------------------------------------------------------------

def _count(session: Session, query) -> int:
    return int(session.scalar(query) or 0)


def _check_platform(platform: str) -> str:
    if platform not in cat.PLATFORMS:
        raise ValueError(f"Platform must be one of {', '.join(cat.PLATFORMS)}.")
    return platform


def validate_rule(platform: str, key: str, operator: str, expected, severity: str, controls: list[str]) -> tuple[str, object, str, list[str]]:
    s = cat.setting(platform, key)
    if s is None:
        raise ValueError(f"{key!r} is not a {cat.PLATFORM_LABEL.get(platform, platform)} setting.")
    if operator not in cat.OPERATORS_BY_TYPE[s.type]:
        raise ValueError(f"For {s.title} use: {', '.join(cat.OPERATORS[o] for o in cat.OPERATORS_BY_TYPE[s.type])}.")
    if severity not in cat.SEVERITIES:
        raise ValueError(f"Severity must be one of {', '.join(cat.SEVERITIES)}.")
    if operator in ("is_true", "is_false", "empty"):
        expected = None
    elif operator in ("in", "not_in"):
        if not isinstance(expected, list) or not expected or len(expected) > 20:
            raise ValueError("Give between 1 and 20 values.")
        expected = [str(x).strip().lower()[:200] for x in expected if str(x).strip()]
        if not expected:
            raise ValueError("Give at least one value.")
    elif s.type == "int":
        try:
            expected = int(expected)
        except (TypeError, ValueError):
            raise ValueError("Enter a whole number to compare with.") from None
        if not -1 <= expected <= s.max_int:
            raise ValueError(f"The number must be between -1 and {s.max_int}.")
    else:
        if expected is None or not str(expected).strip():
            raise ValueError("Enter the value to compare with.")
        expected = str(expected).strip()[:200]
        if s.choices:
            expected = expected.lower()
    controls = [c.strip() for c in (controls or []) if isinstance(c, str) and c.strip()][:20]  # checked by _known_controls
    return operator, expected, severity, controls


def _known_controls(session: Session, codes: list[str]) -> list[str]:
    from keystone.frameworks.models import CommonControl

    known = set(session.scalars(select(CommonControl.code).where(CommonControl.code.in_(codes)))) if codes else set()
    unknown = [c for c in codes if c not in known]
    if unknown:
        raise ValueError(f"Unknown control code(s): {', '.join(unknown[:5])}.")
    return codes


def _set_default(session: Session, b: ConfigBaseline) -> None:
    for other in session.scalars(select(ConfigBaseline).where(ConfigBaseline.platform == b.platform, ConfigBaseline.id != b.id, ConfigBaseline.is_default.is_(True))):
        other.is_default = False
    b.is_default = True


def create_baseline(session: Session, actor, *, name: str, platform: str, description: str | None = None, recommended: bool = True, is_default: bool | None = None) -> ConfigBaseline:
    """A new baseline, filled with the recommended rules unless `recommended` is false. The first baseline of a
    platform becomes its default."""
    authorize(session, actor, "integration.manage")
    platform = _check_platform(platform)
    b = ConfigBaseline(name=require_text(name, "Name")[:200], platform=platform, description=(description or "").strip()[:4000] or None, enabled=True, is_default=False)
    session.add(b)
    session.flush()
    first = session.scalar(select(func.count(ConfigBaseline.id)).where(ConfigBaseline.platform == platform)) == 1
    if is_default or (is_default is None and first):
        _set_default(session, b)
    if recommended:
        from keystone.frameworks.models import CommonControl

        codes = set(session.scalars(select(CommonControl.code)))
        for s in cat.settings_for(platform):
            if s.recommended is None:
                continue
            op, expected, severity, controls = s.recommended
            session.add(ConfigRule(baseline_id=b.id, key=s.key, operator=op, expected=expected, severity=severity, controls=[c for c in controls if c in codes], enabled=True))
    session.flush()
    _reevaluate(session, platform)
    return b


def update_baseline(session: Session, actor, baseline_id: int, *, name: str | None = None, description: str | None = None, enabled: bool | None = None, is_default: bool | None = None) -> ConfigBaseline:
    authorize(session, actor, "integration.manage")
    b = get_or_404(session, ConfigBaseline, baseline_id)
    if name is not None:
        b.name = require_text(name, "Name")[:200]
    if description is not None:
        b.description = description.strip()[:4000] or None
    if enabled is not None:
        b.enabled = enabled
    if is_default is True:
        _set_default(session, b)
    elif is_default is False:
        b.is_default = False
    session.flush()
    _reevaluate(session, b.platform)
    return b


def delete_baseline(session: Session, actor, baseline_id: int) -> None:
    authorize(session, actor, "integration.manage")
    b = get_or_404(session, ConfigBaseline, baseline_id)
    platform = b.platform
    for t in session.scalars(select(ConfigTarget).where(ConfigTarget.baseline_id == b.id)):
        t.baseline_id = None
    rule_ids = list(session.scalars(select(ConfigRule.id).where(ConfigRule.baseline_id == b.id)))
    if rule_ids:
        session.execute(delete(ConfigFinding).where(ConfigFinding.rule_id.in_(rule_ids)))
    for r in session.scalars(select(ConfigRule).where(ConfigRule.baseline_id == b.id)):
        session.delete(r)  # one by one, so each removal is in the audit log
    session.flush()
    session.delete(b)
    session.flush()
    _reevaluate(session, platform)


def save_rule(session: Session, actor, *, baseline_id: int | None = None, rule_id: int | None = None, key: str | None = None, operator: str | None = None,
              expected=None, severity: str | None = None, controls: list[str] | None = None, enabled: bool | None = None) -> ConfigRule:
    authorize(session, actor, "integration.manage")
    if rule_id is not None:
        r = get_or_404(session, ConfigRule, rule_id)
        b = get_or_404(session, ConfigBaseline, r.baseline_id)
    else:
        if baseline_id is None:
            raise ValueError("Choose the baseline.")
        b = get_or_404(session, ConfigBaseline, baseline_id)
        if not key:
            raise ValueError("Choose the setting to check.")
        if session.scalar(select(ConfigRule.id).where(ConfigRule.baseline_id == b.id, ConfigRule.key == key)):
            raise ValueError("This baseline already has a rule for that setting.")
        if _count(session, select(func.count(ConfigRule.id)).where(ConfigRule.baseline_id == b.id)) >= MAX_RULES:
            raise ValueError(f"A baseline can have at most {MAX_RULES} rules.")
        r = ConfigRule(baseline_id=b.id, key=key, operator="", expected=None, severity="medium", controls=[], enabled=True)
    s = cat.setting(b.platform, r.key or key or "")
    op = operator if operator is not None else r.operator or (s.recommended[0] if s and s.recommended else "")
    exp = expected if (operator is not None or expected is not None) else r.expected
    op, exp, sev, ctl = validate_rule(b.platform, r.key or key or "", op, exp, severity or r.severity, controls if controls is not None else list(r.controls or []))
    r.operator, r.expected, r.severity, r.controls = op, exp, sev, _known_controls(session, ctl)
    if enabled is not None:
        r.enabled = enabled
    if r.id is None:
        session.add(r)
    session.flush()
    _reevaluate(session, b.platform)
    return r


def delete_rule(session: Session, actor, rule_id: int) -> None:
    authorize(session, actor, "integration.manage")
    r = get_or_404(session, ConfigRule, rule_id)
    b = get_or_404(session, ConfigBaseline, r.baseline_id)
    session.execute(delete(ConfigFinding).where(ConfigFinding.rule_id == r.id))
    session.delete(r)
    session.flush()
    _reevaluate(session, b.platform)


def baselines(session: Session) -> list[ConfigBaseline]:
    return list(session.scalars(select(ConfigBaseline).order_by(ConfigBaseline.platform, ConfigBaseline.name)))


def rules(session: Session, baseline_id: int) -> list[ConfigRule]:
    return list(session.scalars(select(ConfigRule).where(ConfigRule.baseline_id == baseline_id).order_by(ConfigRule.id)))


# ---- evaluation ----------------------------------------------------------------------------------------------------

def effective_baseline(session: Session, t: ConfigTarget) -> ConfigBaseline | None:
    if t.baseline_id:
        b = session.get(ConfigBaseline, t.baseline_id)
        return b if b is not None and b.enabled else None
    return session.scalar(select(ConfigBaseline).where(ConfigBaseline.platform == t.platform, ConfigBaseline.is_default.is_(True), ConfigBaseline.enabled.is_(True)))


def judge(platform: str, r: ConfigRule, facts: dict) -> tuple[str, object, str]:
    """(status, actual value, explanation) for one rule. A missing or unreadable value is unknown, never a pass."""
    s = cat.setting(platform, r.key)
    if s is None:
        return "unknown", None, "This setting doesn't exist for the platform."
    if s.requires:
        pre = facts.get(s.requires)
        if pre is False:
            req = cat.setting(platform, s.requires)
            return "na", None, f"Not applicable: {(req.title if req else s.requires).lower()} is off."
        if pre is None:
            return "unknown", None, "Not reported."
    v = cat.clean_value(s, facts.get(r.key))
    if v is None:
        return "unknown", None, "Not reported."
    op, exp = r.operator, r.expected
    ok: bool
    if op == "is_true":
        ok = v is True
    elif op == "is_false":
        ok = v is False
    elif op == "empty":
        ok = isinstance(v, list) and not v
    elif op in ("in", "not_in"):
        values = [str(x).lower() for x in exp] if isinstance(exp, list) else []
        ok = (str(v).lower() in values) == (op == "in")
    elif s.type == "int":
        if not isinstance(exp, int):
            return "unknown", v, "The rule has no number to compare with."
        ok = {"eq": v == exp, "ne": v != exp, "gte": v >= exp, "lte": v <= exp}[op]
    else:
        ok = {"eq": str(v).lower() == str(exp).lower(), "ne": str(v).lower() != str(exp).lower()}.get(op, False)
    if ok:
        return "pass", v, ""
    shown = "on" if v is True else "off" if v is False else ", ".join(v) if isinstance(v, list) else str(v)
    return "fail", v, f"Reported {shown}; required: {cat.describe_expected(op, exp)}."


def evaluate_target(session: Session, t: ConfigTarget, source: str = "evaluate") -> dict:
    """Compare the target's latest facts with its baseline. Updates findings, records a snapshot with what changed,
    and returns the counts. New critical and high failures alert the ISMS managers."""
    now, on = utcnow(), today()
    b = effective_baseline(session, t)
    current = {f.rule_id: f for f in session.scalars(select(ConfigFinding).where(ConfigFinding.target_id == t.id))}
    counts: Counter = Counter()
    changes, new_failures = [], []
    seen = set()
    if b is not None and t.facts_at is not None:
        for r in session.scalars(select(ConfigRule).where(ConfigRule.baseline_id == b.id, ConfigRule.enabled.is_(True))):
            status, actual, detail = judge(t.platform, r, t.facts or {})
            f = current.get(r.id)
            if status == "fail" and f is not None and f.status == "excepted" and f.exception_until and f.exception_until >= on:
                status = "excepted"
            if f is None:
                f = ConfigFinding(target_id=t.id, rule_id=r.id, status=status, since=now)
                session.add(f)
                if status == "fail":
                    new_failures.append((r, t))
            elif f.status != status:
                changes.append({"key": r.key, "from": f.status, "to": status, "value_from": f.actual, "value_to": actual})
                if status == "fail" and f.status != "excepted":
                    new_failures.append((r, t))
                f.status, f.since = status, now
                if status != "excepted":
                    f.exception_reason = f.exception_by_id = f.exception_until = None
            f.actual, f.detail, f.evaluated_at = actual, detail[:500], now
            counts[status] += 1
            seen.add(r.id)
    for rid, f in current.items():
        if rid not in seen:
            session.delete(f)  # the rule was removed, disabled, or the baseline changed
    if source != "evaluate" or changes:  # a re-check after a baseline edit is recorded only when results changed
        session.add(ConfigSnapshot(target_id=t.id, at=now, source=source, baseline_id=b.id if b else None, counts=dict(counts), changes=changes[:200]))
    session.flush()
    _alert(session, new_failures)
    return {"baseline_id": b.id if b else None, **{k: counts.get(k, 0) for k in ("pass", "fail", "unknown", "na", "excepted")}, "changes": len(changes)}


def _reevaluate(session: Session, platform: str) -> None:
    for t in session.scalars(select(ConfigTarget).where(ConfigTarget.platform == platform, ConfigTarget.revoked_at.is_(None))):
        if t.facts_at is not None:
            evaluate_target(session, t)


def _title(platform: str, key: str) -> str:
    st = cat.setting(platform, key)
    return st.title if st else key


def _alert(session: Session, failures: list[tuple[ConfigRule, ConfigTarget]]) -> None:
    from keystone.notifications.models import Notification
    from keystone.outbound.service import emit

    serious = [(r, t) for r, t in failures if r.severity in ("critical", "high")]
    if not serious:
        return
    users = [u for u in session.scalars(select(User).where(User.active.is_(True))) if not expired(u)]
    managers = [u.id for u in users if u.role == Role.ISMS_MANAGER.value] or [u.id for u in users if u.role == Role.ADMIN.value]
    stamp = datetime.now()
    by_target: dict[int, list[ConfigRule]] = {}
    for r, t in serious:
        by_target.setdefault(t.id, []).append(r)
    for tid, rs in by_target.items():
        t = get_or_404(session, ConfigTarget, tid)
        worst = "critical" if any(r.severity == "critical" for r in rs) else "high"
        names = ", ".join(_title(t.platform, r.key) for r in rs[:3])
        text = f"{t.name}: {len(rs)} {worst} configuration failure(s) ({names}{'…' if len(rs) > 3 else ''})"
        for m in managers:
            session.add(Notification(user_id=m, key=f"config:{tid}:{stamp:%Y%m%d%H%M%S%f}", kind="config", title=text[:500], page=f"/configuration?target={tid}", created_at=stamp))
        emit(session, "config.failed", title=text, severity=worst, page=f"/configuration?target={tid}")
    session.flush()


def file_evidence(session: Session) -> int:
    """Each enabled baseline whose targets (at least one, reported recently) all pass or have approved exceptions is
    evidence for its rules' controls. Refreshed by the daily job; lapses after three days without a refresh."""
    from keystone.controls.models import Evidence
    from keystone.frameworks.models import CommonControl

    filed = 0
    targets = [t for t in session.scalars(select(ConfigTarget).where(ConfigTarget.revoked_at.is_(None))) if t.facts_at and not is_stale(session, t)]
    for b in session.scalars(select(ConfigBaseline).where(ConfigBaseline.enabled.is_(True))):
        mine = [t for t in targets if getattr(effective_baseline(session, t), "id", None) == b.id]
        if not mine:
            continue
        statuses = Counter(f.status for f in session.scalars(select(ConfigFinding).where(ConfigFinding.target_id.in_([t.id for t in mine]))))
        if statuses.get("fail") or statuses.get("unknown") or not statuses.get("pass"):
            continue
        codes = sorted({c for r in rules(session, b.id) if r.enabled for c in (r.controls or [])})
        title = f"Configuration baseline met: {b.name}"
        desc = (f"{len(mine)} {cat.PLATFORM_LABEL[b.platform]} target(s) meet every rule of “{b.name}”"
                + (f" ({statuses['excepted']} result(s) under an approved exception)" if statuses.get("excepted") else "")
                + f". Checked {utcnow():%Y-%m-%d %H:%M} UTC from agent reports and uploaded configurations.")
        for code in codes:
            c = session.scalar(select(CommonControl).where(CommonControl.code == code))
            if c is None:
                continue
            ev = session.scalar(select(Evidence).where(Evidence.common_control_id == c.id, Evidence.title == title, Evidence.kind == "note"))
            if ev is None:
                session.add(Evidence(common_control_id=c.id, title=title, kind="note", description=desc, collected_on=today(), valid_until=today() + timedelta(days=3)))
            else:
                ev.description, ev.collected_on, ev.valid_until = desc, today(), today() + timedelta(days=3)
            filed += 1
    session.flush()
    return filed


def housekeeping(session: Session) -> dict:
    """The scheduled job: lapse expired exceptions (re-evaluating, so they show as failing), file evidence, trim history."""
    lapsed = expire_exceptions(session)
    if lapsed:
        for p in cat.PLATFORMS:
            _reevaluate(session, p)
    return {"lapsed": lapsed, "evidence": file_evidence(session), "pruned": prune_snapshots(session)}


def prune_snapshots(session: Session) -> int:
    removed = 0
    for tid in session.scalars(select(ConfigTarget.id)):
        cutoff = session.scalar(select(ConfigSnapshot.id).where(ConfigSnapshot.target_id == tid).order_by(ConfigSnapshot.id.desc()).offset(SNAPSHOTS_KEPT).limit(1))
        if cutoff is not None:
            gone = list(session.scalars(select(ConfigSnapshot.id).where(ConfigSnapshot.target_id == tid, ConfigSnapshot.id <= cutoff)))
            session.execute(delete(ConfigSnapshot).where(ConfigSnapshot.id.in_(gone)))
            removed += len(gone)
    return removed


# ---- targets (read / integration.manage) ---------------------------------------------------------------------------

def agent_settings(session: Session) -> ConfigAgentSettings:
    s = session.scalar(select(ConfigAgentSettings).limit(1))
    if s is None:
        s = ConfigAgentSettings(report_hours=4)
        session.add(s)
        session.flush()
    return s


def is_stale(session: Session, t: ConfigTarget, settings: ConfigAgentSettings | None = None) -> bool:
    if t.facts_at is None:
        return True
    if t.kind == "firewall":
        return t.facts_at < utcnow() - timedelta(days=FIREWALL_STALE_DAYS)
    hours = (settings or agent_settings(session)).report_hours
    return t.facts_at < utcnow() - timedelta(hours=hours * STALE_FACTOR)


def targets(session: Session) -> list[ConfigTarget]:
    return list(session.scalars(select(ConfigTarget).order_by(ConfigTarget.platform, ConfigTarget.name)))


def findings(session: Session, target_id: int) -> list[ConfigFinding]:
    return list(session.scalars(select(ConfigFinding).where(ConfigFinding.target_id == target_id)))


def history(session: Session, target_id: int, limit: int = 100) -> list[ConfigSnapshot]:
    return list(session.scalars(select(ConfigSnapshot).where(ConfigSnapshot.target_id == target_id).order_by(ConfigSnapshot.id.desc()).limit(limit)))


def update_target(session: Session, actor, target_id: int, *, name: str | None = None, baseline_id: int | None = None, clear_baseline: bool = False) -> ConfigTarget:
    authorize(session, actor, "integration.manage")
    t = get_or_404(session, ConfigTarget, target_id)
    changes = []
    if name is not None:
        t.name = require_text(name, "Name")[:200]
        changes.append("renamed")
    if clear_baseline:
        t.baseline_id = None
        changes.append("uses the platform default baseline")
    elif baseline_id is not None:
        b = get_or_404(session, ConfigBaseline, baseline_id)
        if b.platform != t.platform:
            raise ValueError("Choose a baseline for the same platform.")
        t.baseline_id = b.id
        changes.append(f"baseline {b.name}")
    session.flush()
    evaluate_target(session, t)
    log_event(session, actor, "update", "ConfigTarget", t.id, f"{t.name}: " + ", ".join(changes or ["re-evaluated"]))
    return t


def revoke_target(session: Session, actor, target_id: int) -> ConfigTarget:
    """Stops an agent's token working. Its results stay until the target is deleted."""
    authorize(session, actor, "integration.manage")
    t = get_or_404(session, ConfigTarget, target_id)
    if t.kind != "agent":
        raise ValueError("Only agents have a token to revoke.")
    t.revoked_at = t.revoked_at or utcnow()
    session.flush()
    log_event(session, actor, "revoke", "ConfigTarget", t.id, f"Agent token revoked for {t.name}")
    return t


def delete_target(session: Session, actor, target_id: int) -> None:
    authorize(session, actor, "integration.manage")
    t = get_or_404(session, ConfigTarget, target_id)
    name = t.name
    session.execute(delete(ConfigFinding).where(ConfigFinding.target_id == t.id))
    session.execute(delete(ConfigSnapshot).where(ConfigSnapshot.target_id == t.id))
    session.delete(t)
    session.flush()
    log_event(session, actor, "delete", "ConfigTarget", target_id, f"Removed {name} from configuration checks")


# ---- exceptions (risk.accept) ----------------------------------------------------------------------------------------

def grant_exception(session: Session, actor, finding_id: int, reason: str, until: date) -> ConfigFinding:
    authorize(session, actor, "risk.accept")
    f = get_or_404(session, ConfigFinding, finding_id)
    if f.status != "fail":
        raise ValueError("Only failing results can get an exception.")
    if until <= today() or until > today() + timedelta(days=MAX_EXCEPTION_DAYS):
        raise ValueError("The exception must end within a year.")
    f.status, f.since = "excepted", utcnow()
    f.exception_reason, f.exception_by_id, f.exception_until = require_text(reason, "Reason")[:2000], actor.id, until
    session.flush()
    r = session.get(ConfigRule, f.rule_id)
    t = session.get(ConfigTarget, f.target_id)
    log_event(session, actor, "exception", "ConfigFinding", f.id, f"Exception until {until.isoformat()} for {r.key if r else '?'} on {t.name if t else '?'}: {f.exception_reason[:200]}")
    return f


def revoke_exception(session: Session, actor, finding_id: int) -> ConfigFinding:
    authorize(session, actor, "risk.accept")
    f = get_or_404(session, ConfigFinding, finding_id)
    if f.status != "excepted":
        raise ValueError("This result has no exception.")
    f.status, f.since = "fail", utcnow()
    f.exception_reason = f.exception_by_id = f.exception_until = None
    session.flush()
    log_event(session, actor, "exception_revoked", "ConfigFinding", f.id, "Exception withdrawn")
    return f


def expire_exceptions(session: Session) -> int:
    n = 0
    for f in session.scalars(select(ConfigFinding).where(ConfigFinding.status == "excepted", ConfigFinding.exception_until < today())):
        f.status, f.since = "fail", utcnow()
        f.exception_reason = f.exception_by_id = f.exception_until = None
        n += 1
    session.flush()
    return n


# ---- firewall uploads (integration.manage) ---------------------------------------------------------------------------

def upload_firewall(session: Session, actor, *, platform: str, filename: str, data: bytes, target_id: int | None = None, name: str | None = None) -> tuple[ConfigTarget, dict, list[str]]:
    """Parse a configuration export, keep only the facts (never the file, which holds secrets), and evaluate."""
    from keystone.core.attachments import safe_filename

    authorize(session, actor, "integration.manage")
    if platform not in cat.FIREWALL_PLATFORMS:
        raise ValueError("Choose FortiGate, PAN-OS, Cisco or pfSense/OPNsense.")
    parsed = parsers.parse(platform, data)
    allowed = {s.key: s for s in cat.settings_for(platform)}
    facts = {k: cat.clean_value(allowed[k], v) for k, v in parsed.facts.items() if k in allowed}
    facts = {k: v for k, v in facts.items() if v is not None}
    if target_id is not None:
        t = get_or_404(session, ConfigTarget, target_id)
        if t.kind != "firewall" or t.platform != platform:
            raise ValueError("That target is not a firewall of this platform.")
    else:
        if _count(session, select(func.count(ConfigTarget.id))) >= MAX_TARGETS:
            raise ValueError(f"At most {MAX_TARGETS} targets.")
        label = (name or "").strip() or parsed.hostname or safe_filename(filename)
        t = ConfigTarget(kind="firewall", platform=platform, name=label[:200], facts={}, created_at=utcnow())
        session.add(t)
    t.hostname = (parsed.hostname or t.hostname or "")[:253] or None
    t.os_name, t.os_version = cat.PLATFORM_LABEL[platform], (parsed.version or "")[:100] or None
    t.source_filename, t.source_sha256 = safe_filename(filename), hashlib.sha256(data).hexdigest()
    t.facts, t.facts_at = facts, utcnow()
    session.flush()
    result = evaluate_target(session, t, source="upload")
    log_event(session, actor, "upload", "ConfigTarget", t.id, f"Configuration of {t.name} ({cat.PLATFORM_LABEL[platform]}) checked: {result['fail']} failing, {result['unknown']} unknown; file SHA-256 {t.source_sha256[:16]}…")
    return t, result, parsed.notes


# ---- agents: enrolment key (integration.manage), enrolment and reports (device credentials) ---------------------------

def enrolment_key(session: Session, actor) -> str:
    """The current enrolment key, created on first use. Shown to administrators for the install command."""
    authorize(session, actor, "integration.manage")
    s = agent_settings(session)
    if not s.enrollment_key_enc:
        s.enrollment_key_enc, s.rotated_at = crypto.encrypt(ENROLMENT_PREFIX + pysecrets.token_urlsafe(24)), utcnow()
        session.flush()
    return crypto.decrypt(s.enrollment_key_enc)


def rotate_enrolment_key(session: Session, actor) -> str:
    """A new key for new installs. Agents already enrolled keep working: they use their own device tokens."""
    authorize(session, actor, "integration.manage")
    s = agent_settings(session)
    s.enrollment_key_enc, s.rotated_at = crypto.encrypt(ENROLMENT_PREFIX + pysecrets.token_urlsafe(24)), utcnow()
    session.flush()
    log_event(session, actor, "rotate", "ConfigAgentSettings", s.id, "Agent enrolment key rotated")
    return crypto.decrypt(s.enrollment_key_enc)


def set_report_hours(session: Session, actor, hours: int) -> ConfigAgentSettings:
    authorize(session, actor, "integration.manage")
    if hours not in (1, 2, 4, 8, 12, 24):
        raise ValueError("Choose 1, 2, 4, 8, 12 or 24 hours.")
    s = agent_settings(session)
    s.report_hours = hours
    session.flush()
    return s


class AgentRejected(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def enrol(session: Session, *, key: str, hostname: str, platform: str, os_name: str | None, os_version: str | None, agent_version: str | None, ip: str | None) -> tuple[ConfigTarget, str]:
    """Exchange the enrolment key for a device token. Every enrolment creates a new target; an administrator removes
    the old one after a reinstall. The token is returned once and stored only as a hash."""
    s = session.scalar(select(ConfigAgentSettings).limit(1))
    current = crypto.decrypt(s.enrollment_key_enc) if s is not None and s.enrollment_key_enc else None
    if current is None or not hmac.compare_digest(current.encode(), (key or "").encode()):
        raise AgentRejected(401, "Invalid enrolment key.")
    if platform not in cat.AGENT_PLATFORMS:
        raise AgentRejected(400, "Unsupported platform.")
    if _count(session, select(func.count(ConfigTarget.id))) >= MAX_TARGETS:
        raise AgentRejected(409, "Too many targets.")
    raw = DEVICE_PREFIX + pysecrets.token_urlsafe(32)
    now = utcnow()
    t = ConfigTarget(kind="agent", platform=platform, name=hostname, hostname=hostname, os_name=(os_name or "")[:200] or None, os_version=(os_version or "")[:100] or None,
                     agent_version=(agent_version or "")[:20] or None, token_hash=_hash(raw), enrolled_at=now, last_ip=(ip or "")[:64] or None, facts={}, created_at=now)
    session.add(t)
    session.flush()
    log_event(session, None, "enrol", "ConfigTarget", t.id, f"Agent enrolled: {hostname} ({cat.PLATFORM_LABEL[platform]}) from {ip or 'unknown address'}")
    return t, raw


def resolve_device(session: Session, header: str | None) -> ConfigTarget:
    if not header or not header.startswith("Bearer ") or len(header) > 300:
        raise AgentRejected(401, "Device token required.")
    raw = header[7:].strip()
    if not raw.startswith(DEVICE_PREFIX):
        raise AgentRejected(401, "Invalid device token.")
    digest = _hash(raw)
    t = session.scalar(select(ConfigTarget).where(ConfigTarget.token_hash == digest))
    if t is None or not hmac.compare_digest(t.token_hash or "", digest) or t.revoked_at is not None:
        raise AgentRejected(401, "Invalid or revoked device token.")
    return t


def report(session: Session, t: ConfigTarget, *, facts: dict, hostname: str | None, os_name: str | None, os_version: str | None, agent_version: str | None, ip: str | None) -> dict:
    """Store an agent's report and evaluate it. Unknown keys and values of the wrong type are dropped, not stored."""
    allowed = {s.key: s for s in cat.settings_for(t.platform)}
    clean, ignored = {}, []
    for k, v in (facts or {}).items():
        s = allowed.get(k)
        value = cat.clean_value(s, v) if s else None
        if value is None:
            ignored.append(str(k)[:60])
        else:
            clean[k] = value
    t.facts, t.facts_at = clean, utcnow()
    if hostname:
        t.hostname = hostname[:253]
    t.os_name = (os_name or t.os_name or "")[:200] or None
    t.os_version = (os_version or t.os_version or "")[:100] or None
    t.agent_version = (agent_version or t.agent_version or "")[:20] or None
    t.last_ip = (ip or "")[:64] or None
    session.flush()
    session.info["actor"] = None
    evaluate_target(session, t, source="agent")
    return {"accepted": len(clean), "ignored": ignored[:50], "report_hours": agent_settings(session).report_hours}


# ---- overview ---------------------------------------------------------------------------------------------------------

def summary(session: Session, t: ConfigTarget, settings: ConfigAgentSettings | None = None) -> dict:
    c = Counter(f.status for f in findings(session, t.id))
    b = effective_baseline(session, t)
    stale = is_stale(session, t, settings)
    total = c["pass"] + c["fail"] + c["unknown"]
    state = ("revoked" if t.revoked_at else "waiting" if t.facts_at is None else "no_baseline" if b is None else
             "failing" if c["fail"] else "unknown" if c["unknown"] else "compliant")
    return {"baseline_id": b.id if b else None, "baseline": b.name if b else None, "stale": stale, "state": state,
            "counts": {k: c.get(k, 0) for k in ("pass", "fail", "unknown", "na", "excepted")},
            "score": round(100 * (c["pass"] + c["excepted"]) / (total + c["excepted"])) if (total + c["excepted"]) else None}


def overview(session: Session) -> dict:
    s = agent_settings(session)
    rows = [(t, summary(session, t, s)) for t in targets(session)]
    per = {}
    for p in cat.PLATFORMS:
        mine = [x for t, x in rows if t.platform == p and t.revoked_at is None]
        per[p] = {"targets": len(mine), "compliant": sum(1 for x in mine if x["state"] == "compliant"), "failing": sum(1 for x in mine if x["state"] == "failing"),
                  "stale": sum(1 for x in mine if x["stale"]), "fail_results": sum(x["counts"]["fail"] for x in mine)}
    worst: Counter[tuple[str, str, str]] = Counter()
    for f in session.scalars(select(ConfigFinding).where(ConfigFinding.status == "fail")):
        r = session.get(ConfigRule, f.rule_id)
        t = session.get(ConfigTarget, f.target_id)
        if r is not None and t is not None and t.revoked_at is None:
            worst[(t.platform, r.key, r.severity)] += 1
    order = {s: i for i, s in enumerate(reversed(cat.SEVERITIES))}
    top = sorted(worst.items(), key=lambda kv: (order[kv[0][2]], -kv[1]))[:10]
    return {"platforms": per, "report_hours": s.report_hours,
            "top_failures": [{"platform": p, "key": k, "title": _title(p, k), "severity": sev, "targets": n} for (p, k, sev), n in top]}
