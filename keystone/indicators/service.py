"""Security indicators: thresholds on figures Keystone measures every day (or that people enter), with a
notification to the owner when one turns red."""

from __future__ import annotations

from datetime import date, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from keystone.core.auth import User
from keystone.core.rbac import has_permission
from keystone.core.services import authorize, get_or_404, require_text, today

from .models import Indicator, IndicatorValue

# Figures measured every day, with their unit and which way is good. The dashboard's figures are included.
METRICS: dict[str, tuple[str, str, bool]] = {
    "mfa_coverage_pct": ("MFA coverage of enabled accounts", "%", True),
    "vulns_past_fix_by": ("Vulnerabilities past their fix-by date", "", False),
    "known_exploited_open": ("Known-exploited vulnerabilities open", "", False),
    "asm_findings_open": ("Open attack surface findings", "", False),
    "config_failing": ("Hosts and firewalls failing their baseline", "", False),
    "alerts_open": ("Open alerts in the security alert inbox", "", False),
    "security_reports_30d": ("Reports of suspicious activity in the last 30 days", "", True),
    "leavers_with_access": ("Leavers who still have access", "", False),
    "exceptions_expired": ("Exceptions past their end date", "", False),
    "training_overdue": ("People overdue on security training", "", False),
    "findings_past_fix_by": ("Test findings past their fix-by date", "", False),
    "backups_failing": ("Backup jobs failing", "", False),
    "certs_expiring_30d": ("Certificates and keys due within 30 days", "", False),
    "open_incidents": ("Open incidents", "", False),
    "tasks_overdue": ("Overdue tasks", "", False),
    "high_risks": ("High and critical risks", "", False),
    "readiness_pct": ("Framework readiness", "%", True),
}

RECOMMENDED = (  # (metric, amber, red)
    ("mfa_coverage_pct", 98, 90), ("vulns_past_fix_by", 1, 5), ("known_exploited_open", 1, 1), ("leavers_with_access", 1, 1),
    ("exceptions_expired", 1, 3), ("training_overdue", 1, 5), ("backups_failing", 1, 1), ("certs_expiring_30d", 1, 3),
    ("alerts_open", 10, 25), ("findings_past_fix_by", 1, 3),
)


def measure(session: Session, on: date | None = None) -> dict[str, float]:
    """Today's value of every figure in METRICS."""
    from keystone.access_reviews.reconcile import compute as access_check
    from keystone.alerts.models import Alert
    from keystone.asm.models import AsmFinding, AsmIdentity, AsmVulnerability
    from keystone.configcheck.models import ConfigFinding
    from keystone.incidents.models import SecurityReport
    from keystone.people.service import training_overdue
    from keystone.registers.models import RegisterEntry
    from keystone.reporting import dashboard
    from keystone.reporting.exceptions import compute as exceptions

    on = on or today()
    out: dict[str, float] = {}
    ids = [i for i in session.scalars(select(AsmIdentity)) if (i.properties or {}).get("account_enabled") is not False and not (i.properties or {}).get("is_guest")]
    out["mfa_coverage_pct"] = round(100 * sum(1 for i in ids if (i.properties or {}).get("mfa_registered")) / len(ids), 1) if ids else 100.0
    out["vulns_past_fix_by"] = session.scalar(select(func.count(AsmVulnerability.id)).where(AsmVulnerability.state == "open", AsmVulnerability.fix_by < on)) or 0
    out["known_exploited_open"] = session.scalar(select(func.count(AsmVulnerability.id)).where(AsmVulnerability.state == "open", AsmVulnerability.kev.is_(True))) or 0
    out["asm_findings_open"] = session.scalar(select(func.count(AsmFinding.id)).where(AsmFinding.status == "open")) or 0
    out["config_failing"] = session.scalar(select(func.count(func.distinct(ConfigFinding.target_id))).where(ConfigFinding.status == "fail")) or 0
    out["alerts_open"] = session.scalar(select(func.count(Alert.id)).where(Alert.status.in_(("new", "acknowledged")))) or 0
    out["security_reports_30d"] = session.scalar(select(func.count(SecurityReport.id)).where(SecurityReport.created_at >= datetime.combine(on - timedelta(days=30), datetime.min.time()))) or 0
    out["leavers_with_access"] = sum(1 for f in access_check(session, on)["findings"] if f["kind"] == "leaver")
    out["exceptions_expired"] = sum(1 for x in exceptions(session, on) if x["state"] == "expired")
    out["training_overdue"] = sum(training_overdue(session, on).values())
    entries = list(session.scalars(select(RegisterEntry).where(RegisterEntry.register.in_(("findings", "backups", "crypto")))))
    out["findings_past_fix_by"] = sum(1 for e in entries if e.register == "findings" and e.status in ("open", "fixed") and e.due_on and e.due_on < on)
    out["backups_failing"] = sum(1 for e in entries if e.register == "backups" and e.status == "failing")
    out["certs_expiring_30d"] = sum(1 for e in entries if e.register == "crypto" and e.status == "active" and e.due_on and e.due_on <= on + timedelta(days=30))
    dash = dashboard.metrics(session, on)
    for k in ("open_incidents", "tasks_overdue", "high_risks", "readiness_pct"):
        out[k] = float(dash[k])
    return {k: float(v) for k, v in out.items()}


def state(i: Indicator, value: float | None) -> str | None:
    if value is None:
        return None
    if i.higher_is_better:
        return "red" if value <= i.red else "amber" if value <= i.amber else "green"
    return "red" if value >= i.red else "amber" if value >= i.amber else "green"


def _record(session: Session, i: Indicator, on: date, value: float, source: str, note: str | None = None) -> None:
    v = session.scalar(select(IndicatorValue).where(IndicatorValue.indicator_id == i.id, IndicatorValue.measured_on == on))
    if v is None:
        v = IndicatorValue(indicator_id=i.id, measured_on=on, value=value, source=source)
        session.add(v)
    v.value, v.source, v.note = value, source, (note or "").strip()[:500] or None
    before = i.last_state
    if i.last_measured_on is None or on >= i.last_measured_on:
        i.last_value, i.last_measured_on, i.last_state = value, on, state(i, value)
    if i.last_state == "red" and before != "red":
        _notify_red(session, i)


def _notify_red(session: Session, i: Indicator) -> None:
    from keystone.notifications.models import Notification

    owner = session.get(User, i.owner_id) if i.owner_id else None
    users = [owner] if owner is not None and owner.active else [u for u in session.scalars(select(User).where(User.active.is_(True))) if has_permission(u, "org.write")]
    for u in users:
        session.add(Notification(user_id=u.id, key=f"kri-red:{i.id}:{i.last_measured_on}", kind="system", title=f"Indicator red: {i.name} is {i.last_value:g}{i.unit or ''}"[:500],
                                 page="/indicators", created_at=datetime.now()))


def measure_all(session: Session, on: date | None = None) -> int:
    """Record today's value of every active indicator linked to a figure (idempotent per day). Run with the daily snapshot."""
    on = on or today()
    linked = [i for i in session.scalars(select(Indicator).where(Indicator.active.is_(True), Indicator.metric_key.is_not(None)))]
    if not linked:
        return 0
    values = measure(session, on)
    for i in linked:
        if i.metric_key in values:
            _record(session, i, on, values[i.metric_key], "metric")
    session.flush()
    return len(linked)


# ---- managing indicators (org.write) -------------------------------------------------------------------------------

def indicators(session: Session, actor) -> list[Indicator]:
    authorize(session, actor, "read")
    return list(session.scalars(select(Indicator).order_by(Indicator.active.desc(), Indicator.name)))


def history(session: Session, actor, indicator_id: int, days: int = 180) -> list[IndicatorValue]:
    authorize(session, actor, "read")
    get_or_404(session, Indicator, indicator_id)
    return list(session.scalars(select(IndicatorValue).where(IndicatorValue.indicator_id == indicator_id, IndicatorValue.measured_on >= today() - timedelta(days=days))
                                .order_by(IndicatorValue.measured_on)))


def save(session: Session, actor, indicator_id: int | None = None, *, name: str, description: str | None, metric_key: str | None, unit: str | None,
         higher_is_better: bool, amber: float, red: float, owner_id: int | None, active: bool = True) -> Indicator:
    authorize(session, actor, "org.write")
    if metric_key is not None and metric_key not in METRICS:
        raise ValueError("Choose a figure Keystone measures, or none to enter values by hand.")
    if (higher_is_better and red > amber) or (not higher_is_better and red < amber):
        raise ValueError("Red can't be better than amber: no higher when higher is better, no lower when lower is better.")
    if owner_id is not None:
        u = session.get(User, owner_id)
        if u is None or not u.active:
            raise ValueError("Choose an active owner.")
    i = get_or_404(session, Indicator, indicator_id) if indicator_id else Indicator()
    i.name, i.description = require_text(name, "Name")[:200], (description or "").strip()[:2000] or None
    i.metric_key, i.unit, i.higher_is_better = metric_key, (unit or "").strip()[:20] or None, bool(higher_is_better)
    i.amber, i.red, i.owner_id, i.active = float(amber), float(red), owner_id, bool(active)
    i.last_state = state(i, i.last_value)
    session.add(i)
    session.flush()
    return i


def add_recommended(session: Session, actor) -> list[Indicator]:
    authorize(session, actor, "org.write")
    have = set(session.scalars(select(Indicator.metric_key)))
    out = []
    for key, amber, red in RECOMMENDED:
        if key in have:
            continue
        label, unit, up = METRICS[key]
        out.append(save(session, actor, name=label, description=None, metric_key=key, unit=unit or None, higher_is_better=up, amber=amber, red=red, owner_id=None))
    measure_all(session)
    return out


def record(session: Session, actor, indicator_id: int, *, value: float, measured_on: date | None = None, note: str | None = None) -> Indicator:
    """A value entered by hand (for indicators Keystone doesn't measure)."""
    authorize(session, actor, "org.write")
    i = get_or_404(session, Indicator, indicator_id)
    if i.metric_key:
        raise ValueError("Keystone measures this indicator every day.")
    on = measured_on or today()
    if on > today():
        raise ValueError("The date can't be in the future.")
    _record(session, i, on, float(value), "manual", note)
    session.flush()
    return i
