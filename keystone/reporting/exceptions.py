"""One register of every exception in force: risk acceptances, attack surface and configuration exceptions, and policy
exceptions, with who approved them and when they end (ISO 27001 A.5.36, 6.1.3)."""

from __future__ import annotations

from datetime import date, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.auth import User
from keystone.core.services import authorize, today

SOON = 30


def _state(until: date | None, on: date) -> str:
    if until is None:
        return "no_end"
    if until < on:
        return "expired"
    return "ending" if until <= on + timedelta(days=SOON) else "active"


def all_exceptions(session: Session, actor, on: date | None = None) -> list[dict]:
    from keystone.asm.models import AsmFinding, Baseline
    from keystone.configcheck.models import ConfigFinding, ConfigRule, ConfigTarget
    from keystone.configcheck.catalogue import setting
    from keystone.registers.models import RegisterEntry
    from keystone.risk.models import Risk, RiskAcceptance

    authorize(session, actor, "read")
    on = on or today()
    users = {u.id: u.display_name for u in session.scalars(select(User))}

    def names(uid: int | None) -> str | None:
        return users.get(uid) if uid is not None else None
    out: list[dict] = []
    for a in session.scalars(select(RiskAcceptance).where(RiskAcceptance.revoked_at.is_(None))):
        r = session.get(Risk, a.risk_id)
        out.append({"type": "risk_acceptance", "type_label": "Risk acceptance", "ref": r.ref if r else "", "title": r.title if r else "",
                    "reason": a.justification, "approved_by": names(a.accepted_by_id), "until": a.expires_on, "state": _state(a.expires_on, on),
                    "page": f"/risks?open={a.risk_id}"})
    baselines = {b.id: b.name for b in session.scalars(select(Baseline))}
    for f in session.scalars(select(AsmFinding).where(AsmFinding.status == "excepted")):
        out.append({"type": "attack_surface", "type_label": "Attack surface exception", "ref": f.ref, "title": f"{baselines.get(f.baseline_id, 'Baseline')}: {f.detail}"[:300],
                    "reason": f.exception_reason, "approved_by": names(f.exception_by_id), "until": f.exception_until, "state": _state(f.exception_until, on),
                    "page": "/attack-surface?tab=findings"})
    for cf in session.scalars(select(ConfigFinding).where(ConfigFinding.status == "excepted")):
        rule, target = session.get(ConfigRule, cf.rule_id), session.get(ConfigTarget, cf.target_id)
        s = setting(target.platform, rule.key) if rule and target else None
        out.append({"type": "configuration", "type_label": "Configuration exception", "ref": "",
                    "title": f"{target.name if target else 'Target'}: {s.title if s else (rule.key if rule else 'rule')}", "reason": cf.exception_reason,
                    "approved_by": names(cf.exception_by_id), "until": cf.exception_until, "state": _state(cf.exception_until, on),
                    "page": f"/configuration?target={cf.target_id}"})
    for e in session.scalars(select(RegisterEntry).where(RegisterEntry.register == "policy-exceptions", RegisterEntry.status.in_(("requested", "approved")))):
        approver = next((d["by"] for d in reversed(e.decisions or []) if d.get("to") == "approved"), None)
        out.append({"type": "policy", "type_label": "Policy exception" + (" (requested)" if e.status == "requested" else ""), "ref": e.ref,
                    "title": f"{(e.data or {}).get('policy', '')}: {e.title}", "reason": (e.data or {}).get("justification"), "approved_by": approver,
                    "until": e.due_on, "state": "requested" if e.status == "requested" else _state(e.due_on, on), "page": f"/registers/policy-exceptions?open={e.id}"})
    order = {"expired": 0, "ending": 1, "requested": 2, "active": 3, "no_end": 4}
    out.sort(key=lambda x: (order[x["state"]], x["until"] or date.max))
    return out
