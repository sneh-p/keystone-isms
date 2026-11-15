"""Management review (ISO 27001 9.3): inputs compiled from live data, frozen when finalised."""

from __future__ import annotations

from datetime import date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.controls import service as controls
from keystone.core.db import utcnow
from keystone.core.services import apply_fields, authorize, get_or_404, require_text
from keystone.frameworks import service as fw
from keystone.improvement import service as imp
from keystone.incidents import service as inc
from keystone.org import service as org
from keystone.org.models import InterestedParty, SecurityObjective
from keystone.policies import service as pol
from keystone.risk import service as risk
from keystone.tprm import service as tprm

from .models import ManagementReview
from .service import control_coverage, list_audits


def _in_period(d: datetime | date | None, start: date) -> bool:
    if d is None:
        return False
    return (d.date() if isinstance(d, datetime) else d) >= start


def previous_final(session: Session, before: date | None = None) -> ManagementReview | None:
    q = select(ManagementReview).where(ManagementReview.status == "final").order_by(ManagementReview.held_on.desc())
    if before:
        q = q.where(ManagementReview.held_on < before)
    return session.scalar(q.limit(1))


def compile_inputs(session: Session, period_start: date, on: date | None = None) -> dict:
    """Everything clause 9.3.2 asks a management review to consider, from current records."""
    on = on or date.today()
    prev = previous_final(session, on + timedelta(days=1))
    o = org.get_org(session)
    risks = risk.list_risks(session)
    attention = risk.needs_attention(risks, on)
    levels: dict[str, int] = {}
    for r in risks:
        lv = risk.current_level(r) or "Not assessed"
        levels[lv] = levels.get(lv, 0) + 1
    ncs_all = imp.list_ncs(session)
    audits = [a for a in list_audits(session) if a.status == "closed" and _in_period(a.closed_at, period_start)]
    findings: dict[str, int] = {}
    for a in audits:
        for f in a.findings:
            findings[f.finding_type] = findings.get(f.finding_type, 0) + 1
    incidents = [i for i in inc.list_incidents(session) if _in_period(i.detected_at, period_start)]
    by_sev: dict[str, int] = {}
    for i in incidents:
        by_sev[i.severity] = by_sev.get(i.severity, 0) + 1
    coverage = {f.code: fw.coverage_summary(fw.coverage(session, f.id)) for f in fw.frameworks(session)}
    ctl_att = controls.control_attention(session, on)
    vatt = tprm.vendor_attention(session, on)
    patt = pol.policy_attention(session, on)
    objectives = list(session.scalars(select(SecurityObjective)))
    parties = list(session.scalars(select(InterestedParty)))
    return {
        "generated_at": utcnow().isoformat(timespec="seconds"),
        "period_start": period_start.isoformat(),
        "period_end": on.isoformat(),
        "a_previous_actions": {
            "previous_review": prev.title if prev else None,
            "previous_held_on": prev.held_on.isoformat() if prev else None,
            "previous_actions": prev.actions if prev else None,
            "open_items_from_reviews": [f"{n.ref} {n.title} ({n.status})" for n in ncs_all if n.source == "management_review" and n.status != "closed"],
        },
        "b_issues": {"internal": o.internal_issues if o else None, "external": o.external_issues if o else None, "scope_approved": bool(o and o.scope_approved_at)},
        "c_interested_parties": [{"name": p.name, "type": p.party_type, "needs": p.needs} for p in parties],
        "d1_nonconformities": {
            "raised_in_period": sum(1 for n in ncs_all if _in_period(n.created_at, period_start)),
            "closed_in_period": sum(1 for n in ncs_all if _in_period(n.closed_at, period_start)),
            "open": sum(1 for n in ncs_all if n.status != "closed"),
            "open_major": sum(1 for n in ncs_all if n.status != "closed" and n.severity == "major"),
            "actions_overdue": len(imp.nc_attention(session, on)["actions_overdue"]),
        },
        "d2_monitoring": {
            "control_status": controls.status_counts(session),
            "framework_implemented_pct": {k: v["implemented_pct"] for k, v in coverage.items()},
            "controls_without_evidence": len(ctl_att["implemented_without_evidence"]),
            "control_reviews_overdue": len(ctl_att["review_overdue"]),
            "evidence_expired": len(ctl_att["evidence_expired"]),
            "policies_review_overdue": len(patt["review_overdue"]),
            "policies_acknowledgement_incomplete": len(patt["acknowledgement_incomplete"]),
        },
        "d3_audits": {
            "closed_in_period": [f"{a.ref} {a.title}" for a in audits],
            "findings": findings,
            "control_audit_coverage_pct": control_coverage(session, on)["pct"],
        },
        "d4_objectives": [{"objective": x.title, "target": x.target, "current": x.current_value, "status": x.status} for x in objectives],
        "f_risk": {
            "open_risks": len([r for r in risks if r.status != "closed"]),
            "by_level": levels,
            "above_appetite_untreated": [f"{r.ref} {r.title}" for r in attention["above_appetite_untreated"]],
            "acceptances_expired": [f"{r.ref} {r.title}" for r in attention["acceptance_expired"]],
            "treatment_actions_overdue": len(attention["actions_overdue"]),
            "reviews_overdue": len(attention["review_overdue"]),
        },
        "incidents": {"in_period": len(incidents), "by_severity": by_sev, "open": len([i for i in incidents if i.status != "closed"])},
        "third_parties": {k: len(v) for k, v in vatt.items()},
    }


REVIEW_FIELDS = {"title", "held_on", "period_start", "attendees", "interested_party_feedback", "improvement_opportunities", "discussion", "decisions", "actions"}


def create_review(session: Session, actor, *, title: str, held_on: date, attendees: str | None = None, period_start: date | None = None) -> ManagementReview:
    authorize(session, actor, "review.write")
    prev = previous_final(session, held_on)
    start = period_start or (prev.held_on if prev else held_on - timedelta(days=365))
    mr = ManagementReview(title=require_text(title, "Title"), held_on=held_on, period_start=start, attendees=attendees, status="draft", inputs=compile_inputs(session, start, held_on))
    session.add(mr)
    session.flush()
    return mr


def update_review(session: Session, actor, review_id: int, **fields) -> ManagementReview:
    authorize(session, actor, "review.write")
    mr = get_or_404(session, ManagementReview, review_id)
    if mr.status == "final":
        raise ValueError("Finalised reviews are records and cannot be changed.")
    apply_fields(mr, fields, REVIEW_FIELDS)
    session.flush()
    return mr


def refresh_inputs(session: Session, actor, review_id: int) -> ManagementReview:
    authorize(session, actor, "review.write")
    mr = get_or_404(session, ManagementReview, review_id)
    if mr.status == "final":
        raise ValueError("Finalised reviews keep the inputs they were held with.")
    mr.inputs = compile_inputs(session, mr.period_start, mr.held_on)
    session.flush()
    return mr


def raise_improvement(session: Session, actor, review_id: int, title: str, owner_id: int | None = None, due_date: date | None = None):
    """Record a decision as a tracked improvement item (a nonconformity with source management_review)."""
    authorize(session, actor, "review.write")
    mr = get_or_404(session, ManagementReview, review_id)
    return imp.raise_nc(session, actor, title=title, description=f"Decided at {mr.title} ({mr.held_on.isoformat()}).", source="management_review", severity="observation", owner_id=owner_id, due_date=due_date)


def finalize(session: Session, actor, review_id: int) -> ManagementReview:
    authorize(session, actor, "review.write")
    mr = get_or_404(session, ManagementReview, review_id)
    if mr.status == "final":
        raise ValueError("Already finalised.")
    require_text(mr.attendees, "Attendees")
    require_text(mr.decisions, "Decisions (ISO 27001 9.3.3)")
    mr.status, mr.finalized_by_id, mr.finalized_at = "final", actor.id, utcnow()
    session.flush()
    return mr


def list_reviews(session: Session) -> list[ManagementReview]:
    return list(session.scalars(select(ManagementReview).order_by(ManagementReview.held_on.desc())))
