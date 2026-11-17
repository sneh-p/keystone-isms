"""Compliance calendar: who tests, reviews or renews what, and when.

Events come from the records' own dates: task due dates; control, policy, risk, vendor, processing-activity, DPIA and
business-process review dates; contract ends; evidence expiry; planned audits; data subject request deadlines;
continuity tests and plan exercises; access reviews; nonconformity and corrective-action due dates; objective target
dates; and when an uploaded firewall configuration goes out of date. Nothing is stored here; editing the record moves
the event.
"""

from __future__ import annotations

from datetime import date, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.services import authorize, today

MAX_DAYS = 100


def events(session: Session, actor, start: date, end: date) -> list[dict]:
    from keystone.audits.models import Audit
    from keystone.controls.models import Evidence
    from keystone.frameworks.models import CommonControl
    from keystone.policies.models import PolicyDocument
    from keystone.risk.models import Risk
    from keystone.tasks.models import Task
    from keystone.tprm.models import Vendor

    authorize(session, actor, "read")
    if end < start:
        raise ValueError("The end is before the start.")
    if (end - start).days > MAX_DAYS:
        raise ValueError(f"Show at most {MAX_DAYS} days at a time.")
    on = today()
    out: list[dict] = []

    def add(d: date | None, kind: str, title: str, page: str, owner_id: int | None, done: bool = False) -> None:
        if d and start <= d <= end:
            out.append({"date": d.isoformat(), "kind": kind, "title": title, "page": page, "owner_id": owner_id, "overdue": d < on and not done, "done": done})

    for t in session.scalars(select(Task).where(Task.due_date.between(start, end), Task.status != "not_relevant")):
        codes = ", ".join(c.code for c in t.controls[:3])
        add(t.due_date, "task", f"{t.title}{f' ({codes})' if codes else ''}", f"/tasks?open={t.id}", t.assignee_id, t.status == "done")
    for c in session.scalars(select(CommonControl).where(CommonControl.next_review_date.between(start, end), CommonControl.status != "not_applicable")):
        add(c.next_review_date, "control_review", f"Review control {c.code} {c.title}", f"/controls?open={c.id}", c.owner_id)
    for d in session.scalars(select(PolicyDocument).where(PolicyDocument.next_review_date.between(start, end), PolicyDocument.status == "approved")):
        add(d.next_review_date, "policy_review", f"Review policy {d.code} {d.title}", f"/policies?open={d.id}", d.owner_id)
    for r in session.scalars(select(Risk).where(Risk.review_date.between(start, end), Risk.status != "closed")):
        add(r.review_date, "risk_review", f"Review risk {r.ref} {r.title}", f"/risks?open={r.id}", r.owner_id)
    for v in session.scalars(select(Vendor).where(Vendor.status == "active")):
        add(v.next_review_date, "vendor_review", f"Review vendor {v.name}", f"/vendors?open={v.id}", v.owner_id)
        add(v.contract_end, "contract_end", f"Contract with {v.name} ends", f"/vendors?open={v.id}", v.owner_id)
    owners = {c.id: c.owner_id for c in session.scalars(select(CommonControl))}
    for e in session.scalars(select(Evidence).where(Evidence.valid_until.between(start, end), Evidence.superseded.is_(False))):
        add(e.valid_until, "evidence_expiry", f"Evidence expires: {e.title}", f"/controls?open={e.common_control_id}", owners.get(e.common_control_id))
    for a in session.scalars(select(Audit).where(Audit.status != "closed")):
        add(a.planned_start, "audit", f"Audit starts: {a.title}", f"/audits?open={a.id}", a.lead_auditor_id)
        if a.planned_end and a.planned_end != a.planned_start:
            add(a.planned_end, "audit", f"Audit ends: {a.title}", f"/audits?open={a.id}", a.lead_auditor_id)
    _more(session, add)
    out.sort(key=lambda e: (e["date"], e["kind"], e["title"]))
    return out


def _more(session: Session, add) -> None:
    """Privacy, continuity, access reviews, improvement, objectives and configuration."""
    from keystone.access_reviews.models import AccessReview
    from keystone.configcheck.models import ConfigTarget
    from keystone.configcheck.service import FIREWALL_STALE_DAYS
    from keystone.continuity import service as continuity
    from keystone.continuity.models import BusinessProcess, ContinuityPlan, ContinuityTest
    from keystone.improvement.models import CorrectiveAction, Nonconformity
    from keystone.org.models import SecurityObjective
    from keystone.privacy.models import DataSubjectRequest, Dpia, ProcessingActivity

    for r in session.scalars(select(DataSubjectRequest).where(DataSubjectRequest.status.notin_(("completed", "refused")))):
        add(r.due_date, "dsr_due", f"Data subject request due: {r.ref}", "/privacy?tab=requests", r.assignee_id)
    for a in session.scalars(select(ProcessingActivity).where(ProcessingActivity.status == "active")):
        add(a.next_review_date, "privacy_review", f"Review processing activity {a.name}", "/privacy", a.owner_id)
    for d in session.scalars(select(Dpia).where(Dpia.status == "approved")):
        add(d.next_review_date, "dpia_review", f"Review DPIA {d.title}", "/privacy?tab=dpias", getattr(d, "owner_id", None) or d.created_by_id)
    for p in session.scalars(select(BusinessProcess).where(BusinessProcess.status == "active")):
        add(p.next_review_date, "bia_review", f"Review business impact: {p.name}", "/continuity", p.owner_id)
    for t in session.scalars(select(ContinuityTest).where(ContinuityTest.status == "planned")):
        plan = session.get(ContinuityPlan, t.plan_id)
        add(t.planned_on, "continuity_test", f"Continuity test: {plan.title if plan else t.ref}", "/continuity?tab=tests", plan.owner_id if plan else None)
    for pl in session.scalars(select(ContinuityPlan).where(ContinuityPlan.status == "active")):
        planned = session.scalar(select(ContinuityTest.id).where(ContinuityTest.plan_id == pl.id, ContinuityTest.status == "planned"))
        if planned is None:  # a planned test is already on the calendar
            add(continuity.due_on(session, pl), "plan_exercise", f"Exercise due: {pl.title}", "/continuity?tab=plans", pl.owner_id)
    for ar in session.scalars(select(AccessReview).where(AccessReview.status != "completed")):
        add(ar.due_date, "access_review", f"Access review due: {ar.title}", "/access-reviews", ar.owner_id)
    for nc in session.scalars(select(Nonconformity).where(Nonconformity.status != "closed")):
        add(nc.due_date, "nc_due", f"Nonconformity due: {nc.ref} {nc.title}", f"/nonconformities?open={nc.id}", nc.owner_id)
    for ca in session.scalars(select(CorrectiveAction).where(CorrectiveAction.status == "open")):
        add(ca.due_date, "corrective_action", f"Corrective action due: {ca.description[:80]}", f"/nonconformities?open={ca.nonconformity_id}", ca.owner_id)
    for o in session.scalars(select(SecurityObjective).where(SecurityObjective.status.notin_(("achieved", "missed")))):
        add(o.due_date, "objective", f"Objective target date: {o.title}", "/settings/organisation", o.owner_id)
    for fw in session.scalars(select(ConfigTarget).where(ConfigTarget.kind == "firewall", ConfigTarget.facts_at.is_not(None))):
        if fw.facts_at is None:
            continue
        add(fw.facts_at.date() + timedelta(days=FIREWALL_STALE_DAYS), "firewall_upload", f"Upload a current configuration of {fw.name}", f"/configuration?target={fw.id}", None)


def month_bounds(year: int, month: int) -> tuple[date, date]:
    first = date(year, month, 1)
    nxt = (first + timedelta(days=32)).replace(day=1)
    return first, nxt - timedelta(days=1)
