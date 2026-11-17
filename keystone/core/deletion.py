"""Deleting records created in error.

An ISMS keeps its history, so deleting is the exception: a record can be deleted only while nothing depends on it, and
nothing about it was approved, accepted, signed, notified or verified. Otherwise the request is refused with the
reason and what to do instead (retire, close, offboard). The audit log is never touched: `Audited` models record the
deletion with the row's last values, and the explicit log entry names who deleted what.

Comments and ticket links that pointed at the record are removed with it; links in other records' JSON lists (asset
ids on business processes, for example) are cleaned up; foreign keys that are optional are cleared.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .audit import log_event
from .services import authorize, get_or_404


class DeleteRefused(ValueError):
    pass


@dataclass(frozen=True)
class Spec:
    model: str  # "module:Class"
    permission: str
    label: str
    instead: str
    blockers: Callable[[Session, object], list[str]]
    cleanup: Callable[[Session, object], None] | None = None
    comment_kind: str | None = None
    ticket_kind: str | None = None


def _model(path: str):
    import importlib

    mod, cls = path.split(":")
    return getattr(importlib.import_module(mod), cls)


def _count(session: Session, q) -> int:
    return len(list(session.scalars(q)))


# ---- per-record rules -----------------------------------------------------------------------------------------------------

def _risk(session: Session, r) -> list[str]:
    from keystone.incidents.models import Incident

    out = []
    if r.acceptances:
        out.append("it has a risk acceptance on record")
    if _count(session, select(Incident.id).where(Incident.risk_id == r.id)):
        out.append("an incident is linked to it")
    return out


def _asset(session: Session, a) -> list[str]:
    from keystone.incidents.models import incident_assets
    from keystone.risk.models import risk_assets
    from keystone.tprm.models import vendor_assets

    out = []
    if session.execute(select(risk_assets.c.risk_id).where(risk_assets.c.asset_id == a.id)).first():
        out.append("risks are linked to it")
    if session.execute(select(incident_assets.c.incident_id).where(incident_assets.c.asset_id == a.id)).first():
        out.append("incidents are linked to it")
    if session.execute(select(vendor_assets.c.vendor_id).where(vendor_assets.c.asset_id == a.id)).first():
        out.append("vendors are linked to it")
    return out


def _asset_cleanup(session: Session, a) -> None:
    from keystone.configcheck.models import ConfigTarget
    from keystone.continuity.models import BusinessProcess

    for p in session.scalars(select(BusinessProcess)):
        ids = list(p.asset_ids or [])
        if a.id in ids:
            p.asset_ids = [x for x in ids if x != a.id]
    for t in session.scalars(select(ConfigTarget).where(ConfigTarget.asset_id == a.id)):
        t.asset_id = None


def _incident(session: Session, i) -> list[str]:
    from keystone.improvement.models import Nonconformity
    from keystone.privacy.models import BreachAssessment

    out = []
    if i.status == "closed":
        out.append("it is closed")
    if i.regulator_notified_at:
        out.append("a regulator notification is recorded")
    if session.scalar(select(BreachAssessment.id).where(BreachAssessment.incident_id == i.id)):
        out.append("it has a personal data breach assessment")
    if session.scalar(select(Nonconformity.id).where(Nonconformity.incident_id == i.id)):
        out.append("a nonconformity was raised from it")
    from keystone.incidents.models import IncidentEvidence

    if session.scalar(select(IncidentEvidence.id).where(IncidentEvidence.incident_id == i.id)):
        out.append("evidence was collected for it (its chain of custody must be kept)")
    return out


def _vendor(session: Session, v) -> list[str]:
    from keystone.audits.models import Audit
    from keystone.incidents.models import Incident
    from keystone.tprm.models import VendorAssessment, VendorQuestionnaire

    out = []
    if session.scalar(select(VendorAssessment.id).where(VendorAssessment.vendor_id == v.id, VendorAssessment.status == "approved")):
        out.append("it has an approved assessment")
    if session.scalar(select(VendorQuestionnaire.id).where(VendorQuestionnaire.vendor_id == v.id, VendorQuestionnaire.status.in_(("received", "reviewed")))):
        out.append("it has answered questionnaires")
    if session.scalar(select(Incident.id).where(Incident.vendor_id == v.id)):
        out.append("incidents name it")
    if session.scalar(select(Audit.id).where(Audit.vendor_id == v.id)):
        out.append("an audit of it is recorded")
    return out


def _vendor_cleanup(session: Session, v) -> None:
    from keystone.continuity.models import BusinessProcess

    for p in session.scalars(select(BusinessProcess)):
        ids = list(p.vendor_ids or [])
        if v.id in ids:
            p.vendor_ids = [x for x in ids if x != v.id]


def _task(session: Session, t) -> list[str]:
    return ["it was approved and its evidence filed"] if t.status == "done" else ["it is waiting for approval"] if t.status == "in_review" else []


def _task_cleanup(session: Session, t) -> None:
    from keystone.tasks.models import Task

    for nxt in session.scalars(select(Task).where(Task.previous_task_id == t.id)):
        nxt.previous_task_id = None


def _nc(session: Session, n) -> list[str]:
    from keystone.audits.models import AuditFinding

    out = []
    if n.status == "closed":
        out.append("it is closed")
    if any(a.status in ("done", "verified", "ineffective") for a in n.actions):
        out.append("corrective actions were completed")
    if session.scalar(select(AuditFinding.id).where(AuditFinding.nonconformity_id == n.id)):
        out.append("it was raised from an audit finding")
    return out


def _finding(session: Session, f) -> list[str]:
    from keystone.audits.models import Audit

    out = []
    audit = session.get(Audit, f.audit_id)
    if audit is not None and audit.status == "closed":
        out.append("its audit is closed")
    if f.nonconformity_id:
        out.append("a nonconformity was raised from it (delete or close that first)")
    return out


def _dpia(session: Session, d) -> list[str]:
    return [f"it was {d.status}"] if d.status in ("approved", "rejected") else []


def _dsr(session: Session, r) -> list[str]:
    return [f"it was {r.status}"] if r.status in ("completed", "refused") else []


def _process(session: Session, p) -> list[str]:
    from keystone.continuity.models import ContinuityPlan

    return ["a continuity plan covers it"] if any(p.id in (pl.process_ids or []) for pl in session.scalars(select(ContinuityPlan))) else []


def _plan(session: Session, p) -> list[str]:
    from keystone.continuity.models import ContinuityTest

    return ["it has completed tests"] if session.scalar(select(ContinuityTest.id).where(ContinuityTest.plan_id == p.id, ContinuityTest.status == "completed")) else []


def _ctest(session: Session, t) -> list[str]:
    return ["it is completed"] if t.status == "completed" else []


def _none(session: Session, r) -> list[str]:
    return []


SPECS: dict[str, Spec] = {
    "risk": Spec("keystone.risk.models:Risk", "risk.write", "risk", "Close it instead.", _risk, comment_kind="risk", ticket_kind="risk"),
    "asset": Spec("keystone.assets.models:Asset", "asset.write", "asset", "Unlink it or set it to retired instead.", _asset, _asset_cleanup, comment_kind="asset"),
    "incident": Spec("keystone.incidents.models:Incident", "incident.write", "incident", "Close it instead.", _incident, comment_kind="incident", ticket_kind="incident"),
    "vendor": Spec("keystone.tprm.models:Vendor", "vendor.write", "vendor", "Set it to terminated instead.", _vendor, _vendor_cleanup, comment_kind="vendor"),
    "task": Spec("keystone.tasks.models:Task", "task.write", "task", "Mark it not relevant instead.", _task, _task_cleanup, comment_kind="task", ticket_kind="task"),
    "nonconformity": Spec("keystone.improvement.models:Nonconformity", "nc.write", "nonconformity", "Close it instead.", _nc, comment_kind="nonconformity", ticket_kind="nc"),
    "audit_finding": Spec("keystone.audits.models:AuditFinding", "audit.findings", "audit finding", "", _finding),
    "processing_activity": Spec("keystone.privacy.models:ProcessingActivity", "privacy.write", "processing activity", "", _none, comment_kind="processing_activity"),
    "dpia": Spec("keystone.privacy.models:Dpia", "privacy.write", "DPIA", "", _dpia, comment_kind="dpia"),
    "data_subject_request": Spec("keystone.privacy.models:DataSubjectRequest", "privacy.write", "data subject request", "", _dsr, comment_kind="data_subject_request"),
    "business_process": Spec("keystone.continuity.models:BusinessProcess", "continuity.write", "business process", "Set it to retired instead.", _process, comment_kind="business_process"),
    "continuity_plan": Spec("keystone.continuity.models:ContinuityPlan", "continuity.write", "continuity plan", "Set it to retired instead.", _plan, comment_kind="continuity_plan"),
    "continuity_test": Spec("keystone.continuity.models:ContinuityTest", "continuity.write", "continuity test", "", _ctest),
    "objective": Spec("keystone.org.models:SecurityObjective", "org.write", "objective", "", _none, comment_kind="objective"),
    "integration": Spec("keystone.integrations.models:Integration", "integration.manage", "integration", "", _none),
    "trust_document": Spec("keystone.trust.models:TrustDocument", "trust.manage", "Trust Center document", "", _none),
}


def delete_record(session: Session, actor, kind: str, record_id: int) -> None:
    spec = SPECS[kind]
    authorize(session, actor, spec.permission)
    rec = get_or_404(session, _model(spec.model), record_id)
    reasons = spec.blockers(session, rec)
    if reasons:
        raise DeleteRefused(f"This {spec.label} can't be deleted: {'; '.join(reasons)}. {spec.instead}".strip())
    if spec.cleanup:
        spec.cleanup(session, rec)
    if spec.comment_kind:
        from keystone.collab.models import Comment

        session.execute(delete(Comment).where(Comment.entity_type == spec.comment_kind, Comment.entity_id == rec.id))
    if spec.ticket_kind:
        from keystone.ticketing.models import TicketLink

        session.execute(delete(TicketLink).where(TicketLink.record_type == spec.ticket_kind, TicketLink.record_id == rec.id))
    name = getattr(rec, "title", None) or getattr(rec, "name", None) or getattr(rec, "ref", "")
    ref = getattr(rec, "ref", f"#{rec.id}")
    session.delete(rec)
    session.flush()
    log_event(session, actor, "delete", type(rec).__name__, record_id, f"Deleted {spec.label} {ref}: {str(name)[:200]}")
