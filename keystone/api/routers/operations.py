from datetime import date, datetime

from pydantic import Field
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from keystone.audits import review as mr
from keystone.audits import service as aud
from keystone.audits.models import Audit, AuditRequest, ManagementReview
from keystone.core.services import get_or_404
from keystone.improvement import service as imp
from keystone.improvement.models import Nonconformity
from keystone.incidents import service as inc
from keystone.incidents.models import Incident

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(tags=["operations"])

# ---- incidents -------------------------------------------------------------------------
INC = ("id", "title", "description", "category", "severity", "status", "detected_at", "reported_by", "owner_id", "vendor_id", "risk_id", "personal_data_involved", "notification_required", "regulator_notified_at", "contained_at", "root_cause", "lessons_learned", "resolution", "closed_at")


def inc_out(i: Incident, detail=False) -> dict:
    d = ser(i, INC, notification_deadline=inc.notification_deadline(i), allowed_moves=list(inc.TRANSITIONS[i.status]), asset_ids=[a.id for a in i.assets])
    if detail:
        d["events"] = [ser(e, ("id", "occurred_at", "entry", "author", "kind")) for e in i.events]
    return d


@router.get("/incidents")
def incidents(user=Depends(perm("read")), db: Session = Depends(get_db)):
    att = inc.incident_attention(db)
    return {"incidents": [inc_out(i) for i in inc.list_incidents(db)], "attention": {k: [i.id for i in v] for k, v in att.items()}}


@router.get("/incidents/{iid}")
def incident(iid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return inc_out(get_or_404(db, Incident, iid), True)


class IncidentIn(In):
    title: str | None = None
    description: str | None = None
    category: str | None = None
    severity: str | None = None
    detected_at: datetime | None = None
    reported_by: str | None = None
    owner_id: int | None = None
    vendor_id: int | None = None
    risk_id: int | None = None
    personal_data_involved: bool | None = None
    notification_required: bool | None = None
    root_cause: str | None = None
    lessons_learned: str | None = None
    asset_ids: list[int] | None = None


def _naive(dt):
    return dt.replace(tzinfo=None) if dt and dt.tzinfo else dt


@router.post("/incidents")
def report(body: IncidentIn, user=Depends(perm("incident.write")), db: Session = Depends(get_db)):
    f = body.model_dump(exclude_unset=True)
    if "detected_at" in f:
        f["detected_at"] = _naive(f["detected_at"])
    return inc_out(inc.report_incident(db, user, **f), True)


@router.patch("/incidents/{iid}")
def update_incident(iid: int, body: IncidentIn, user=Depends(perm("incident.write")), db: Session = Depends(get_db)):
    f = body.model_dump(exclude_unset=True)
    f.pop("detected_at", None)
    return inc_out(inc.update_incident(db, user, iid, **f), True)


class NoteIn(In):
    entry: str


@router.post("/incidents/{iid}/notes")
def note(iid: int, body: NoteIn, user=Depends(perm("incident.write")), db: Session = Depends(get_db)):
    inc.add_note(db, user, iid, body.entry)
    return inc_out(get_or_404(db, Incident, iid), True)


class MoveIn(In):
    status: str
    resolution: str | None = None


@router.post("/incidents/{iid}/move")
def move(iid: int, body: MoveIn, user=Depends(perm("incident.write")), db: Session = Depends(get_db)):
    return inc_out(inc.move(db, user, iid, body.status, body.resolution), True)


@router.post("/incidents/{iid}/notify")
def notify(iid: int, user=Depends(perm("incident.write")), db: Session = Depends(get_db)):
    return inc_out(inc.record_notification(db, user, iid), True)


# ---- nonconformities ------------------------------------------------------------------------
NC = ("id", "title", "description", "source", "severity", "status", "requirement_id", "common_control_id", "incident_id", "owner_id", "containment", "root_cause", "due_date", "closed_at", "closed_by_id", "created_by_id")
CA = ("id", "description", "owner_id", "due_date", "status", "completed_at", "completion_notes", "verified_by_id", "verified_at", "effectiveness_notes")


def nc_out(n: Nonconformity) -> dict:
    return ser(n, NC, actions=[ser(a, CA) for a in n.actions])


@router.get("/nonconformities")
def ncs(user=Depends(perm("read")), db: Session = Depends(get_db)):
    att = imp.nc_attention(db)
    return {"items": [nc_out(n) for n in imp.list_ncs(db)], "attention": {"overdue": [n.id for n in att["overdue"]], "actions_overdue": [a.id for a in att["actions_overdue"]], "awaiting_verification": [a.id for a in att["awaiting_verification"]]}}


class NcIn(In):
    title: str | None = None
    description: str | None = None
    source: str | None = None
    severity: str | None = None
    requirement_id: int | None = None
    common_control_id: int | None = None
    incident_id: int | None = None
    owner_id: int | None = None
    containment: str | None = None
    root_cause: str | None = None
    due_date: date | None = None


@router.post("/nonconformities")
def raise_nc(body: NcIn, user=Depends(perm("read")), db: Session = Depends(get_db)):
    # nc.write or audit.findings; the service checks which applies.
    return nc_out(imp.raise_nc(db, user, **body.model_dump(exclude_unset=True)))


@router.patch("/nonconformities/{nid}")
def update_nc(nid: int, body: NcIn, user=Depends(perm("nc.write")), db: Session = Depends(get_db)):
    f = body.model_dump(exclude_unset=True)
    f.pop("source", None)
    return nc_out(imp.update_nc(db, user, nid, **f))


class CaIn(In):
    description: str
    owner_id: int | None = None
    due_date: date | None = None


@router.post("/nonconformities/{nid}/actions")
def add_ca(nid: int, body: CaIn, user=Depends(perm("nc.write")), db: Session = Depends(get_db)):
    imp.add_action(db, user, nid, body.description, body.owner_id, body.due_date)
    return nc_out(get_or_404(db, Nonconformity, nid))


@router.post("/nonconformities/{nid}/plan")
def plan(nid: int, user=Depends(perm("nc.write")), db: Session = Depends(get_db)):
    return nc_out(imp.plan(db, user, nid))


class DoneIn(In):
    notes: str


@router.post("/corrective-actions/{aid}/complete")
def complete(aid: int, body: DoneIn, user=Depends(perm("nc.write")), db: Session = Depends(get_db)):
    return nc_out(imp.complete_action(db, user, aid, body.notes).nonconformity)


class VerifyIn(In):
    effective: bool
    notes: str


@router.post("/corrective-actions/{aid}/verify")
def verify(aid: int, body: VerifyIn, user=Depends(perm("nc.verify")), db: Session = Depends(get_db)):
    return nc_out(imp.verify_action(db, user, aid, body.effective, body.notes).nonconformity)


@router.post("/nonconformities/{nid}/close")
def close(nid: int, user=Depends(perm("nc.verify")), db: Session = Depends(get_db)):
    return nc_out(imp.close(db, user, nid))


# ---- audits ---------------------------------------------------------------------------------
AUD = ("id", "title", "audit_type", "scope", "criteria", "framework_id", "vendor_id", "lead_auditor_id", "audit_team", "planned_start", "planned_end", "status", "summary", "conclusion", "closed_at")


def aud_out(a: Audit) -> dict:
    return ser(a, AUD, control_ids=[c.id for c in a.controls], controls=[c.code for c in a.controls], conflicts=aud.independence_conflicts(a), next_status=aud.NEXT.get(a.status),
               findings=[ser(f, ("id", "finding_type", "title", "description", "evidence", "common_control_id", "nonconformity_id")) for f in a.findings])


@router.get("/audits")
def audits(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return {"audits": [aud_out(a) for a in aud.list_audits(db)], "coverage": aud.control_coverage(db)}


class AuditIn(In):
    title: str | None = None
    audit_type: str | None = None
    scope: str | None = None
    criteria: str | None = None
    framework_id: int | None = None
    vendor_id: int | None = None
    lead_auditor_id: int | None = None
    audit_team: str | None = None
    planned_start: date | None = None
    planned_end: date | None = None
    summary: str | None = None
    conclusion: str | None = None
    control_ids: list[int] | None = None


@router.post("/audits")
def create_audit(body: AuditIn, user=Depends(perm("audit.manage")), db: Session = Depends(get_db)):
    return aud_out(aud.save_audit(db, user, **body.model_dump(exclude_unset=True)))


@router.patch("/audits/{aid}")
def update_audit(aid: int, body: AuditIn, user=Depends(perm("audit.manage")), db: Session = Depends(get_db)):
    return aud_out(aud.save_audit(db, user, aid, **body.model_dump(exclude_unset=True)))


@router.post("/audits/{aid}/advance")
def advance(aid: int, user=Depends(perm("audit.manage")), db: Session = Depends(get_db)):
    return aud_out(aud.advance(db, user, aid))


# ---- evidence request list ("PBC") and audit pack ---------------------------------------------------

def req_out(r) -> dict:
    return ser(r, ("id", "audit_id", "title", "description", "common_control_id", "due_date", "status", "created_by_id", "created_at"),
               evidence=[{"id": e.id, "title": e.title, "attachment_id": e.attachment_id, "filename": e.attachment.filename if e.attachment else None, "url": e.url, "common_control_id": e.common_control_id} for e in r.evidence],
               comments=[ser(c, ("id", "body", "created_by_id", "created_at")) for c in r.comments])


@router.get("/audits/{aid}/requests")
def audit_requests(aid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [req_out(r) for r in aud.requests_for(db, aid)]


class RequestIn(In):
    title: str = Field(max_length=300)
    description: str | None = Field(default=None, max_length=5000)
    common_control_id: int | None = None
    due_date: date | None = None


@router.post("/audits/{aid}/requests")
def add_request(aid: int, body: RequestIn, user=Depends(perm("audit.findings")), db: Session = Depends(get_db)):
    return req_out(aud.add_request(db, user, aid, **body.model_dump()))


class CommentIn(In):
    body: str = Field(max_length=5000)


@router.post("/audit-requests/{rid}/comments")
def comment_request(rid: int, body: CommentIn, user=Depends(perm("audit.findings")), db: Session = Depends(get_db)):
    aud.comment_request(db, user, rid, body.body)
    return req_out(get_or_404(db, AuditRequest, rid))


class RespondIn(In):
    body: str | None = Field(default=None, max_length=5000)
    evidence_ids: list[int] | None = Field(default=None, max_length=200)


@router.post("/audit-requests/{rid}/respond")
def respond_request(rid: int, body: RespondIn, user=Depends(perm("evidence.write")), db: Session = Depends(get_db)):
    return req_out(aud.respond_request(db, user, rid, body=body.body, evidence_ids=body.evidence_ids))


class RequestStatusIn(In):
    status: str


@router.post("/audit-requests/{rid}/status")
def request_status(rid: int, body: RequestStatusIn, user=Depends(perm("audit.findings")), db: Session = Depends(get_db)):
    return req_out(aud.set_request_status(db, user, rid, body.status))


@router.get("/audits/{aid}/pack.zip")
def audit_pack(aid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    from fastapi.responses import StreamingResponse

    from keystone.audits import pack

    f, name, _n = pack.build(db, user, aid)

    def chunks():
        try:
            while data := f.read(1024 * 1024):
                yield data
        finally:
            f.close()

    return StreamingResponse(chunks(), media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="{name}"', "X-Content-Type-Options": "nosniff"})


class FindingIn(In):
    finding_type: str
    title: str
    description: str | None = None
    evidence: str | None = None
    requirement_id: int | None = None
    common_control_id: int | None = None


@router.post("/audits/{aid}/findings")
def finding(aid: int, body: FindingIn, user=Depends(perm("audit.findings")), db: Session = Depends(get_db)):
    aud.add_finding(db, user, aid, **body.model_dump())
    return aud_out(get_or_404(db, Audit, aid))


# ---- management review ------------------------------------------------------------------------
MR = ("id", "title", "held_on", "period_start", "attendees", "status", "inputs", "interested_party_feedback", "improvement_opportunities", "discussion", "decisions", "actions", "finalized_by_id", "finalized_at")


@router.get("/reviews")
def reviews(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [ser(r, ("id", "title", "held_on", "period_start", "status", "finalized_by_id")) for r in mr.list_reviews(db)]


@router.get("/reviews/{rid}")
def review(rid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return ser(get_or_404(db, ManagementReview, rid), MR)


class ReviewNew(In):
    title: str
    held_on: date
    attendees: str | None = None


@router.post("/reviews")
def create_review(body: ReviewNew, user=Depends(perm("review.write")), db: Session = Depends(get_db)):
    return ser(mr.create_review(db, user, **body.model_dump()), MR)


class ReviewIn(In):
    title: str | None = None
    attendees: str | None = None
    interested_party_feedback: str | None = None
    improvement_opportunities: str | None = None
    discussion: str | None = None
    decisions: str | None = None
    actions: str | None = None


@router.patch("/reviews/{rid}")
def update_review(rid: int, body: ReviewIn, user=Depends(perm("review.write")), db: Session = Depends(get_db)):
    return ser(mr.update_review(db, user, rid, **body.model_dump(exclude_unset=True)), MR)


@router.post("/reviews/{rid}/refresh")
def refresh(rid: int, user=Depends(perm("review.write")), db: Session = Depends(get_db)):
    return ser(mr.refresh_inputs(db, user, rid), MR)


class ImproveIn(In):
    title: str
    owner_id: int | None = None
    due_date: date | None = None


@router.post("/reviews/{rid}/improvements")
def improvement(rid: int, body: ImproveIn, user=Depends(perm("review.write")), db: Session = Depends(get_db)):
    return nc_out(mr.raise_improvement(db, user, rid, body.title, body.owner_id, body.due_date))


@router.post("/reviews/{rid}/finalize")
def finalize(rid: int, user=Depends(perm("review.write")), db: Session = Depends(get_db)):
    return ser(mr.finalize(db, user, rid), MR)


# ---- deleting records created in error (keystone/core/deletion.py: refused while anything depends on them)


@router.delete("/incidents/{iid}")
def delete_incident(iid: int, user=Depends(perm("incident.write")), db: Session = Depends(get_db)):
    from keystone.core.deletion import delete_record

    delete_record(db, user, "incident", iid)
    return {"ok": True}


@router.delete("/nonconformities/{nid}")
def delete_nonconformity(nid: int, user=Depends(perm("nc.write")), db: Session = Depends(get_db)):
    from keystone.core.deletion import delete_record

    delete_record(db, user, "nonconformity", nid)
    return {"ok": True}


@router.delete("/audit-findings/{fid}")
def delete_audit_finding(fid: int, user=Depends(perm("audit.findings")), db: Session = Depends(get_db)):
    from keystone.core.deletion import delete_record

    delete_record(db, user, "audit_finding", fid)
    return {"ok": True}
