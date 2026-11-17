"""Privacy: records of processing, DPIAs, data subject requests (privacy.write only) and the breach log."""

from datetime import date, datetime

from fastapi import APIRouter, Depends
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.privacy import service as pv

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(prefix="/privacy", tags=["privacy"])
ACTIVITY = ("id", "name", "purpose", "role", "lawful_basis", "legitimate_interest", "special_category", "special_condition", "data_subjects", "data_categories",
            "recipients", "vendor_ids", "asset_ids", "transfers", "transfer_safeguard", "retention", "security_measures", "dpia_required", "owner_id", "status",
            "next_review_date", "updated_at")
DPIA = ("id", "title", "activity_id", "description", "necessity", "risks", "dpo_advice", "outcome", "status", "submitted_by_id", "decided_by_id", "decided_at",
        "decision_note", "next_review_date", "created_by_id", "updated_at")
REQUEST = ("id", "request_type", "received_on", "channel", "requester_name", "requester_contact", "details", "identity_verified", "due_date", "extended",
           "extension_reason", "status", "assignee_id", "outcome", "closed_on", "redacted_at")
BREACH = ("id", "incident_id", "data_categories", "subjects_affected", "records_affected", "consequences", "measures", "risk_level", "rationale", "authority_reference",
          "subjects_notified_at")
T = Field(default=None, max_length=4000)


class ActivityIn(In):
    name: str | None = Field(default=None, max_length=200)
    purpose: str | None = T
    role: str | None = None
    lawful_basis: str | None = None
    legitimate_interest: str | None = T
    special_category: bool | None = None
    special_condition: str | None = Field(default=None, max_length=300)
    data_subjects: str | None = T
    data_categories: str | None = T
    recipients: str | None = T
    vendor_ids: list[int] | None = Field(default=None, max_length=200)
    asset_ids: list[int] | None = Field(default=None, max_length=200)
    transfers: str | None = T
    transfer_safeguard: str | None = None
    retention: str | None = Field(default=None, max_length=500)
    security_measures: str | None = T
    dpia_required: bool | None = None
    owner_id: int | None = None
    status: str | None = None
    next_review_date: date | None = None


@router.get("/activities")
def activities(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [ser(a, ACTIVITY) for a in pv.activities(db, user)]


@router.post("/activities")
def create_activity(body: ActivityIn, user=Depends(perm("privacy.write")), db: Session = Depends(get_db)):
    return ser(pv.save_activity(db, user, **body.model_dump(exclude_unset=True)), ACTIVITY)


@router.patch("/activities/{aid}")
def update_activity(aid: int, body: ActivityIn, user=Depends(perm("privacy.write")), db: Session = Depends(get_db)):
    return ser(pv.save_activity(db, user, aid, **body.model_dump(exclude_unset=True)), ACTIVITY)


class RiskIn(In):
    risk: str = Field(max_length=500)
    likelihood: int | None = Field(default=None, ge=1, le=3)
    severity: int | None = Field(default=None, ge=1, le=3)
    measures: str | None = Field(default=None, max_length=1000)
    residual: int | None = Field(default=None, ge=1, le=3)


class DpiaIn(In):
    title: str | None = Field(default=None, max_length=300)
    activity_id: int | None = None
    description: str | None = T
    necessity: str | None = T
    risks: list[RiskIn] | None = Field(default=None, max_length=50)
    dpo_advice: str | None = T
    outcome: str | None = None
    next_review_date: date | None = None


def _dpia(d) -> dict:
    return ser(d, DPIA, high_residual=pv.high_residual(d))


@router.get("/dpias")
def dpias(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [_dpia(d) for d in pv.dpias(db, user)]


@router.post("/dpias")
def create_dpia(body: DpiaIn, user=Depends(perm("privacy.write")), db: Session = Depends(get_db)):
    return _dpia(pv.save_dpia(db, user, **body.model_dump(exclude_unset=True)))


@router.patch("/dpias/{did}")
def update_dpia(did: int, body: DpiaIn, user=Depends(perm("privacy.write")), db: Session = Depends(get_db)):
    return _dpia(pv.save_dpia(db, user, did, **body.model_dump(exclude_unset=True)))


@router.post("/dpias/{did}/submit")
def submit_dpia(did: int, user=Depends(perm("privacy.write")), db: Session = Depends(get_db)):
    return _dpia(pv.submit_dpia(db, user, did))


class DecisionIn(In):
    approve: bool
    note: str = Field(min_length=1, max_length=4000)


@router.post("/dpias/{did}/decide")
def decide_dpia(did: int, body: DecisionIn, user=Depends(perm("risk.accept")), db: Session = Depends(get_db)):
    return _dpia(pv.decide_dpia(db, user, did, body.approve, body.note))


class RequestIn(In):
    request_type: str | None = None
    received_on: date | None = None
    channel: str | None = Field(default=None, max_length=100)
    requester_name: str | None = Field(default=None, max_length=200)
    requester_contact: str | None = Field(default=None, max_length=320)
    details: str | None = T
    identity_verified: bool | None = None
    assignee_id: int | None = None
    outcome: str | None = T


@router.get("/requests")
def requests(user=Depends(perm("privacy.write")), db: Session = Depends(get_db)):
    return [ser(r, REQUEST) for r in pv.requests(db, user)]


@router.post("/requests")
def create_request(body: RequestIn, user=Depends(perm("privacy.write")), db: Session = Depends(get_db)):
    return ser(pv.save_request(db, user, **body.model_dump(exclude_unset=True)), REQUEST)


@router.patch("/requests/{rid}")
def update_request(rid: int, body: RequestIn, user=Depends(perm("privacy.write")), db: Session = Depends(get_db)):
    return ser(pv.save_request(db, user, rid, **body.model_dump(exclude_unset=True)), REQUEST)


class ExtendIn(In):
    reason: str = Field(min_length=1, max_length=2000)


@router.post("/requests/{rid}/extend")
def extend_request(rid: int, body: ExtendIn, user=Depends(perm("privacy.write")), db: Session = Depends(get_db)):
    return ser(pv.extend_request(db, user, rid, body.reason), REQUEST)


class MoveIn(In):
    status: str = Field(max_length=20)
    outcome: str | None = T


@router.post("/requests/{rid}/status")
def move_request(rid: int, body: MoveIn, user=Depends(perm("privacy.write")), db: Session = Depends(get_db)):
    return ser(pv.move_request(db, user, rid, body.status, body.outcome), REQUEST)


@router.get("/breaches")
def breaches(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [{"incident_id": b["incident"].id, "ref": b["incident"].ref, "title": b["incident"].title, "severity": b["incident"].severity,
             "status": b["incident"].status, "detected_at": b["incident"].detected_at, "personal_data_involved": b["incident"].personal_data_involved,
             "notification_required": b["incident"].notification_required, "regulator_notified_at": b["incident"].regulator_notified_at,
             "deadline": b["deadline"], "late": b["late"], "assessment": ser(b["assessment"], BREACH) if b["assessment"] else None} for b in pv.breaches(db, user)]


class BreachIn(In):
    data_categories: str | None = T
    subjects_affected: int | None = Field(default=None, ge=0)
    records_affected: int | None = Field(default=None, ge=0)
    consequences: str | None = T
    measures: str | None = T
    risk_level: str | None = None
    rationale: str | None = T
    authority_reference: str | None = Field(default=None, max_length=100)
    subjects_notified_at: datetime | None = None


@router.put("/breaches/{incident_id}")
def assess_breach(incident_id: int, body: BreachIn, user=Depends(perm("privacy.write")), db: Session = Depends(get_db)):
    return ser(pv.assess_breach(db, user, incident_id, **body.model_dump(exclude_unset=True)), BREACH)


# ---- deleting records created in error (keystone/core/deletion.py: refused while anything depends on them)


@router.delete("/activities/{aid}")
def delete_processing_activity(aid: int, user=Depends(perm("privacy.write")), db: Session = Depends(get_db)):
    from keystone.core.deletion import delete_record

    delete_record(db, user, "processing_activity", aid)
    return {"ok": True}


@router.delete("/dpias/{did}")
def delete_dpia(did: int, user=Depends(perm("privacy.write")), db: Session = Depends(get_db)):
    from keystone.core.deletion import delete_record

    delete_record(db, user, "dpia", did)
    return {"ok": True}


@router.delete("/requests/{rid}")
def delete_data_subject_request(rid: int, user=Depends(perm("privacy.write")), db: Session = Depends(get_db)):
    from keystone.core.deletion import delete_record

    delete_record(db, user, "data_subject_request", rid)
    return {"ok": True}
