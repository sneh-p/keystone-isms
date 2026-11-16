from fastapi import APIRouter, Depends, File, Form, UploadFile
from sqlalchemy.orm import Session

from keystone.core.services import get_or_404
from keystone.policies import service as pol
from keystone.policies.models import PolicyDocument, PolicyVersion

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(prefix="/policies", tags=["policies"])
DOC = ("id", "code", "title", "doc_type", "owner_id", "status", "review_interval_months", "next_review_date", "requires_acknowledgement", "current_version_id")
VER = ("id", "document_id", "version_label", "body", "attachment_id", "change_summary", "status", "author_id", "submitted_at", "approved_by_id", "approved_at", "approval_note")


def doc_out(db, d: PolicyDocument, detail=False) -> dict:
    cur = pol.current_version(db, d)
    ov = pol.open_version(d)
    ack = pol.ack_status(db, d)
    out = ser(d, DOC, current_version=cur.version_label if cur else None, open_version=None if ov is None else {"id": ov.id, "label": ov.version_label, "status": ov.status},
              ack=None if ack is None else {"acknowledged": ack.acknowledged, "total": ack.total, "pct": ack.pct}, control_ids=[c.id for c in d.controls], controls=[c.code for c in d.controls])
    if detail:
        out["versions"] = [ser(v, VER) for v in reversed(d.versions)]
    return out


@router.get("")
def documents(include_retired: bool = False, user=Depends(perm("read")), db: Session = Depends(get_db)):
    docs = pol.documents(db, include_retired)
    att = pol.policy_attention(db)
    return {"documents": [doc_out(db, d) for d in docs], "attention": {k: [d.id for d in v] for k, v in att.items()}}


@router.get("/pending")
def pending(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [ser(v, ("id", "version_label", "body", "attachment_id"), code=v.document.code, title=v.document.title) for v in pol.pending_for(db, user)]


@router.get("/{did}")
def document(did: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return doc_out(db, get_or_404(db, PolicyDocument, did), True)


class DocIn(In):
    code: str | None = None
    title: str | None = None
    doc_type: str | None = None
    owner_id: int | None = None
    review_interval_months: int | None = None
    requires_acknowledgement: bool | None = None
    control_ids: list[int] | None = None


@router.post("")
def create(body: DocIn, user=Depends(perm("policy.write")), db: Session = Depends(get_db)):
    return doc_out(db, pol.save_document(db, user, **body.model_dump(exclude_unset=True)), True)


@router.patch("/{did}")
def update(did: int, body: DocIn, user=Depends(perm("policy.write")), db: Session = Depends(get_db)):
    return doc_out(db, pol.save_document(db, user, did, **body.model_dump(exclude_unset=True)), True)


class VersionIn(In):
    body: str | None = None
    change_summary: str | None = None
    major: bool = True


@router.post("/{did}/versions")
def start(did: int, body: VersionIn, user=Depends(perm("policy.write")), db: Session = Depends(get_db)):
    pol.start_version(db, user, did, body=body.body, change_summary=body.change_summary, major=body.major)
    return doc_out(db, get_or_404(db, PolicyDocument, did), True)


@router.patch("/versions/{vid}")
async def edit(vid: int, body: str | None = Form(None), change_summary: str | None = Form(None), file: UploadFile | None = File(None), user=Depends(perm("policy.write")), db: Session = Depends(get_db)):
    data = await file.read() if file else None
    v = pol.edit_version(db, user, vid, body=body, change_summary=change_summary, filename=file.filename if file else None, data=data)
    return ser(v, VER)


@router.post("/versions/{vid}/submit")
def submit(vid: int, user=Depends(perm("policy.write")), db: Session = Depends(get_db)):
    return ser(pol.submit_version(db, user, vid), VER)


class NoteIn(In):
    note: str | None = None


@router.post("/versions/{vid}/approve")
def approve(vid: int, body: NoteIn, user=Depends(perm("policy.approve")), db: Session = Depends(get_db)):
    return ser(pol.approve_version(db, user, vid, body.note), VER)


@router.post("/versions/{vid}/return")
def return_(vid: int, body: NoteIn, user=Depends(perm("policy.approve")), db: Session = Depends(get_db)):
    return ser(pol.return_version(db, user, vid, body.note or ""), VER)


@router.post("/versions/{vid}/acknowledge")
def acknowledge(vid: int, user=Depends(perm("policy.acknowledge")), db: Session = Depends(get_db)):
    a = pol.acknowledge(db, user, vid)
    return ser(a, ("id", "version_id", "acknowledged_at"))


@router.post("/{did}/review")
def review(did: int, user=Depends(perm("policy.approve")), db: Session = Depends(get_db)):
    return doc_out(db, pol.record_review_no_change(db, user, did))


@router.post("/{did}/retire")
def retire(did: int, user=Depends(perm("policy.approve")), db: Session = Depends(get_db)):
    return doc_out(db, pol.retire(db, user, did))
