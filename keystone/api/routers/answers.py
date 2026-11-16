from datetime import date

from fastapi import APIRouter, Depends, File, Form, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.answers import service as svc
from keystone.answers.models import KnowledgeEntry, QuestionnaireItem, SecurityQuestionnaire
from keystone.core.services import get_or_404

from ..deps import get_db, perm
from ..serialize import ser
from .common import In, people_names, xlsx_response

router = APIRouter(tags=["security questionnaires"])
SQ = ("id", "title", "requester", "due_date", "status", "source_kind", "attachment_id", "job_status", "job_progress", "job_total", "job_error", "created_at")
ITEM = ("id", "position", "section", "question", "answer", "status", "origin", "confidence", "citations", "note", "sheet", "row", "reviewed_by_id", "reviewed_at")
KB = ("id", "question", "answer", "tags", "status", "approved_by_id", "approved_at", "updated_at")


def sq_out(q: SecurityQuestionnaire, items=False, names=None) -> dict:
    out = ser(q, SQ, progress=svc.progress(q))
    if items:
        out["items"] = [ser(it, ITEM, reviewed_by=(names or {}).get(it.reviewed_by_id)) for it in q.items]
    return out


@router.get("/security-questionnaires")
def list_all(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [sq_out(q) for q in db.scalars(select(SecurityQuestionnaire).order_by(SecurityQuestionnaire.created_at.desc()))]


@router.post("/security-questionnaires")
async def create(title: str = Form(..., max_length=200), requester: str | None = Form(None, max_length=200), due_date: date | None = Form(None), pasted: str | None = Form(None, max_length=500_000),
                 file: UploadFile | None = File(None), user=Depends(perm("questionnaire.write")), db: Session = Depends(get_db)):
    data = await file.read() if file else None
    q = svc.create(db, user, title=title, requester=requester, due_date=due_date, filename=file.filename if file else None, data=data, pasted=pasted)
    return sq_out(q, True)


@router.get("/security-questionnaires/{qid}")
def detail(qid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return sq_out(get_or_404(db, SecurityQuestionnaire, qid), True, people_names(db))


@router.delete("/security-questionnaires/{qid}")
def delete(qid: int, user=Depends(perm("questionnaire.approve")), db: Session = Depends(get_db)):
    svc.delete(db, user, qid)
    return {"ok": True}


class StatusIn(In):
    status: str


@router.post("/security-questionnaires/{qid}/status")
def set_status(qid: int, body: StatusIn, user=Depends(perm("questionnaire.approve")), db: Session = Depends(get_db)):
    return sq_out(svc.set_status(db, user, qid, body.status))


@router.post("/security-questionnaires/{qid}/fill-from-kb")
def fill(qid: int, user=Depends(perm("questionnaire.write")), db: Session = Depends(get_db)):
    n = svc.fill_from_knowledge_base(db, user, qid)
    return {"filled": n, **sq_out(get_or_404(db, SecurityQuestionnaire, qid), True, people_names(db))}


class DraftIn(In):
    item_ids: list[int] | None = None


@router.post("/security-questionnaires/{qid}/ai-draft")
def ai_draft(qid: int, body: DraftIn, user=Depends(perm("questionnaire.write")), db: Session = Depends(get_db)):
    return sq_out(svc.start_ai_draft(db, user, qid, body.item_ids))


@router.get("/security-questionnaires/{qid}/export")
def export(qid: int, include_drafts: bool = False, user=Depends(perm("read")), db: Session = Depends(get_db)):
    data, name = svc.export_xlsx(db, user, qid, approved_only=not include_drafts)
    return xlsx_response(data, name)


class ItemIn(In):
    answer: str | None = None
    note: str | None = None


def item_out(db, it: QuestionnaireItem) -> dict:
    return ser(it, ITEM, reviewed_by=people_names(db).get(it.reviewed_by_id))


@router.patch("/questionnaire-items/{iid}")
def edit_item(iid: int, body: ItemIn, user=Depends(perm("questionnaire.write")), db: Session = Depends(get_db)):
    return item_out(db, svc.edit_item(db, user, iid, **body.model_dump(exclude_unset=True)))


@router.post("/questionnaire-items/{iid}/approve")
def approve_item(iid: int, user=Depends(perm("questionnaire.approve")), db: Session = Depends(get_db)):
    return item_out(db, svc.approve_item(db, user, iid))


@router.post("/questionnaire-items/{iid}/unapprove")
def unapprove_item(iid: int, user=Depends(perm("questionnaire.approve")), db: Session = Depends(get_db)):
    return item_out(db, svc.unapprove_item(db, user, iid))


@router.get("/questionnaire-items/{iid}/suggestions")
def suggestions(iid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return svc.suggestions(db, iid)


@router.post("/questionnaire-items/{iid}/to-knowledge-base")
def to_kb(iid: int, user=Depends(perm("questionnaire.approve")), db: Session = Depends(get_db)):
    return ser(svc.entry_from_item(db, user, iid), KB)


@router.get("/knowledge-base")
def kb_list(user=Depends(perm("read")), db: Session = Depends(get_db)):
    names = people_names(db)
    return [ser(e, KB, approved_by=names.get(e.approved_by_id)) for e in svc.entries(db)]


class KbIn(In):
    question: str | None = None
    answer: str | None = None
    tags: str | None = None


@router.post("/knowledge-base")
def kb_create(body: KbIn, user=Depends(perm("questionnaire.write")), db: Session = Depends(get_db)):
    return ser(svc.save_entry(db, user, **body.model_dump(exclude_unset=True)), KB)


@router.patch("/knowledge-base/{eid}")
def kb_update(eid: int, body: KbIn, user=Depends(perm("questionnaire.write")), db: Session = Depends(get_db)):
    return ser(svc.save_entry(db, user, eid, **body.model_dump(exclude_unset=True)), KB)


@router.post("/knowledge-base/{eid}/approve")
def kb_approve(eid: int, user=Depends(perm("questionnaire.approve")), db: Session = Depends(get_db)):
    return ser(svc.approve_entry(db, user, eid), KB)


@router.delete("/knowledge-base/{eid}")
def kb_delete(eid: int, user=Depends(perm("questionnaire.approve")), db: Session = Depends(get_db)):
    svc.delete_entry(db, user, eid)
    return {"ok": True}
