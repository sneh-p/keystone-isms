"""Tasks, onboarding, control readiness."""

from datetime import date

from fastapi import APIRouter, Depends, File, Query, UploadFile
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.core.attachments import attachments_for
from keystone.core.services import get_or_404
from keystone.frameworks.models import CommonControl
from keystone.onboarding import service as onb
from keystone.tasks import service as tsk
from keystone.tasks.models import Task

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(tags=["tasks"])
TASK = ("id", "title", "description", "template_key", "evidence_hint", "frequency", "assignee_id", "due_date", "status", "completion_notes", "submitted_by_id", "submitted_at", "approved_by_id", "approved_at", "review_comment", "not_relevant_reason", "previous_task_id")


def task_out(db, t: Task, detail=False) -> dict:
    d = ser(t, TASK, overdue=tsk.overdue(t), controls=[{"id": c.id, "code": c.code, "title": c.title} for c in t.controls])
    if detail:
        d["attachments"] = [ser(a, ("id", "filename", "size", "created_at")) for a in attachments_for(db, "Task", t.id)]
    return d


@router.get("/tasks")
def tasks(mine: bool = False, include_closed: bool = True, closed_limit: int = Query(500, ge=0, le=5000), user=Depends(perm("read")), db: Session = Depends(get_db)):
    # SC-ERR-004: every open task, plus the most recent completed ones (bounded).
    return [task_out(db, t) for t in tsk.list_tasks(db, assignee_id=user.id if mine else None, include_closed=include_closed, closed_limit=closed_limit)]


@router.get("/tasks/{tid}")
def task(tid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return task_out(db, get_or_404(db, Task, tid), True)


class TaskIn(In):
    title: str | None = None
    description: str | None = None
    frequency: str | None = None
    assignee_id: int | None = None
    due_date: date | None = None
    evidence_hint: str | None = None
    control_ids: list[int] | None = None


@router.post("/tasks")
def create(body: TaskIn, user=Depends(perm("task.write")), db: Session = Depends(get_db)):
    return task_out(db, tsk.save_task(db, user, **body.model_dump(exclude_unset=True)), True)


class TaskBulkIn(In):
    ids: list[int] = Field(min_length=1, max_length=500)
    assignee_id: int | None = None
    due_date: date | None = None


@router.post("/tasks/bulk")
def bulk_update(body: TaskBulkIn, user=Depends(perm("task.write")), db: Session = Depends(get_db)):
    return {"updated": len(tsk.bulk_update_tasks(db, user, body.ids, **body.model_dump(exclude_unset=True, exclude={"ids"})))}


@router.patch("/tasks/{tid}")
def update(tid: int, body: TaskIn, user=Depends(perm("task.write")), db: Session = Depends(get_db)):
    return task_out(db, tsk.save_task(db, user, tid, **body.model_dump(exclude_unset=True)), True)


@router.post("/tasks/{tid}/start")
def start(tid: int, user=Depends(perm("task.write")), db: Session = Depends(get_db)):
    return task_out(db, tsk.start(db, user, tid), True)


@router.post("/tasks/{tid}/attachments")
async def attach(tid: int, file: UploadFile = File(...), user=Depends(perm("task.write")), db: Session = Depends(get_db)):
    tsk.add_attachment(db, user, tid, file.filename or "evidence", await file.read())
    return task_out(db, get_or_404(db, Task, tid), True)


class NotesIn(In):
    notes: str | None = None


@router.post("/tasks/{tid}/submit")
def submit(tid: int, body: NotesIn, user=Depends(perm("task.write")), db: Session = Depends(get_db)):
    return task_out(db, tsk.submit(db, user, tid, body.notes), True)


class CommentIn(In):
    comment: str | None = None


@router.post("/tasks/{tid}/approve")
def approve(tid: int, body: CommentIn, user=Depends(perm("task.approve")), db: Session = Depends(get_db)):
    return task_out(db, tsk.approve(db, user, tid, body.comment), True)


@router.post("/tasks/{tid}/return")
def send_back(tid: int, body: CommentIn, user=Depends(perm("task.approve")), db: Session = Depends(get_db)):
    return task_out(db, tsk.send_back(db, user, tid, body.comment or ""), True)


@router.post("/tasks/{tid}/not-relevant")
def not_relevant(tid: int, body: CommentIn, user=Depends(perm("task.approve")), db: Session = Depends(get_db)):
    return task_out(db, tsk.mark_not_relevant(db, user, tid, body.comment or ""), True)


@router.get("/task-templates")
def task_templates(user=Depends(perm("read"))):
    return tsk.templates()


@router.get("/controls/{cid}/readiness")
def readiness(cid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    c = get_or_404(db, CommonControl, cid)
    r = tsk.control_readiness(db, c)
    return {"status": r.status, "score": r.score, "checks": r.checks, "tasks": [task_out(db, t) for t in db.query(Task).join(Task.controls).filter(CommonControl.id == cid).order_by(Task.id.desc()).limit(20)]}


@router.get("/readiness")
def all_readiness(user=Depends(perm("read")), db: Session = Depends(get_db)):
    out = {}
    for c in db.query(CommonControl).all():
        r = tsk.control_readiness(db, c)
        out[c.id] = {"status": r.status, "score": r.score}
    return out


# ---- onboarding ------------------------------------------------------------------------------

@router.get("/onboarding")
def onboarding_state(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return {**onb.state(db), "hosting_options": onb.HOSTING, "sizes": onb.SIZES, "policy_templates": [{"code": m["code"], "title": m["title"], "when": m.get("when")} for m, _ in onb.policy_templates()], "task_template_count": len(tsk.templates())}


class ProfileIn(In):
    company_name: str
    legal_name: str | None = None
    industry: str | None = None
    description: str | None = None
    size: str | None = None
    website: str | None = None
    locations: str | None = None
    hosting: list[str] = []
    data_types: list[str] = []
    develops_software: bool = False
    offices: bool = True
    frameworks: list[str]
    isms_owner_id: int | None = None
    review_months: int = 12


@router.post("/onboarding/complete")
def complete(body: ProfileIn, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    return onb.complete(db, user, body.model_dump())
