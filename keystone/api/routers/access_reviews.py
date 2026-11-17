"""Access review campaigns."""

from datetime import date

from fastapi import APIRouter, Depends
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.access_reviews import service as ar

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(prefix="/access-reviews", tags=["access-reviews"])
REVIEW = ("id", "title", "sources", "owner_id", "due_date", "status", "completed_at", "created_at", "repeat_months", "next_start_on")
ITEM = ("id", "review_id", "source", "subject", "access", "user_id", "reviewer_id", "decision", "comment", "decided_by_id", "decided_at", "actioned_at", "task_id")


@router.get("")
def reviews(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [ser(x["review"], REVIEW, total=x["total"], decided=x["decided"], revoke=x["revoke"], change=x["change"]) for x in ar.reviews(db, user)]


class StartIn(In):
    title: str = Field(min_length=1, max_length=300)
    sources: list[str] = Field(min_length=1, max_length=2)
    due_date: date
    owner_id: int | None = None
    repeat_months: int | None = None


@router.post("")
def start(body: StartIn, user=Depends(perm("access_review.manage")), db: Session = Depends(get_db)):
    return ser(ar.start(db, user, body.title, body.sources, body.due_date, body.owner_id, body.repeat_months), REVIEW)


@router.get("/{rid}/export.xlsx")
def export(rid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    from keystone.core.audit import log_event
    from keystone.reporting.exports import xlsx

    from .common import xlsx_response

    headers, rows = ar.export_rows(db, user, rid)
    log_event(db, user, "export", "AccessReview", rid, f"Access review exported ({len(rows)} items)")
    return xlsx_response(xlsx({"Access review": (headers, rows)}, title="Access review"), f"access-review-{rid}.xlsx")


@router.get("/{rid}/items")
def items(rid: int, mine: bool = False, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [ser(i, ITEM) for i in ar.items(db, user, rid, mine)]


class DecideIn(In):
    decision: str = Field(pattern="^(keep|revoke|change)$")
    comment: str | None = Field(default=None, max_length=2000)


# perm("read"): only the assigned reviewer may decide, checked in the service.
@router.post("/items/{iid}/decide")
def decide(iid: int, body: DecideIn, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return ser(ar.decide(db, user, iid, body.decision, body.comment), ITEM)


@router.post("/items/{iid}/apply")
def apply(iid: int, user=Depends(perm("users.manage")), db: Session = Depends(get_db)):
    return ser(ar.apply_revocation(db, user, iid), ITEM)


@router.post("/{rid}/complete")
def complete(rid: int, user=Depends(perm("access_review.manage")), db: Session = Depends(get_db)):
    return ser(ar.complete(db, user, rid), REVIEW)
