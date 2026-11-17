"""Comments and @mentions, saved views, guided tours, workload."""

from datetime import date
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.collab import service as col

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(tags=["collaboration"])
COMMENT = ("id", "body", "created_by_id", "created_at")


@router.get("/comments/{kind}/{rid}")
def comments(kind: str, rid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [ser(c, COMMENT) for c in col.comments_for(db, user, kind, rid)]


class CommentIn(In):
    body: str = Field(max_length=5000)


# Any staff member who can read the record may comment (decision 2026-11-16); employees lack "read".
@router.post("/comments/{kind}/{rid}")
def add_comment(kind: str, rid: int, body: CommentIn, user=Depends(perm("read")), db: Session = Depends(get_db)):
    c, notified = col.add_comment(db, user, kind, rid, body.body)
    return {**ser(c, COMMENT), "notified": [u.display_name for u in notified]}


@router.get("/history/{kind}/{rid}")
def history(kind: str, rid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return col.history(db, user, kind, rid)


@router.get("/mentionable")
def mentionable(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return col.mentionable(db, user)


@router.get("/views/{page}")
def views(page: str, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [ser(v, ("id", "name", "query")) for v in col.views(db, user, page)]


class ViewIn(In):
    name: str = Field(max_length=80)
    query: str = Field(max_length=1000)


@router.post("/views/{page}")
def save_view(page: str, body: ViewIn, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return ser(col.save_view(db, user, page, body.name, body.query), ("id", "name", "query"))


@router.delete("/views/{page}/{vid}")
def delete_view(page: str, vid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    col.delete_view(db, user, vid)
    return {"ok": True}


# Guided tours: every role holds "portal" (employees included); the service reads and writes only the caller's own row.
@router.get("/portal/tours")
def tours(user=Depends(perm("portal")), db: Session = Depends(get_db)):
    return col.tours(db, user)


class TourIn(In):
    outcome: Literal["completed", "skipped"] | None


@router.put("/portal/tours/{tour}")
def set_tour(tour: Literal["app", "portal"], body: TourIn, user=Depends(perm("portal")), db: Session = Depends(get_db)):
    return col.set_tour(db, user, tour, body.outcome)


@router.get("/workload")
def workload(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return col.workload(db, user)


# ---- risk library, calendar, board report ---------------------------------------------------------------

@router.get("/risk-library")
def risk_library(user=Depends(perm("read"))):
    from keystone.risk import service as risk

    return risk.library()


class LibraryIn(In):
    key: str = Field(max_length=60)
    owner_id: int | None = None


@router.post("/risks/from-library")
def risk_from_library(body: LibraryIn, user=Depends(perm("risk.write")), db: Session = Depends(get_db)):
    from keystone.core.services import require_active_user
    from keystone.risk import service as risk

    require_active_user(db, body.owner_id)
    r = risk.add_from_library(db, user, body.key, body.owner_id)
    return {"id": r.id, "ref": r.ref}


@router.get("/calendar")
def calendar(start: date, end: date, user=Depends(perm("read")), db: Session = Depends(get_db)):
    from keystone.reporting import calendar as cal

    return cal.events(db, user, start, end)


@router.get("/reports/board.docx")
def board_report(user=Depends(perm("read")), db: Session = Depends(get_db)):
    from keystone.reporting import board

    from .common import docx_response

    return docx_response(board.report_docx(db, user), f"Board_summary_{date.today().isoformat()}.docx")


@router.get("/reports/board.pdf")
def board_report_pdf(user=Depends(perm("read")), db: Session = Depends(get_db)):
    from fastapi.responses import Response

    from keystone.reporting import board

    return Response(board.report_pdf(db, user), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="Board_summary_{date.today().isoformat()}.pdf"', "Cache-Control": "no-store"})


@router.get("/search")
def search(q: str = Query("", max_length=100), user=Depends(perm("read")), db: Session = Depends(get_db)):
    """Records whose reference or title contains the query, for the command palette."""
    from keystone.reporting.search import search as find

    return find(db, user, q)
