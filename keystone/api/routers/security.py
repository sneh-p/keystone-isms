"""Reports of suspicious activity, the leaver access check, and the exceptions register."""

from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.access_reviews import reconcile
from keystone.incidents import reports as rep
from keystone.incidents.models import REPORT_KINDS
from keystone.reporting.exceptions import all_exceptions

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(tags=["security"])
OWN = ("id", "kind", "description", "sender", "subject", "where", "clicked", "status", "outcome", "reply", "created_at", "triaged_at")
FULL = OWN + ("reporter_id", "triaged_by_id", "incident_id")


# ---- reporting from the portal (every role holds "portal"; the service filters to the caller's own reports) -------------

@router.get("/portal/reports")
def my_reports(user=Depends(perm("portal")), db: Session = Depends(get_db)):
    return {"kinds": REPORT_KINDS, "outcomes": rep.OUTCOMES, "reports": [ser(r, OWN, ref=r.ref) for r in rep.mine(db, user)]}


class ReportIn(In):
    kind: str = Field(max_length=20)
    description: str = Field(min_length=1, max_length=8000)
    sender: str | None = Field(None, max_length=320)
    subject: str | None = Field(None, max_length=300)
    where: str | None = Field(None, max_length=300)
    clicked: bool | None = None


@router.post("/portal/reports")
def submit_report(body: ReportIn, user=Depends(perm("portal")), db: Session = Depends(get_db)):
    r = rep.submit(db, user, **body.model_dump())
    return ser(r, OWN, ref=r.ref)


# ---- triage (incident handlers) ----------------------------------------------------------------------------------

@router.get("/security-reports")
def reports(include_closed: bool = True, user=Depends(perm("incident.write")), db: Session = Depends(get_db)):
    from keystone.core.auth import User

    names: dict[int | None, str] = {u.id: u.display_name for u in db.query(User).all()}
    return {"kinds": REPORT_KINDS, "outcomes": rep.OUTCOMES,
            "reports": [ser(r, FULL, ref=r.ref, reporter=names.get(r.reporter_id), triaged_by=names.get(r.triaged_by_id)) for r in rep.reports(db, user, include_closed)]}


class ToIncidentIn(In):
    severity: Literal["low", "medium", "high", "critical"]
    reply: str | None = Field(None, max_length=2000)


@router.post("/security-reports/{rid}/incident")
def report_to_incident(rid: int, body: ToIncidentIn, user=Depends(perm("incident.write")), db: Session = Depends(get_db)):
    i = rep.to_incident(db, user, rid, severity=body.severity, reply=body.reply)
    return {"incident_id": i.id, "ref": i.ref}


class CloseIn(In):
    outcome: Literal["phishing_blocked", "not_a_threat", "duplicate"]
    reply: str = Field(min_length=1, max_length=2000)


@router.post("/security-reports/{rid}/close")
def close_report(rid: int, body: CloseIn, user=Depends(perm("incident.write")), db: Session = Depends(get_db)):
    r = rep.close(db, user, rid, outcome=body.outcome, reply=body.reply)
    return ser(r, FULL, ref=r.ref)


# ---- leaver access check (access_review.manage) -----------------------------------------------------------------

@router.get("/access-check")
def access_check(user=Depends(perm("access_review.manage")), db: Session = Depends(get_db)):
    return reconcile.findings(db, user)


class ExemptIn(In):
    account: str = Field(min_length=3, max_length=400)
    note: str = Field(min_length=1, max_length=2000)


@router.post("/access-check/exemptions")
def exempt_account(body: ExemptIn, user=Depends(perm("access_review.manage")), db: Session = Depends(get_db)):
    x = reconcile.exempt(db, user, body.account, body.note)
    return {"id": x.id, "account": x.account}


@router.delete("/access-check/exemptions/{xid}")
def remove_exemption(xid: int, user=Depends(perm("access_review.manage")), db: Session = Depends(get_db)):
    reconcile.remove_exemption(db, user, xid)
    return {"ok": True}


# ---- exceptions register -------------------------------------------------------------------------------------------

@router.get("/exceptions")
def exceptions(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return all_exceptions(db, user)
