"""Phishing simulations, look-alike domains, supplier breach news, on-call alerting and DMARC reports."""

from datetime import date

from fastapi import APIRouter, Depends, File, Request, UploadFile
from fastapi.responses import JSONResponse
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.dmarc import service as dm
from keystone.oncall import service as oc
from keystone.phishing import service as ph
from keystone.threatintel import service as ti
from keystone.trust.service import rate_limit

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(tags=["security outreach"])
CAMPAIGN = ("id", "name", "template", "audience", "status", "created_by_id", "launched_by_id", "launched_at", "completed_at", "created_at")


# ---- phishing simulations (people.write; the landing page is public, by its one-off token) ---------------------------

@router.get("/phishing")
def phishing(user=Depends(perm("people.write")), db: Session = Depends(get_db)):
    tpl = {k: {"title": t["title"], "difficulty": t["difficulty"], "from_name": t["from_name"], "subject": t["subject"], "body": t["body"], "red_flags": t["red_flags"]}
           for k, t in ph.templates().items()}
    return {"templates": tpl, "campaigns": [ser(c, CAMPAIGN, ref=c.ref, results=ph.results(db, user, c.id)) for c in ph.campaigns(db, user)]}


class CampaignIn(In):
    name: str = Field(min_length=1, max_length=200)
    template: str = Field(max_length=60)
    audience: dict | None = None


@router.post("/phishing")
def create_campaign(body: CampaignIn, user=Depends(perm("people.write")), db: Session = Depends(get_db)):
    return ser(ph.create(db, user, name=body.name, template=body.template, audience=body.audience), CAMPAIGN)


@router.post("/phishing/{cid}/launch")
def launch_campaign(cid: int, user=Depends(perm("people.write")), db: Session = Depends(get_db)):
    return ser(ph.launch(db, user, cid), CAMPAIGN)


@router.post("/phishing/{cid}/complete")
def complete_campaign(cid: int, user=Depends(perm("people.write")), db: Session = Depends(get_db)):
    return ser(ph.complete(db, user, cid), CAMPAIGN)


class ClickIn(In):
    token: str = Field(min_length=10, max_length=100)


@router.post("/public/phish")
def phish_landing(body: ClickIn, request: Request, db: Session = Depends(get_db)):
    """The practice email's link: records the click and explains the warning signs. Never asks for anything."""
    try:
        rate_limit(f"phish:{request.client.host if request.client else '?'}", limit=60, window=3600)
    except PermissionError:
        return JSONResponse({"detail": "Too many requests."}, status_code=429)
    return ph.click(db, body.token)


# ---- look-alike domains and supplier breach news --------------------------------------------------------------------

LOOK = ("id", "domain_id", "name", "reason", "first_seen", "last_seen", "status", "note", "decided_by_id")
BREACH = ("id", "vendor_id", "breach", "title", "domain", "breach_date", "added_on", "accounts", "data_classes", "status", "note", "decided_by_id")


@router.get("/lookalikes")
def lookalikes(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return {"lookalikes": [ser(x, LOOK) for x in ti.lookalikes(db, user)], "statuses": ti.LOOKALIKE_STATUSES}


class DecideIn(In):
    status: str = Field(max_length=20)
    note: str | None = Field(None, max_length=2000)


@router.post("/lookalikes/{lid}/decide")
def decide_lookalike(lid: int, body: DecideIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return ser(ti.decide_lookalike(db, user, lid, body.status, body.note), LOOK)


@router.post("/lookalikes/scan")
def scan_lookalikes(user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    from keystone.core.services import authorize

    authorize(db, user, "integration.manage")
    return {"new": ti.scan_lookalikes(db)}


@router.get("/vendor-breaches")
def vendor_breaches(user=Depends(perm("read")), db: Session = Depends(get_db)):
    from keystone.tprm.models import Vendor

    names = {v.id: v.name for v in db.query(Vendor).all()}
    return {"breaches": [ser(b, BREACH, vendor=names.get(b.vendor_id)) for b in ti.breaches(db, user)], "statuses": ti.BREACH_STATUSES}


@router.post("/vendor-breaches/{bid}/decide")
def decide_breach(bid: int, body: DecideIn, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    return ser(ti.decide_breach(db, user, bid, body.status, body.note or ""), BREACH)


@router.post("/vendor-breaches/scan")
def scan_breaches(user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    from keystone.core.services import authorize

    authorize(db, user, "vendor.write")
    return {"new": ti.scan_breaches(db)}


# ---- on-call ------------------------------------------------------------------------------------------------------

ROTA = ("id", "name", "member_ids", "start_on", "rotation_days", "escalate_after_minutes", "active")
PAGE = ("id", "rota_id", "user_id", "level", "title", "page", "source", "created_at", "emailed", "acked_at", "escalated_at")


@router.get("/oncall")
def oncall(user=Depends(perm("read")), db: Session = Depends(get_db)):
    from keystone.core.rbac import has_permission

    rotas = oc.rotas(db, user)
    out = {"rotas": [ser(r, ROTA, on_call=oc.on_call(r), next=oc.on_call(r, offset=1)) for r in rotas]}
    if has_permission(user, "incident.write"):
        out["pages"] = [ser(p, PAGE) for p in oc.pages(db, user)]
    return out


class RotaIn(In):
    name: str = Field(min_length=1, max_length=100)
    member_ids: list[int] = Field(min_length=1, max_length=30)
    start_on: date
    rotation_days: int = Field(ge=1, le=31)
    escalate_after_minutes: int = Field(ge=5, le=240)
    active: bool = True


@router.post("/oncall")
def create_rota(body: RotaIn, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    return ser(oc.save(db, user, **body.model_dump()), ROTA)


@router.put("/oncall/{rid}")
def update_rota(rid: int, body: RotaIn, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    return ser(oc.save(db, user, rid, **body.model_dump()), ROTA)


@router.post("/oncall/pages/{pid}/ack")
def ack_page(pid: int, user=Depends(perm("incident.write")), db: Session = Depends(get_db)):
    return ser(oc.acknowledge(db, user, pid), PAGE)


# ---- DMARC reports --------------------------------------------------------------------------------------------------

@router.get("/dmarc")
def dmarc(days: int = 90, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return dm.summary(db, user, max(1, min(days, 400)))


@router.post("/dmarc")
async def upload_dmarc(file: UploadFile = File(...), user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    data = await file.read(dm.MAX_UPLOAD + 1)
    if len(data) > dm.MAX_UPLOAD:
        raise ValueError("Upload reports of at most 10 MB.")
    return dm.upload(db, user, file.filename or "report.xml", data)


