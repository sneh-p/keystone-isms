"""Trust Center: staff management and public endpoints."""

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import Response
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.trust import service as trust
from keystone.trust.models import AccessRequest, TrustDocument, TrustFaq, TrustSubprocessor

from ..deps import get_db, perm
from ..serialize import ser
from .common import In, public_link

router = APIRouter(tags=["trust center"])
SET = ("published", "slug", "headline", "overview", "contact_email", "brand_color", "show_frameworks", "framework_status", "show_controls", "show_policies", "show_subprocessors", "nda_required", "nda_text", "nda_version", "access_days")


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.get("/trust-center")
def manage(user=Depends(perm("read")), db: Session = Depends(get_db)):
    s = trust.settings(db)
    return {
        "settings": ser(s, SET),
        "documents": [ser(d, ("id", "public_id", "title", "description", "kind", "access", "published", "attachment_id")) for d in db.scalars(select(TrustDocument).order_by(TrustDocument.title))],
        "faqs": [ser(f, ("id", "question", "answer", "sort_order")) for f in db.scalars(select(TrustFaq).order_by(TrustFaq.sort_order, TrustFaq.id))],
        "subprocessors": [ser(sp, ("vendor_id", "purpose", "location")) for sp in db.scalars(select(TrustSubprocessor))],
        "requests": [ser(r, ("id", "name", "email", "company", "reason", "status", "decided_by_id", "decided_at", "expires_at", "nda_accepted_at", "nda_version", "nda_signed_name", "view_count", "last_viewed_at", "created_at")) for r in trust.access_requests(db)],
        "passing_controls": trust.passing_controls(db),
    }


class SettingsIn(In):
    published: bool | None = None
    slug: str | None = None
    headline: str | None = None
    overview: str | None = Field(None, max_length=50_000)
    contact_email: str | None = None
    brand_color: str | None = None
    show_frameworks: bool | None = None
    framework_status: dict[str, str] | None = Field(default=None, max_length=50)
    show_controls: bool | None = None
    show_policies: bool | None = None
    show_subprocessors: bool | None = None
    nda_required: bool | None = None
    nda_text: str | None = Field(None, max_length=100_000)
    access_days: int | None = None


@router.patch("/trust-center/settings")
def update(body: SettingsIn, user=Depends(perm("trust.manage")), db: Session = Depends(get_db)):
    return ser(trust.update_settings(db, user, **body.model_dump(exclude_unset=True)), SET)


@router.post("/trust-center/documents")
async def add_doc(title: str = Form(..., max_length=200), kind: str = Form("report", max_length=20), access: str = Form("nda", max_length=10), description: str | None = Form(None, max_length=20_000), file: UploadFile = File(...), user=Depends(perm("trust.manage")), db: Session = Depends(get_db)):
    d = trust.add_document(db, user, title=title, kind=kind, access=access, filename=file.filename or "document", data=await file.read(), description=description)
    return ser(d, ("id", "public_id", "title", "access"))


class DocIn(In):
    title: str | None = None
    description: str | None = None
    access: str | None = None
    published: bool | None = None
    kind: str | None = None


@router.patch("/trust-center/documents/{did}")
def edit_doc(did: int, body: DocIn, user=Depends(perm("trust.manage")), db: Session = Depends(get_db)):
    return ser(trust.update_document(db, user, did, **body.model_dump(exclude_unset=True)), ("id", "title", "access", "published"))


class FaqIn(In):
    question: str | None = None
    answer: str | None = None
    sort_order: int | None = None


@router.post("/trust-center/faqs")
def add_faq(body: FaqIn, user=Depends(perm("trust.manage")), db: Session = Depends(get_db)):
    return ser(trust.save_faq(db, user, **body.model_dump(exclude_unset=True)), ("id", "question"))


@router.delete("/trust-center/faqs/{fid}")
def del_faq(fid: int, user=Depends(perm("trust.manage")), db: Session = Depends(get_db)):
    trust.delete_faq(db, user, fid)
    return {"ok": True}


class SubIn(In):
    purpose: str | None = None
    location: str | None = None


@router.put("/trust-center/subprocessors/{vendor_id}")
def subprocessor(vendor_id: int, body: SubIn, user=Depends(perm("trust.manage")), db: Session = Depends(get_db)):
    trust.set_subprocessor(db, user, vendor_id, body.purpose, body.location)
    return {"ok": True}


class ApproveIn(In):
    days: int | None = Field(None, ge=1, le=365)  # same bounds as the default in the settings (SC-VAL-002)
    send_email: bool = False  # email the link to the requester


@router.post("/trust-center/requests/{rid}/approve")
def approve(rid: int, body: ApproveIn, user=Depends(perm("trust.manage")), db: Session = Depends(get_db)):
    token = trust.approve(db, user, rid, body.days)
    st = trust.settings(db)
    # SC-CRY-005: the token travels in the URL fragment, never in a path or query the server would log.
    out = {**public_link(f"/trust/{st.slug}#access={token}"), "emailed_to": None}
    if body.send_email:
        from keystone.notifications import service as ntf

        r = db.get(AccessRequest, rid)
        exp = r.expires_at.strftime("%d %b %Y") if r and r.expires_at else ""
        out["emailed_to"] = ntf.email_link(db, user, to=r.email if r else None, subject=f"Your access to {st.headline or 'our Trust Center'}",
                                           intro=f"Hello {r.name if r else ''},\n\nYour request for access to our security documents has been approved. Open this link to view and download them:",
                                           path=f"/trust/{st.slug}#access={token}", closing=f"The link is personal to you and works until {exp}. Please don't forward it.", entity=("AccessRequest", rid))
    return out


@router.post("/trust-center/requests/{rid}/deny")
def deny(rid: int, user=Depends(perm("trust.manage")), db: Session = Depends(get_db)):
    trust.deny(db, user, rid)
    return {"ok": True}


@router.post("/trust-center/requests/{rid}/revoke")
def revoke(rid: int, user=Depends(perm("trust.manage")), db: Session = Depends(get_db)):
    trust.revoke(db, user, rid)
    return {"ok": True}


# ---- public ----------------------------------------------------------------------------------

@router.get("/public/trust/{slug}")
def public_page(slug: str, db: Session = Depends(get_db)):
    return trust.public_view(db, slug)


class RequestIn(In):
    name: str
    email: str
    company: str
    reason: str | None = None
    website: str | None = None  # honeypot: must stay empty


@router.post("/public/trust/{slug}/requests")
def public_request(slug: str, body: RequestIn, request: Request, db: Session = Depends(get_db)):
    if body.website:
        return {"ok": True}  # bot: pretend success, store nothing
    try:
        trust.request_access(db, slug, name=body.name, email=body.email, company=body.company, reason=body.reason, ip=_ip(request))
    except PermissionError as e:
        raise HTTPException(429, str(e)) from None
    return {"ok": True}


ACCESS_HEADER = "X-Trust-Access"


@router.get("/public/trust/{slug}/access")
def public_grant(slug: str, token: str | None = Header(None, alias=ACCESS_HEADER), db: Session = Depends(get_db)):
    s = trust.published_settings(db, slug)
    r = trust.grant_for(db, slug, token)
    return {"name": r.name, "company": r.company, "expires_at": r.expires_at, "nda_required": s.nda_required, "nda_ok": trust.nda_ok(s, r), "nda_text": s.nda_text if s.nda_required else None, "nda_version": s.nda_version}


class NdaIn(In):
    signed_name: str


@router.post("/public/trust/{slug}/access/nda")
def public_nda(slug: str, body: NdaIn, request: Request, token: str | None = Header(None, alias=ACCESS_HEADER), db: Session = Depends(get_db)):
    trust.accept_nda(db, slug, token, body.signed_name, _ip(request))
    return {"ok": True}


@router.get("/public/trust/{slug}/documents/{public_id}")
def public_download(slug: str, public_id: str, token: str | None = Header(None, alias=ACCESS_HEADER), db: Session = Depends(get_db)):
    try:
        att, data = trust.download(db, slug, public_id, token)
    except PermissionError as e:
        raise HTTPException(403, str(e)) from None
    safe = att.filename.replace('"', "")
    return Response(data, media_type=att.content_type, headers={"Content-Disposition": f'attachment; filename="{safe}"', "Cache-Control": "no-store"})


# ---- deleting records created in error (keystone/core/deletion.py: refused while anything depends on them)


@router.delete("/trust-center/documents/{did}")
def delete_trust_document(did: int, user=Depends(perm("trust.manage")), db: Session = Depends(get_db)):
    from keystone.core.deletion import delete_record

    delete_record(db, user, "trust_document", did)
    return {"ok": True}
