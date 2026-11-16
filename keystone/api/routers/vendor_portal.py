"""Vendor self-service portal: staff manage links; vendors use public endpoints with the X-Vendor-Token header."""

from datetime import datetime

from fastapi import APIRouter, Depends, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import Response
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.core import antivirus
from keystone.core.services import get_or_404
from keystone.tprm import portal
from keystone.tprm.models import VendorQuestionnaire

from ..deps import get_db, perm
from ..serialize import ser
from .admin import _naive_utc
from .common import In, public_link
from .trust import _ip

router = APIRouter(tags=["vendor-portal"])
VENDOR_HEADER = "X-Vendor-Token"
LINK = ("id", "contact_name", "contact_email", "expires_at", "revoked_at", "last_used_at", "created_at", "created_by_id")


# ---- staff -----------------------------------------------------------------------------------------

@router.get("/questionnaires/{qid}/portal")
def portal_status(qid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    get_or_404(db, VendorQuestionnaire, qid)
    return {"links": [ser(link, LINK) for link in portal.links_for(db, qid)],
            "files": [ser(a, ("id", "filename", "size", "created_at")) for a in portal.files_for(db, qid)],
            "scanner_ok": antivirus.ping()}


class LinkIn(In):
    contact_name: str | None = Field(default=None, max_length=200)
    contact_email: str | None = Field(default=None, max_length=320)
    expires_at: datetime | None = None  # none = never expires (default)


@router.post("/questionnaires/{qid}/portal-link")
def create_link(qid: int, body: LinkIn, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    link, token = portal.create_link(db, user, qid, contact_name=body.contact_name, contact_email=body.contact_email, expires_at=_naive_utc(body.expires_at))
    # SC-AUTHN-007: the token travels after "#", so it never reaches server logs; shown once, stored as a hash.
    return {**ser(link, LINK), **public_link(f"/vendor-portal#token={token}")}


class ExpiryIn(In):
    expires_at: datetime | None = None


@router.patch("/portal-links/{lid}")
def set_expiry(lid: int, body: ExpiryIn, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    return ser(portal.set_expiry(db, user, lid, _naive_utc(body.expires_at)), LINK)


@router.post("/portal-links/{lid}/revoke")
def revoke(lid: int, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    return ser(portal.revoke(db, user, lid), LINK)


# ---- vendor (public) ---------------------------------------------------------------------------------

def _guard(fn):
    try:
        return fn()
    except PermissionError as e:  # rate limit
        raise HTTPException(429, str(e)) from None
    except antivirus.ScannerUnavailable:
        raise HTTPException(503, "Uploads are paused because virus scanning is unavailable. Please try again later.") from None


@router.get("/public/vendor-portal")
def public_view(request: Request, token: str | None = Header(None, alias=VENDOR_HEADER), db: Session = Depends(get_db)):
    return _guard(lambda: portal.view(db, token, _ip(request)))


class AnswersIn(In):
    responses: dict[str, dict[str, str | None] | None] = Field(max_length=500)
    submit: bool = False


@router.put("/public/vendor-portal")
def public_save(body: AnswersIn, request: Request, token: str | None = Header(None, alias=VENDOR_HEADER), db: Session = Depends(get_db)):
    return _guard(lambda: portal.save(db, token, _ip(request), body.responses, body.submit))


@router.post("/public/vendor-portal/files")
async def public_upload(request: Request, file: UploadFile = File(...), token: str | None = Header(None, alias=VENDOR_HEADER), db: Session = Depends(get_db)):
    data = await file.read(portal.MAX_FILE_BYTES + 1)  # never read more than the limit allows
    return _guard(lambda: portal.upload(db, token, _ip(request), file.filename or "file", data))


@router.delete("/public/vendor-portal/files/{file_id}")
def public_delete(file_id: str, request: Request, token: str | None = Header(None, alias=VENDOR_HEADER), db: Session = Depends(get_db)):
    return _guard(lambda: portal.delete_file(db, token, _ip(request), file_id))


@router.get("/public/vendor-portal/files/{file_id}")
def public_download(file_id: str, request: Request, token: str | None = Header(None, alias=VENDOR_HEADER), db: Session = Depends(get_db)):
    att, data = _guard(lambda: portal.download_own(db, token, _ip(request), file_id))
    safe = att.filename.replace('"', "")
    return Response(data, media_type=att.content_type, headers={"Content-Disposition": f'attachment; filename="{safe}"', "X-Content-Type-Options": "nosniff"})
