"""Vendor self-service portal: a vendor answers one questionnaire and uploads documents through a link.

Security design (docs/feature-security-designs.md, approved):
- 256-bit token in the URL fragment, sent in the X-Vendor-Token header, stored as SHA-256 only (SC-AUTHN-007).
- A link opens exactly one questionnaire; vendors see question text and their own answers and files, never scoring
  weights, control mappings, internal notes, staff names or ids of other records.
- No expiry by default (the organisation's decision); staff can set one or revoke the link. After submission the
  questionnaire is read-only for the vendor.
- Uploads: PDF, PNG, JPEG, DOCX, XLSX only, checked by content; 10 MB each; 20 per questionnaire; Office files pass
  the archive checks; every file is scanned by ClamAV and refused if the scanner can't give a clean verdict.
- Public endpoints are rate-limited per token and per address. Every save, upload, submit and refusal is audited.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from keystone.core import antivirus
from keystone.core.attachments import Attachment, AttachmentRejected, read_attachment, safe_filename, save_attachment
from keystone.core.audit import log_event
from keystone.core.db import utcnow
from keystone.core.safe_files import check_zip
from keystone.core.services import authorize, get_or_404
from keystone.org.service import get_org
from keystone.trust.service import rate_limit

from . import service as tprm
from .models import Vendor, VendorPortalLink, VendorQuestionnaire

ENTITY = "VendorQuestionnaire"
ALLOWED = {".pdf": [b"%PDF"], ".png": [b"\x89PNG"], ".jpg": [b"\xff\xd8\xff"], ".jpeg": [b"\xff\xd8\xff"], ".docx": [b"PK\x03\x04"], ".xlsx": [b"PK\x03\x04"]}
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_FILES = 20


class LinkInvalid(LookupError):
    """Unknown, revoked or expired link. One message for all cases, so links can't be probed."""

    def __init__(self):
        super().__init__("This link is not valid. Ask your contact for a new one.")


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _fid(att: Attachment) -> str:
    """Opaque file id for the vendor (no row numbers)."""
    return hashlib.sha256(f"{att.id}:{att.sha256}".encode()).hexdigest()[:32]


# ---- staff ----------------------------------------------------------------------------------------

def create_link(session: Session, actor, questionnaire_id: int, *, contact_name: str | None = None, contact_email: str | None = None, expires_at: datetime | None = None) -> tuple[VendorPortalLink, str]:
    """A new link for the questionnaire; any earlier link for it is revoked. Returns (link, token)."""
    authorize(session, actor, "vendor.write")
    vq = get_or_404(session, VendorQuestionnaire, questionnaire_id)
    if vq.status == "reviewed":
        raise ValueError("This questionnaire has been reviewed and is locked.")
    if expires_at is not None and expires_at <= utcnow():
        raise ValueError("The expiry must be in the future.")
    for old in session.scalars(select(VendorPortalLink).where(VendorPortalLink.questionnaire_id == vq.id, VendorPortalLink.revoked_at.is_(None))):
        old.revoked_at = utcnow()
    token = secrets.token_urlsafe(32)
    link = VendorPortalLink(questionnaire_id=vq.id, token_hash=_hash(token), contact_name=(contact_name or "").strip() or None,
                            contact_email=(contact_email or "").strip() or None, expires_at=expires_at)
    session.add(link)
    session.flush()
    return link, token


def set_expiry(session: Session, actor, link_id: int, expires_at: datetime | None) -> VendorPortalLink:
    authorize(session, actor, "vendor.write")
    link = get_or_404(session, VendorPortalLink, link_id)
    if expires_at is not None and expires_at <= utcnow():
        raise ValueError("The expiry must be in the future.")
    link.expires_at = expires_at
    session.flush()
    return link


def revoke(session: Session, actor, link_id: int) -> VendorPortalLink:
    authorize(session, actor, "vendor.write")
    link = get_or_404(session, VendorPortalLink, link_id)
    link.revoked_at = link.revoked_at or utcnow()
    session.flush()
    return link


def links_for(session: Session, questionnaire_id: int) -> list[VendorPortalLink]:
    return list(session.scalars(select(VendorPortalLink).where(VendorPortalLink.questionnaire_id == questionnaire_id).order_by(VendorPortalLink.id.desc())))


def files_for(session: Session, questionnaire_id: int) -> list[Attachment]:
    return list(session.scalars(select(Attachment).where(Attachment.entity_type == ENTITY, Attachment.entity_id == questionnaire_id).order_by(Attachment.id)))


# ---- vendor (public, token in a header) -------------------------------------------------------------

def _open(session: Session, token: str | None, ip: str | None, write: bool = False) -> tuple[VendorPortalLink, VendorQuestionnaire]:
    rate_limit(f"vp-ip:{ip}", limit=600, window=3600)
    if not token or len(token) > 200:
        raise LinkInvalid()
    link = session.scalar(select(VendorPortalLink).where(VendorPortalLink.token_hash == _hash(token)))
    now = utcnow()
    if link is None or link.revoked_at or (link.expires_at and link.expires_at <= now):
        raise LinkInvalid()
    rate_limit(f"vp-link:{link.id}:{'w' if write else 'r'}", limit=300 if write else 1200, window=3600)
    vq = session.get(VendorQuestionnaire, link.questionnaire_id)
    if vq is None:
        raise LinkInvalid()
    link.last_used_at = now
    return link, vq


def _editable(vq: VendorQuestionnaire) -> bool:
    return vq.status in ("sent", "draft")


def view(session: Session, token: str | None, ip: str | None) -> dict:
    link, vq = _open(session, token, ip)
    vendor = session.get(Vendor, vq.vendor_id)
    org = get_org(session)
    questions = [{k: q.get(k) for k in ("id", "section", "text", "type", "required")} for q in vq.template.questions]
    return {
        "company": org.name if org else "",
        "vendor": vendor.name if vendor else "",
        "title": f"{vq.template.name} (v{vq.template.version})",
        "due_date": vq.due_date.isoformat() if vq.due_date else None,
        "status": "submitted" if not _editable(vq) else "open",
        "editable": _editable(vq),
        "questions": questions,
        "answer_options": {t: list(v) if v else None for t, v in tprm.QUESTION_TYPES.items()},
        "responses": vq.responses or {},
        "files": [{"id": _fid(a), "filename": a.filename, "size": a.size} for a in files_for(session, vq.id)],
        "limits": {"max_mb": MAX_FILE_BYTES // (1024 * 1024), "max_files": MAX_FILES, "types": sorted({e.lstrip(".") for e in ALLOWED})},
        "expires_at": link.expires_at.isoformat() if link.expires_at else None,
    }


def save(session: Session, token: str | None, ip: str | None, responses: dict, submit: bool = False) -> dict:
    link, vq = _open(session, token, ip, write=True)
    if not _editable(vq):
        raise ValueError("This questionnaire has been submitted and can no longer be changed.")
    tprm.apply_responses(vq, responses, complete=submit)
    log_event(session, None, "submit" if submit else "update", "VendorQuestionnaire", vq.id, f"{'Submitted' if submit else 'Saved'} by the vendor through portal link VPL-{link.id}")
    session.flush()
    return view(session, token, ip)


def upload(session: Session, token: str | None, ip: str | None, filename: str, data: bytes) -> dict:
    link, vq = _open(session, token, ip, write=True)
    rate_limit(f"vp-upload:{link.id}", limit=60, window=3600)
    if not _editable(vq):
        raise ValueError("This questionnaire has been submitted and can no longer be changed.")
    name = safe_filename(filename or "file")
    ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED:
        raise AttachmentRejected("Upload PDF, PNG, JPG, DOCX or XLSX files.")
    if not data:
        raise AttachmentRejected("File is empty.")
    if len(data) > MAX_FILE_BYTES:
        raise AttachmentRejected(f"Files can be at most {MAX_FILE_BYTES // (1024 * 1024)} MB.")
    if not any(data.startswith(m) for m in ALLOWED[ext]):
        raise AttachmentRejected(f"The file's content doesn't match its {ext} extension.")
    if ext in (".docx", ".xlsx"):
        check_zip(data)
    count = session.scalar(select(func.count(Attachment.id)).where(Attachment.entity_type == ENTITY, Attachment.entity_id == vq.id)) or 0
    if count >= MAX_FILES:
        raise AttachmentRejected(f"At most {MAX_FILES} files per questionnaire.")
    try:
        antivirus.scan(data)
    except antivirus.Infected as e:
        log_event(session, None, "upload_blocked", "VendorQuestionnaire", vq.id, f"Vendor upload refused by the virus scanner (portal link VPL-{link.id}): {e.signature}")
        session.commit()  # keep the audit entry although the request fails
        raise AttachmentRejected("The file was rejected by the virus scanner.") from None
    att = save_attachment(session, None, name, data, ENTITY, vq.id, external_channel=f"vendor portal link VPL-{link.id}")
    log_event(session, None, "upload", "VendorQuestionnaire", vq.id, f"Vendor uploaded a file through portal link VPL-{link.id} (attachment {att.id}, {att.size} bytes)")
    session.flush()
    return view(session, token, ip)


def delete_file(session: Session, token: str | None, ip: str | None, file_id: str) -> dict:
    link, vq = _open(session, token, ip, write=True)
    if not _editable(vq):
        raise ValueError("This questionnaire has been submitted and can no longer be changed.")
    att = next((a for a in files_for(session, vq.id) if _fid(a) == file_id), None)
    if att is None:
        raise LookupError("File not found")
    att.entity_type, att.entity_id = "VendorQuestionnaireRemoved", vq.id  # kept for the record; no longer listed
    log_event(session, None, "update", "VendorQuestionnaire", vq.id, f"Vendor removed attachment {att.id} through portal link VPL-{link.id}")
    session.flush()
    return view(session, token, ip)


def download_own(session: Session, token: str | None, ip: str | None, file_id: str) -> tuple[Attachment, bytes]:
    _link, vq = _open(session, token, ip)
    att = next((a for a in files_for(session, vq.id) if _fid(a) == file_id), None)
    if att is None:
        raise LookupError("File not found")
    return att, read_attachment(att)
