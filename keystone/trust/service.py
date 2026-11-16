"""Trust Center: what the public sees, and gated document access with NDA click-through."""

from __future__ import annotations

import hashlib
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.attachments import Attachment, read_attachment, save_attachment
from keystone.core.audit import log_event
from keystone.core.db import utcnow
from keystone.core.services import apply_fields, authorize, get_or_404, require_text
from keystone.frameworks import service as fw
from keystone.frameworks.models import CommonControl
from keystone.org.service import get_org
from keystone.policies import service as pol
from keystone.tasks.service import control_readiness
from keystone.tprm.models import Vendor

from .models import AccessRequest, TrustDocument, TrustFaq, TrustSettings, TrustSubprocessor

SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,58}[a-z0-9])$")
COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DEFAULT_NDA = (
    "## Confidentiality\n\nBy continuing you agree, on behalf of yourself and the company you represent, to keep the "
    "documents shared through this Trust Center confidential, to use them only to evaluate our security practices, "
    "and not to share them with anyone outside your organisation without our written permission. This obligation "
    "lasts for three years from today."
)


class TrustUnavailable(LookupError):
    pass


# ---- settings & content (staff) ---------------------------------------------------------------

def settings(session: Session) -> TrustSettings:
    s = session.scalar(select(TrustSettings))
    if s is None:
        o = get_org(session)
        base = re.sub(r"[^a-z0-9]+", "-", (o.name if o else "trust").lower()).strip("-")[:40] or "trust"
        s = TrustSettings(slug=base if len(base) >= 3 else f"{base}-trust", headline=f"{o.name if o else 'Our'} Trust Center", nda_text=DEFAULT_NDA)
        session.add(s)
        session.flush()
    return s


FRAMEWORK_STATUSES = ("aligned", "certified", "hidden")
SETTINGS_FIELDS = {"published", "slug", "headline", "overview", "contact_email", "brand_color", "show_frameworks", "framework_status", "show_controls", "show_policies", "show_subprocessors", "nda_required", "nda_text", "access_days"}


def update_settings(session: Session, actor, **fields) -> TrustSettings:
    authorize(session, actor, "trust.manage")
    s = settings(session)
    unknown = set(fields) - SETTINGS_FIELDS
    if unknown:
        raise ValueError(f"fields not editable here: {', '.join(sorted(unknown))}")
    if "slug" in fields:
        fields["slug"] = (fields["slug"] or "").strip().lower()
    merged = {k: getattr(s, k) for k in SETTINGS_FIELDS} | fields
    # Validate before touching the record, so a rejected change leaves it unchanged.
    if not SLUG.match(merged["slug"] or ""):
        raise ValueError("Slug must be 3-60 characters: lowercase letters, digits and hyphens.")
    if not COLOR.match(merged["brand_color"] or ""):
        raise ValueError("Brand colour must be a hex value like #4f46e5.")
    if merged["contact_email"] and not EMAIL.match(merged["contact_email"]):
        raise ValueError("Enter a valid contact email.")
    if not 1 <= int(merged["access_days"]) <= 365:
        raise ValueError("Access must last 1-365 days.")
    if "framework_status" in fields:
        codes = {f.code for f in fw.frameworks(session, enabled_only=False)}
        st = fields["framework_status"] or {}
        if not isinstance(st, dict) or set(st) - codes or set(st.values()) - set(FRAMEWORK_STATUSES):
            raise ValueError(f"Framework status must map known frameworks to one of {', '.join(FRAMEWORK_STATUSES)}.")
        fields["framework_status"] = {k: v for k, v in st.items() if v != "aligned"}  # aligned is the default
    nda_changed = "nda_text" in fields and fields["nda_text"] != s.nda_text
    apply_fields(s, fields, SETTINGS_FIELDS)
    if nda_changed:
        s.nda_version += 1  # earlier acceptances no longer cover the new text
    session.flush()
    return s


def add_document(session: Session, actor, *, title: str, kind: str, access: str, filename: str, data: bytes, description: str | None = None) -> TrustDocument:
    authorize(session, actor, "trust.manage")
    if kind not in ("report", "certificate", "policy", "other") or access not in ("public", "nda"):
        raise ValueError("Invalid document kind or access level.")
    att = save_attachment(session, actor, filename, data, "TrustDocument", None)
    d = TrustDocument(public_id=secrets.token_hex(16), title=require_text(title, "Title"), description=description, kind=kind, access=access, attachment_id=att.id, published=True)
    session.add(d)
    session.flush()
    return d


def update_document(session: Session, actor, doc_id: int, **fields) -> TrustDocument:
    authorize(session, actor, "trust.manage")
    d = get_or_404(session, TrustDocument, doc_id)
    apply_fields(d, fields, {"title", "description", "access", "published", "kind"})
    session.flush()
    return d


def save_faq(session: Session, actor, faq_id: int | None = None, **fields) -> TrustFaq:
    authorize(session, actor, "trust.manage")
    f = get_or_404(session, TrustFaq, faq_id) if faq_id else TrustFaq()
    apply_fields(f, fields, {"question", "answer", "sort_order"})
    require_text(f.question, "Question")
    require_text(f.answer, "Answer")
    session.add(f)
    session.flush()
    return f


def delete_faq(session: Session, actor, faq_id: int) -> None:
    authorize(session, actor, "trust.manage")
    session.delete(get_or_404(session, TrustFaq, faq_id))


def set_subprocessor(session: Session, actor, vendor_id: int, purpose: str | None, location: str | None = None) -> TrustSubprocessor | None:
    """Publish a vendor as a subprocessor (purpose given) or unpublish it (purpose empty)."""
    authorize(session, actor, "trust.manage")
    get_or_404(session, Vendor, vendor_id)
    sp = session.scalar(select(TrustSubprocessor).where(TrustSubprocessor.vendor_id == vendor_id))
    if not (purpose or "").strip():
        if sp:
            session.delete(sp)
        return None
    sp = sp or TrustSubprocessor(vendor_id=vendor_id)
    sp.purpose, sp.location = purpose.strip(), (location or "").strip() or None
    session.add(sp)
    session.flush()
    return sp


# ---- public view ----------------------------------------------------------------------------------

def published_settings(session: Session, slug: str) -> TrustSettings:
    s = session.scalar(select(TrustSettings).where(TrustSettings.slug == slug.lower()))
    if s is None or not s.published:
        raise TrustUnavailable("This Trust Center is not available.")
    return s


def passing_controls(session: Session) -> dict[str, list[str]]:
    """Controls that are implemented and audit-ready, by domain. Anything failing or unknown is left out."""
    out: dict[str, list[str]] = {}
    for c in session.scalars(select(CommonControl).where(CommonControl.status == "implemented").order_by(CommonControl.code)):
        if control_readiness(session, c).status == "ready":
            out.setdefault(c.domain, []).append(c.title)
    return out


def public_view(session: Session, slug: str) -> dict:
    s = published_settings(session, slug)
    o = get_org(session)
    view: dict = {"company": o.name if o else "", "headline": s.headline, "overview": s.overview, "contact_email": s.contact_email, "brand_color": s.brand_color, "nda_required": s.nda_required, "updated_at": utcnow().date().isoformat()}
    if s.show_frameworks:
        status = s.framework_status or {}
        view["frameworks"] = [{"name": f"{f.name} {f.version}", "code": f.code, "status": status.get(f.code, "aligned")} for f in fw.frameworks(session) if status.get(f.code) != "hidden"]
    if s.show_controls:
        view["controls"] = passing_controls(session)
    if s.show_policies:
        view["policies"] = [{"code": d.code, "title": d.title, "approved": pol.current_version(session, d).approved_at.date().isoformat() if pol.current_version(session, d) else None} for d in pol.documents(session) if d.status == "approved"]
    if s.show_subprocessors:
        view["subprocessors"] = [{"name": v.name, "purpose": sp.purpose, "location": sp.location} for sp, v in session.execute(select(TrustSubprocessor, Vendor).join(Vendor, Vendor.id == TrustSubprocessor.vendor_id).where(Vendor.status == "active").order_by(Vendor.name))]
    view["documents"] = [{"id": d.public_id, "title": d.title, "description": d.description, "kind": d.kind, "access": d.access} for d in session.scalars(select(TrustDocument).where(TrustDocument.published.is_(True)).order_by(TrustDocument.title))]
    view["faqs"] = [{"question": f.question, "answer": f.answer} for f in session.scalars(select(TrustFaq).order_by(TrustFaq.sort_order, TrustFaq.id))]
    return view


# ---- rate limiting for public writes ---------------------------------------------------------------

_hits: dict[str, deque] = defaultdict(deque)


def rate_limit(key: str, limit: int = 5, window: int = 3600) -> None:
    now = time.monotonic()
    q = _hits[key]
    while q and q[0] < now - window:
        q.popleft()
    if len(q) >= limit:
        raise PermissionError("Too many requests. Please try again later.")
    q.append(now)


# ---- access requests ----------------------------------------------------------------------------

def request_access(session: Session, slug: str, *, name: str, email: str, company: str, reason: str | None, ip: str | None) -> AccessRequest:
    published_settings(session, slug)
    rate_limit(f"req:{ip}")
    require_text(name, "Name")
    require_text(company, "Company")
    if not EMAIL.match(email or ""):
        raise ValueError("Enter a valid work email.")
    r = AccessRequest(name=name.strip()[:200], email=email.strip().lower()[:320], company=company.strip()[:200], reason=(reason or "").strip()[:2000] or None, status="pending", requested_ip=ip)
    session.add(r)
    session.flush()
    return r


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def approve(session: Session, actor, request_id: int, days: int | None = None) -> str:
    """Approve and return a one-off access token (shown once; only its hash is kept)."""
    authorize(session, actor, "trust.manage")
    r = get_or_404(session, AccessRequest, request_id)
    if r.status not in ("pending", "revoked", "denied", "approved"):
        raise ValueError("Unknown state.")
    s = settings(session)
    token = secrets.token_urlsafe(32)
    r.status, r.decided_by_id, r.decided_at = "approved", actor.id, utcnow()
    r.expires_at = utcnow() + timedelta(days=days or s.access_days)
    r.token_hash = _hash(token)
    session.flush()
    return token


def deny(session: Session, actor, request_id: int) -> AccessRequest:
    authorize(session, actor, "trust.manage")
    r = get_or_404(session, AccessRequest, request_id)
    r.status, r.decided_by_id, r.decided_at, r.token_hash = "denied", actor.id, utcnow(), None
    session.flush()
    return r


def revoke(session: Session, actor, request_id: int) -> AccessRequest:
    authorize(session, actor, "trust.manage")
    r = get_or_404(session, AccessRequest, request_id)
    r.status, r.token_hash = "revoked", None
    session.flush()
    return r


def grant_for(session: Session, slug: str, token: str | None) -> AccessRequest:
    published_settings(session, slug)
    if not token or len(token) > 200:
        raise TrustUnavailable("Access link missing or invalid.")
    r = session.scalar(select(AccessRequest).where(AccessRequest.token_hash == _hash(token)))
    if r is None or r.status != "approved" or (r.expires_at and r.expires_at < utcnow()):
        raise TrustUnavailable("This access link is invalid, revoked or expired. Please request access again.")
    return r


def nda_ok(s: TrustSettings, r: AccessRequest) -> bool:
    return not s.nda_required or (r.nda_accepted_at is not None and r.nda_version == s.nda_version)


def accept_nda(session: Session, slug: str, token: str, signed_name: str, ip: str | None) -> AccessRequest:
    s = published_settings(session, slug)
    r = grant_for(session, slug, token)
    require_text(signed_name, "Your full name")
    r.nda_accepted_at, r.nda_version, r.nda_signed_name, r.nda_ip = utcnow(), s.nda_version, signed_name.strip()[:200], ip
    session.info["actor"] = None
    log_event(session, None, "nda_accepted", "AccessRequest", r.id, f"NDA v{s.nda_version} accepted by {r.email} ({signed_name.strip()[:80]})")
    session.flush()
    return r


def download(session: Session, slug: str, public_id: str, token: str | None) -> tuple[Attachment, bytes]:
    s = published_settings(session, slug)
    d = session.scalar(select(TrustDocument).where(TrustDocument.public_id == public_id, TrustDocument.published.is_(True)))
    if d is None:
        raise TrustUnavailable("Document not found.")
    who = "public"
    if d.access == "nda":
        r = grant_for(session, slug, token)
        if not nda_ok(s, r):
            raise PermissionError("Accept the NDA before downloading.")
        r.view_count += 1
        r.last_viewed_at = utcnow()
        who = r.email
    att = session.get(Attachment, d.attachment_id)
    log_event(session, None, "trust_download", "TrustDocument", d.id, f"{d.title} downloaded by {who}")
    return att, read_attachment(att)


def access_requests(session: Session) -> list[AccessRequest]:
    return list(session.scalars(select(AccessRequest).order_by(AccessRequest.id.desc())))
