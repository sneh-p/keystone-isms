from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from keystone.core.attachments import save_attachment
from keystone.core.auth import User
from keystone.core.db import utcnow
from keystone.core.services import apply_fields, authorize, get_or_404, require_text, today
from keystone.core.workflow import Workflow
from keystone.frameworks.models import CommonControl

from .models import DOC_TYPES, PolicyAcknowledgement, PolicyDocument, PolicyVersion

VERSION_FLOW = Workflow(
    "policy version",
    {"draft": {"in_review": "policy.write"}, "in_review": {"approved": "policy.approve", "draft": "policy.approve"}},
    initial="draft",
)


def add_months(d: date, months: int) -> date:
    y, m = divmod(d.month - 1 + months, 12)
    year, month = d.year + y, m + 1
    import calendar

    return date(year, month, min(d.day, calendar.monthrange(year, month)[1]))


def next_label(previous: str | None, major: bool) -> str:
    if not previous:
        return "1.0"
    m = re.fullmatch(r"(\d+)\.(\d+)", previous)
    if not m:
        return "1.0"
    a, b = int(m.group(1)), int(m.group(2))
    return f"{a + 1}.0" if major else f"{a}.{b + 1}"


DOC_FIELDS = {"code", "title", "doc_type", "owner_id", "review_interval_months", "requires_acknowledgement"}


def save_document(session: Session, actor, document_id: int | None = None, *, control_ids: list[int] | None = None, **fields) -> PolicyDocument:
    authorize(session, actor, "policy.write")
    d = get_or_404(session, PolicyDocument, document_id) if document_id else PolicyDocument(status="draft", doc_type="policy", review_interval_months=12, requires_acknowledgement=False)
    apply_fields(d, fields, DOC_FIELDS)
    require_text(d.code, "Document code")
    require_text(d.title, "Title")
    if d.doc_type not in DOC_TYPES:
        raise ValueError(f"doc_type must be one of {DOC_TYPES}")
    if not 1 <= int(d.review_interval_months) <= 36:
        raise ValueError("Review interval must be 1-36 months.")
    if session.scalar(select(PolicyDocument).where(PolicyDocument.code == d.code, PolicyDocument.id != (d.id or 0))):
        raise ValueError(f"Document code {d.code} is already used.")
    if control_ids is not None:
        d.controls = list(session.scalars(select(CommonControl).where(CommonControl.id.in_(control_ids))))
    session.add(d)
    session.flush()
    return d


def open_version(doc: PolicyDocument) -> PolicyVersion | None:
    return next((v for v in doc.versions if v.status in ("draft", "in_review")), None)


def current_version(session: Session, doc: PolicyDocument) -> PolicyVersion | None:
    return session.get(PolicyVersion, doc.current_version_id) if doc.current_version_id else None


def start_version(session: Session, actor, document_id: int, *, body: str | None = None, change_summary: str | None = None, major: bool = True, filename: str | None = None, data: bytes | None = None) -> PolicyVersion:
    authorize(session, actor, "policy.write")
    doc = get_or_404(session, PolicyDocument, document_id)
    if doc.status == "retired":
        raise ValueError("Retired documents cannot get new versions.")
    if open_version(doc):
        raise ValueError("This document already has a version in draft or review.")
    cur = current_version(session, doc)
    v = PolicyVersion(document=doc, version_label=next_label(cur.version_label if cur else None, major), body=body if body is not None else (cur.body if cur else None), change_summary=change_summary, status="draft", author_id=actor.id)
    session.add(v)
    session.flush()
    if data and filename:
        v.attachment_id = save_attachment(session, actor, filename, data, "PolicyVersion", v.id).id
    session.flush()
    return v


def edit_version(session: Session, actor, version_id: int, *, body: str | None = None, change_summary: str | None = None, filename: str | None = None, data: bytes | None = None) -> PolicyVersion:
    authorize(session, actor, "policy.write")
    v = get_or_404(session, PolicyVersion, version_id)
    if v.status != "draft":
        raise ValueError("Only draft versions can be edited.")
    if body is not None:
        v.body = body
    if change_summary is not None:
        v.change_summary = change_summary
    if data and filename:
        v.attachment_id = save_attachment(session, actor, filename, data, "PolicyVersion", v.id).id
    session.flush()
    return v


def submit_version(session: Session, actor, version_id: int) -> PolicyVersion:
    v = get_or_404(session, PolicyVersion, version_id)
    if not (v.body or "").strip() and not v.attachment_id:
        raise ValueError("Add the document text or attach a file before submitting.")
    authorize(session, actor, "policy.write")
    VERSION_FLOW.apply(v, "in_review", actor)
    v.submitted_at = utcnow()
    session.flush()
    return v


def approve_version(session: Session, actor, version_id: int, note: str | None = None) -> PolicyVersion:
    authorize(session, actor, "policy.approve")
    v = get_or_404(session, PolicyVersion, version_id)
    if v.author_id == actor.id:
        raise ValueError("Segregation of duties: the author cannot approve their own version.")
    VERSION_FLOW.apply(v, "approved", actor)
    doc = v.document
    for other in doc.versions:
        if other.id != v.id and other.status == "approved":
            other.status = "superseded"
    v.approved_by_id, v.approved_at, v.approval_note = actor.id, utcnow(), note
    doc.current_version_id, doc.status = v.id, "approved"
    doc.next_review_date = add_months(today(), doc.review_interval_months)
    session.flush()
    return v


def return_version(session: Session, actor, version_id: int, note: str) -> PolicyVersion:
    authorize(session, actor, "policy.approve")
    v = get_or_404(session, PolicyVersion, version_id)
    VERSION_FLOW.apply(v, "draft", actor)
    v.approval_note = require_text(note, "Reason for returning")
    session.flush()
    return v


def record_review_no_change(session: Session, actor, document_id: int) -> PolicyDocument:
    """Periodic review concluded with no changes needed."""
    authorize(session, actor, "policy.approve")
    doc = get_or_404(session, PolicyDocument, document_id)
    if doc.status != "approved":
        raise ValueError("Only approved documents can be reviewed.")
    doc.next_review_date = add_months(today(), doc.review_interval_months)
    session.flush()
    return doc


def retire(session: Session, actor, document_id: int) -> PolicyDocument:
    authorize(session, actor, "policy.approve")
    doc = get_or_404(session, PolicyDocument, document_id)
    doc.status, doc.next_review_date = "retired", None
    session.flush()
    return doc


def acknowledge(session: Session, actor, version_id: int) -> PolicyAcknowledgement:
    authorize(session, actor, "policy.acknowledge")
    v = get_or_404(session, PolicyVersion, version_id)
    doc = v.document
    if not doc.requires_acknowledgement or doc.status != "approved" or doc.current_version_id != v.id:
        raise ValueError("Only the current approved version of a document that requires acknowledgement can be acknowledged.")
    existing = session.scalar(select(PolicyAcknowledgement).where(PolicyAcknowledgement.version_id == v.id, PolicyAcknowledgement.user_id == actor.id))
    if existing:
        return existing
    ack = PolicyAcknowledgement(version_id=v.id, user_id=actor.id, acknowledged_at=utcnow())
    session.add(ack)
    session.flush()
    return ack


def documents(session: Session, include_retired: bool = False) -> list[PolicyDocument]:
    q = select(PolicyDocument).order_by(PolicyDocument.code)
    if not include_retired:
        q = q.where(PolicyDocument.status != "retired")
    return list(session.scalars(q))


def pending_for(session: Session, user: User) -> list[PolicyVersion]:
    """Current versions the user still has to acknowledge."""
    acked = set(session.scalars(select(PolicyAcknowledgement.version_id).where(PolicyAcknowledgement.user_id == user.id)))
    out = []
    for d in documents(session):
        if d.requires_acknowledgement and d.status == "approved" and d.current_version_id and d.current_version_id not in acked:
            out.append(session.get(PolicyVersion, d.current_version_id))
    return out


@dataclass
class AckStatus:
    acknowledged: int
    total: int

    @property
    def pct(self) -> float:
        return round(100 * self.acknowledged / self.total, 1) if self.total else 100.0


def ack_status(session: Session, doc: PolicyDocument) -> AckStatus | None:
    if not doc.requires_acknowledgement or not doc.current_version_id:
        return None
    total = session.scalar(select(func.count(User.id)).where(User.active.is_(True))) or 0
    done = session.scalar(select(func.count(PolicyAcknowledgement.id)).join(User, User.id == PolicyAcknowledgement.user_id).where(PolicyAcknowledgement.version_id == doc.current_version_id, User.active.is_(True))) or 0
    return AckStatus(done, total)


def policy_attention(session: Session, on: date | None = None) -> dict[str, list[PolicyDocument]]:
    on = on or today()
    docs = documents(session)
    return {
        "review_overdue": [d for d in docs if d.status == "approved" and d.next_review_date and d.next_review_date < on],
        "never_approved": [d for d in docs if d.status == "draft"],
        "awaiting_approval": [d for d in docs if (v := open_version(d)) and v.status == "in_review"],
        "acknowledgement_incomplete": [d for d in docs if (a := ack_status(session, d)) and a.acknowledged < a.total],
    }
