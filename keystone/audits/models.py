from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Column, Date, DateTime, ForeignKey, Integer, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin

AUDIT_TYPES = ("internal", "external", "certification", "surveillance", "supplier")
AUDIT_STATUSES = ("planned", "in_progress", "reporting", "closed")
FINDING_TYPES = ("major_nc", "minor_nc", "observation", "opportunity", "conformity")

audit_controls = Table(
    "audit_controls",
    Base.metadata,
    Column("audit_id", ForeignKey("audits.id", ondelete="CASCADE"), primary_key=True),
    Column("common_control_id", ForeignKey("common_controls.id", ondelete="CASCADE"), primary_key=True),
)


class Audit(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "audits"
    REF_PREFIX = "AUD"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    audit_type: Mapped[str] = mapped_column(String(20), nullable=False, default="internal")
    scope: Mapped[str | None] = mapped_column(Text)
    criteria: Mapped[str | None] = mapped_column(Text)
    framework_id: Mapped[int | None] = mapped_column(ForeignKey("frameworks.id"))
    vendor_id: Mapped[int | None] = mapped_column(ForeignKey("vendors.id"))
    lead_auditor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    audit_team: Mapped[str | None] = mapped_column(String(500))
    planned_start: Mapped[date | None] = mapped_column(Date)
    planned_end: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="planned")
    summary: Mapped[str | None] = mapped_column(Text)
    conclusion: Mapped[str | None] = mapped_column(Text)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime)

    controls = relationship("CommonControl", secondary=audit_controls, lazy="selectin")
    findings: Mapped[list[AuditFinding]] = relationship(back_populates="audit", cascade="all, delete-orphan", order_by="AuditFinding.id")


class AuditFinding(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "audit_findings"
    REF_PREFIX = "FND"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    audit_id: Mapped[int] = mapped_column(ForeignKey("audits.id", ondelete="CASCADE"), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text)
    requirement_id: Mapped[int | None] = mapped_column(ForeignKey("requirements.id"))
    common_control_id: Mapped[int | None] = mapped_column(ForeignKey("common_controls.id"))
    nonconformity_id: Mapped[int | None] = mapped_column(ForeignKey("nonconformities.id"))

    audit: Mapped[Audit] = relationship(back_populates="findings")


class ManagementReview(Audited, OwnedMixin, TimestampMixin, Base):
    """ISO 27001 clause 9.3. Inputs are compiled from live data and frozen when finalised."""

    __tablename__ = "management_reviews"
    REF_PREFIX = "MR"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    held_on: Mapped[date] = mapped_column(Date, nullable=False)
    period_start: Mapped[date] = mapped_column(Date, nullable=False)
    attendees: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    inputs: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    interested_party_feedback: Mapped[str | None] = mapped_column(Text)
    improvement_opportunities: Mapped[str | None] = mapped_column(Text)
    discussion: Mapped[str | None] = mapped_column(Text)
    decisions: Mapped[str | None] = mapped_column(Text)
    actions: Mapped[str | None] = mapped_column(Text)
    finalized_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    finalized_at: Mapped[datetime | None] = mapped_column(DateTime)


REQUEST_STATUSES = ("open", "provided", "accepted")

audit_request_evidence = Table(
    "audit_request_evidence",
    Base.metadata,
    Column("request_id", ForeignKey("audit_requests.id", ondelete="CASCADE"), primary_key=True),
    Column("evidence_id", ForeignKey("evidence.id", ondelete="CASCADE"), primary_key=True),
)


class AuditRequest(Audited, OwnedMixin, TimestampMixin, Base):
    """One item on an audit's evidence request list (the "PBC list"): what the auditor asked for and what was given."""

    __tablename__ = "audit_requests"
    REF_PREFIX = "PBC"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    audit_id: Mapped[int] = mapped_column(ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    common_control_id: Mapped[int | None] = mapped_column(ForeignKey("common_controls.id"))
    due_date: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    evidence = relationship("Evidence", secondary=audit_request_evidence, lazy="selectin")
    comments: Mapped[list[AuditRequestComment]] = relationship(back_populates="request", cascade="all, delete-orphan", order_by="AuditRequestComment.id")


class AuditRequestComment(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "audit_request_comments"
    REF_PREFIX = "PBCC"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_id: Mapped[int] = mapped_column(ForeignKey("audit_requests.id", ondelete="CASCADE"), nullable=False, index=True)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    request: Mapped[AuditRequest] = relationship(back_populates="comments")
