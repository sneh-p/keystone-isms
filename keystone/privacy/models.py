"""Privacy records. Requests hold the requester's name and contact details: they're redacted in the audit log and
cleared a configurable time after the request is closed (data minimisation)."""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Date, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin

LAWFUL_BASES = ("consent", "contract", "legal_obligation", "vital_interests", "public_task", "legitimate_interests")
TRANSFER_SAFEGUARDS = ("none", "adequacy", "scc", "bcr", "derogation")
ROLES = ("controller", "processor", "joint_controller")
REQUEST_TYPES = ("access", "rectification", "erasure", "restriction", "portability", "objection", "automated_decision")
REQUEST_STATUSES = ("new", "verifying", "in_progress", "completed", "refused")
DPIA_STATUSES = ("draft", "in_review", "approved", "rejected")
DPIA_OUTCOMES = ("proceed", "proceed_with_measures", "consult_authority", "do_not_proceed")
BREACH_RISK = ("no_risk", "risk", "high_risk")


class ProcessingActivity(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "processing_activities"
    REF_PREFIX = "ROPA"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="controller")
    lawful_basis: Mapped[str] = mapped_column(String(30), nullable=False, default="contract")
    legitimate_interest: Mapped[str | None] = mapped_column(Text)  # the interest pursued, when that is the basis
    special_category: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    special_condition: Mapped[str | None] = mapped_column(String(300))  # Art. 9(2) condition
    data_subjects: Mapped[str | None] = mapped_column(Text)
    data_categories: Mapped[str | None] = mapped_column(Text)
    recipients: Mapped[str | None] = mapped_column(Text)
    vendor_ids: Mapped[list | None] = mapped_column(JSON)  # processors from the vendor register
    asset_ids: Mapped[list | None] = mapped_column(JSON)  # systems from the asset register
    transfers: Mapped[str | None] = mapped_column(Text)  # countries outside the EEA, if any
    transfer_safeguard: Mapped[str] = mapped_column(String(20), nullable=False, default="none")
    retention: Mapped[str | None] = mapped_column(String(500))
    security_measures: Mapped[str | None] = mapped_column(Text)
    dpia_required: Mapped[bool | None] = mapped_column(Boolean)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="active")  # active | retired
    next_review_date: Mapped[date | None] = mapped_column(Date)


class Dpia(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "dpias"
    REF_PREFIX = "DPIA"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    activity_id: Mapped[int | None] = mapped_column(ForeignKey("processing_activities.id", ondelete="SET NULL"))
    description: Mapped[str | None] = mapped_column(Text)  # the processing, its context and purposes
    necessity: Mapped[str | None] = mapped_column(Text)  # necessity and proportionality
    risks: Mapped[list | None] = mapped_column(JSON)  # [{risk, likelihood 1-3, severity 1-3, measures, residual 1-3}]
    dpo_advice: Mapped[str | None] = mapped_column(Text)
    outcome: Mapped[str | None] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    submitted_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    decided_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime)
    decision_note: Mapped[str | None] = mapped_column(Text)
    next_review_date: Mapped[date | None] = mapped_column(Date)


class DataSubjectRequest(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "data_subject_requests"
    __audit_redact__ = ("requester_name", "requester_contact")
    REF_PREFIX = "DSR"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_type: Mapped[str] = mapped_column(String(30), nullable=False)
    received_on: Mapped[date] = mapped_column(Date, nullable=False)
    channel: Mapped[str | None] = mapped_column(String(100))
    requester_name: Mapped[str | None] = mapped_column(String(200))
    requester_contact: Mapped[str | None] = mapped_column(String(320))
    details: Mapped[str | None] = mapped_column(Text)
    identity_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    due_date: Mapped[date] = mapped_column(Date, nullable=False)
    extended: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    extension_reason: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="new")
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    outcome: Mapped[str | None] = mapped_column(Text)
    closed_on: Mapped[date | None] = mapped_column(Date)
    redacted_at: Mapped[datetime | None] = mapped_column(DateTime)


class BreachAssessment(Audited, OwnedMixin, TimestampMixin, Base):
    """The GDPR record for an incident involving personal data. Every breach is documented (Art. 33(5)), whether
    or not it was notified."""

    __tablename__ = "breach_assessments"
    REF_PREFIX = "BRE"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, unique=True)
    data_categories: Mapped[str | None] = mapped_column(Text)
    subjects_affected: Mapped[int | None] = mapped_column(Integer)  # approximate
    records_affected: Mapped[int | None] = mapped_column(Integer)  # approximate
    consequences: Mapped[str | None] = mapped_column(Text)
    measures: Mapped[str | None] = mapped_column(Text)
    risk_level: Mapped[str | None] = mapped_column(String(10))
    rationale: Mapped[str | None] = mapped_column(Text)  # why the authority / people were or weren't notified
    authority_reference: Mapped[str | None] = mapped_column(String(100))
    subjects_notified_at: Mapped[datetime | None] = mapped_column(DateTime)
