from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Column, Date, DateTime, ForeignKey, Integer, String, Table, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin

DOC_TYPES = ("policy", "standard", "procedure", "guideline", "plan")
DOC_STATUSES = ("draft", "approved", "retired")
VERSION_STATUSES = ("draft", "in_review", "approved", "superseded")

policy_controls = Table(
    "policy_controls",
    Base.metadata,
    Column("document_id", ForeignKey("policy_documents.id", ondelete="CASCADE"), primary_key=True),
    Column("common_control_id", ForeignKey("common_controls.id", ondelete="CASCADE"), primary_key=True),
)


class PolicyDocument(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "policy_documents"
    REF_PREFIX = "DOC"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    doc_type: Mapped[str] = mapped_column(String(20), nullable=False, default="policy")
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    review_interval_months: Mapped[int] = mapped_column(Integer, nullable=False, default=12)
    next_review_date: Mapped[date | None] = mapped_column(Date)
    requires_acknowledgement: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ack_audience: Mapped[dict | None] = mapped_column(JSON)  # keystone/core/audience.py: None means everyone
    current_version_id: Mapped[int | None] = mapped_column(ForeignKey("policy_versions.id", use_alter=True))

    versions: Mapped[list[PolicyVersion]] = relationship(back_populates="document", foreign_keys="PolicyVersion.document_id", cascade="all, delete-orphan", order_by="PolicyVersion.id")
    controls = relationship("CommonControl", secondary=policy_controls, lazy="selectin")

    @property
    def ref(self) -> str:
        return self.code


class PolicyVersion(Audited, TimestampMixin, Base):
    __tablename__ = "policy_versions"
    __table_args__ = (UniqueConstraint("document_id", "version_label", name="uq_policy_version_label"),)
    REF_PREFIX = "VER"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    document_id: Mapped[int] = mapped_column(ForeignKey("policy_documents.id", ondelete="CASCADE"), nullable=False)
    version_label: Mapped[str] = mapped_column(String(20), nullable=False)
    body: Mapped[str | None] = mapped_column(Text)
    attachment_id: Mapped[int | None] = mapped_column(ForeignKey("attachments.id"))
    change_summary: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime)
    approved_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime)
    approval_note: Mapped[str | None] = mapped_column(Text)
    # E-signature of the approval: the approver's typed name, bound to a SHA-256 of the exact approved content.
    approval_signed_name: Mapped[str | None] = mapped_column(String(200))
    content_sha256: Mapped[str | None] = mapped_column(String(64))

    document: Mapped[PolicyDocument] = relationship(back_populates="versions", foreign_keys=[document_id])


class PolicyAcknowledgement(Audited, TimestampMixin, Base):
    __tablename__ = "policy_acknowledgements"
    __table_args__ = (UniqueConstraint("version_id", "user_id", name="uq_ack_version_user"),)
    REF_PREFIX = "ACK"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version_id: Mapped[int] = mapped_column(ForeignKey("policy_versions.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    acknowledged_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    # E-signature: typed name, the content fingerprint signed, and where it was signed from.
    signed_name: Mapped[str | None] = mapped_column(String(200))
    content_sha256: Mapped[str | None] = mapped_column(String(64))
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(300))
