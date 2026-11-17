from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Column, Date, DateTime, ForeignKey, Integer, String, Table, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin

EVIDENCE_KINDS = ("file", "link", "note")


class SoaEntry(Audited, TimestampMixin, Base):
    """Organisation decision on one requirement: applicable or not, and why."""

    __tablename__ = "soa_entries"
    __table_args__ = (UniqueConstraint("requirement_id", name="uq_soa_requirement"),)
    REF_PREFIX = "SOA"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    requirement_id: Mapped[int] = mapped_column(ForeignKey("requirements.id"), nullable=False)
    applicable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    justification: Mapped[str | None] = mapped_column(Text)


class SoaApproval(Audited, TimestampMixin, Base):
    """Frozen, approved version of a framework's SoA."""

    __tablename__ = "soa_approvals"
    REF_PREFIX = "SOAV"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    framework_id: Mapped[int] = mapped_column(ForeignKey("frameworks.id"), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    approved_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    snapshot: Mapped[list] = mapped_column(JSON, nullable=False)


# Evidence that also supports other controls than its primary one (one document, several controls).
evidence_controls = Table(
    "evidence_controls",
    Base.metadata,
    Column("evidence_id", ForeignKey("evidence.id", ondelete="CASCADE"), primary_key=True),
    Column("common_control_id", ForeignKey("common_controls.id", ondelete="CASCADE"), primary_key=True),
)

REVIEW_DECISIONS = ("accepted", "rejected")
TEST_TYPES = ("design", "operating")
TEST_METHODS = ("inquiry", "observation", "inspection", "reperformance")
TEST_RESULTS = ("effective", "partially_effective", "ineffective")


class Evidence(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "evidence"
    REF_PREFIX = "EVD"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    common_control_id: Mapped[int] = mapped_column(ForeignKey("common_controls.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    kind: Mapped[str] = mapped_column(String(10), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    attachment_id: Mapped[int | None] = mapped_column(ForeignKey("attachments.id"))
    url: Mapped[str | None] = mapped_column(String(1000))
    collected_on: Mapped[date] = mapped_column(Date, nullable=False)
    valid_until: Mapped[date | None] = mapped_column(Date)
    reviewed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime)
    superseded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    review_decision: Mapped[str | None] = mapped_column(String(10))  # accepted | rejected (A.5.36: someone other than the uploader)
    review_note: Mapped[str | None] = mapped_column(Text)
    attachment = relationship("Attachment", lazy="selectin", viewonly=True)  # for the file name in listings
    also_controls = relationship("CommonControl", secondary=evidence_controls, lazy="selectin")

    @property
    def control_ids(self) -> list[int]:
        return [self.common_control_id] + [c.id for c in self.also_controls if c.id != self.common_control_id]


class ControlTest(Audited, OwnedMixin, TimestampMixin, Base):
    """A test of a control's design or operation (ISO 27001 9.1, 9.2): who tested it, how, on what sample, and the
    result. The tester must not own the control."""

    __tablename__ = "control_tests"
    REF_PREFIX = "CTT"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    common_control_id: Mapped[int] = mapped_column(ForeignKey("common_controls.id", ondelete="CASCADE"), nullable=False, index=True)
    test_type: Mapped[str] = mapped_column(String(10), nullable=False)
    method: Mapped[str] = mapped_column(String(20), nullable=False)
    tested_on: Mapped[date] = mapped_column(Date, nullable=False)
    tester_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    sample: Mapped[str | None] = mapped_column(Text)
    result: Mapped[str] = mapped_column(String(20), nullable=False)
    findings: Mapped[str | None] = mapped_column(Text)
    evidence_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    nonconformity_id: Mapped[int | None] = mapped_column(ForeignKey("nonconformities.id", ondelete="SET NULL"))
