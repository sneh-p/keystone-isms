from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Date, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

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
