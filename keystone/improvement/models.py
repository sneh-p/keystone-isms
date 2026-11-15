from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Date, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin

NC_SOURCES = ("internal_audit", "external_audit", "incident", "management_review", "self_identified", "complaint", "monitoring")
NC_SEVERITIES = ("major", "minor", "observation")
NC_STATUSES = ("open", "action_planned", "verification", "closed")
CA_STATUSES = ("open", "done", "verified", "ineffective")


class Nonconformity(Audited, OwnedMixin, TimestampMixin, Base):
    """ISO 27001 clause 10.2."""

    __tablename__ = "nonconformities"
    REF_PREFIX = "NC"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(30), nullable=False, default="self_identified")
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="minor")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    requirement_id: Mapped[int | None] = mapped_column(ForeignKey("requirements.id"))
    common_control_id: Mapped[int | None] = mapped_column(ForeignKey("common_controls.id"))
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"))
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    containment: Mapped[str | None] = mapped_column(Text)
    root_cause: Mapped[str | None] = mapped_column(Text)
    due_date: Mapped[date | None] = mapped_column(Date)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime)
    closed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))

    actions: Mapped[list[CorrectiveAction]] = relationship(back_populates="nonconformity", cascade="all, delete-orphan", order_by="CorrectiveAction.id")


class CorrectiveAction(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "corrective_actions"
    REF_PREFIX = "CA"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    nonconformity_id: Mapped[int] = mapped_column(ForeignKey("nonconformities.id", ondelete="CASCADE"), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    due_date: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    completion_notes: Mapped[str | None] = mapped_column(Text)
    verified_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime)
    effectiveness_notes: Mapped[str | None] = mapped_column(Text)

    nonconformity: Mapped[Nonconformity] = relationship(back_populates="actions")
