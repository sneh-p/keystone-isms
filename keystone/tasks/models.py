from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Column, Date, DateTime, ForeignKey, Integer, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin

FREQUENCIES = {"once": None, "monthly": 31, "quarterly": 92, "semiannual": 183, "yearly": 366}
TASK_STATUSES = ("todo", "in_progress", "in_review", "done", "not_relevant")

task_controls = Table(
    "task_controls",
    Base.metadata,
    Column("task_id", ForeignKey("tasks.id", ondelete="CASCADE"), primary_key=True),
    Column("common_control_id", ForeignKey("common_controls.id", ondelete="CASCADE"), primary_key=True),
)


class Task(Audited, OwnedMixin, TimestampMixin, Base):
    """A piece of compliance work that produces evidence for one or more controls."""

    __tablename__ = "tasks"
    REF_PREFIX = "TSK"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    template_key: Mapped[str | None] = mapped_column(String(60), index=True)
    evidence_hint: Mapped[str | None] = mapped_column(Text)
    frequency: Mapped[str] = mapped_column(String(20), nullable=False, default="once")
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    due_date: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="todo")
    completion_notes: Mapped[str | None] = mapped_column(Text)
    submitted_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime)
    approved_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime)
    review_comment: Mapped[str | None] = mapped_column(Text)
    not_relevant_reason: Mapped[str | None] = mapped_column(Text)
    previous_task_id: Mapped[int | None] = mapped_column(ForeignKey("tasks.id"))

    controls = relationship("CommonControl", secondary=task_controls, lazy="selectin")
