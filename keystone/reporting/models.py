"""Daily metric snapshots for dashboard trends, and scheduled report emails."""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Date, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin


class MetricSnapshot(Base):
    """One row per day: headline counts as they stood that day. Derived data, so not audited."""

    __tablename__ = "metric_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    day: Mapped[date] = mapped_column(Date, nullable=False, unique=True)
    values: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    taken_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class ReportSchedule(Audited, OwnedMixin, TimestampMixin, Base):
    """A report emailed on a schedule to chosen Keystone users (never to outside addresses)."""

    __tablename__ = "report_schedules"
    REF_PREFIX = "RS"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    report: Mapped[str] = mapped_column(String(100), nullable=False)  # "board_pdf" or a register name
    frequency: Mapped[str] = mapped_column(String(10), nullable=False, default="monthly")  # weekly | monthly | quarterly
    recipient_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    next_run_on: Mapped[date] = mapped_column(Date, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_error: Mapped[str | None] = mapped_column(String(300))
