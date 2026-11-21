from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Date, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin

RESULTS = ("pass", "fail", "error", "unknown")


class Integration(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "integrations"
    __audit_redact__ = ("secret_enc",)
    REF_PREFIX = "INT"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    secret_enc: Mapped[str | None] = mapped_column(Text)
    schedule_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_status: Mapped[str | None] = mapped_column(String(20))
    last_error: Mapped[str | None] = mapped_column(Text)
    # Health (plain add_column): failed runs in a row, the last run that worked, and when the stored credential expires.
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime)
    credential_expires_on: Mapped[date | None] = mapped_column(Date)


class CheckResult(Base):
    """One check outcome from one run. Kept as history (not audited row-by-row; runs are logged)."""

    __tablename__ = "check_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    integration_id: Mapped[int] = mapped_column(ForeignKey("integrations.id", ondelete="CASCADE"), nullable=False, index=True)
    check_key: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    result: Mapped[str] = mapped_column(String(10), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict | None] = mapped_column(JSON)
    controls: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    run_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
