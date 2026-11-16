"""Run records for scheduled jobs and backups. Operational data, not ISMS records, so not audited row by row (backup
runs and restores still write an audit event)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Base


class JobStatus(Base):
    """One row per scheduled job: when it last ran and whether it worked."""

    __tablename__ = "job_status"

    name: Mapped[str] = mapped_column(String(60), primary_key=True)
    last_started: Mapped[datetime | None] = mapped_column(DateTime)
    last_finished: Mapped[datetime | None] = mapped_column(DateTime)
    last_success: Mapped[datetime | None] = mapped_column(DateTime)
    last_ok: Mapped[bool | None] = mapped_column(Boolean)
    # Exception class only: messages can carry hosts, paths or values that don't belong in the UI (SC-LOG-001).
    last_error: Mapped[str | None] = mapped_column(String(200))
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class BackupRun(Base):
    __tablename__ = "backup_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    filename: Mapped[str | None] = mapped_column(String(120))  # name only; the directory is server configuration
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    rows: Mapped[int | None] = mapped_column(Integer)
    files: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="running")  # running | ok | warning | failed
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)  # a test restore succeeded
    detail: Mapped[str | None] = mapped_column(Text)
