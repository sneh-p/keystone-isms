"""DMARC aggregate reports: who sends email as your domains, and whether it passes SPF and DKIM."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin


class DmarcReport(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "dmarc_reports"
    __table_args__ = (UniqueConstraint("org_name", "report_id"),)
    REF_PREFIX = "DMR"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_name: Mapped[str] = mapped_column(String(200), nullable=False)  # who sent the report (the receiving mail provider)
    report_id: Mapped[str] = mapped_column(String(200), nullable=False)
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    policy: Mapped[str | None] = mapped_column(String(20))
    begin: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    end: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    messages: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class DmarcRecord(Base):
    __tablename__ = "dmarc_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    report_id: Mapped[int] = mapped_column(ForeignKey("dmarc_reports.id", ondelete="CASCADE"), nullable=False, index=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False)
    disposition: Mapped[str | None] = mapped_column(String(20))
    dkim: Mapped[str | None] = mapped_column(String(20))
    spf: Mapped[str | None] = mapped_column(String(20))
    header_from: Mapped[str | None] = mapped_column(String(253))
