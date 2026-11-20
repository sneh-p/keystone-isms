"""Look-alike domains (from certificate transparency) and supplier breach news (from a public breach list)."""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Date, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, TimestampMixin


class LookalikeDomain(Audited, TimestampMixin, Base):
    __tablename__ = "lookalike_domains"
    REF_PREFIX = "LKA"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("external_domains.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(253), unique=True, nullable=False)
    reason: Mapped[str] = mapped_column(String(200), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="new")  # new | ours | benign | threat
    note: Mapped[str | None] = mapped_column(Text)
    decided_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))


class VendorBreach(Audited, TimestampMixin, Base):
    __tablename__ = "vendor_breaches"
    __table_args__ = (UniqueConstraint("vendor_id", "breach"),)
    REF_PREFIX = "VBR"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vendor_id: Mapped[int] = mapped_column(ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False, index=True)
    breach: Mapped[str] = mapped_column(String(200), nullable=False)  # the breach list's own name for it
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    breach_date: Mapped[date | None] = mapped_column(Date)
    added_on: Mapped[date | None] = mapped_column(Date)
    accounts: Mapped[int | None] = mapped_column(Integer)
    data_classes: Mapped[list | None] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="new")  # new | not_affected | assessing | affected
    note: Mapped[str | None] = mapped_column(Text)
    decided_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
