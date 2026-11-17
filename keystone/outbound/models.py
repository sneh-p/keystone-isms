"""Destinations (where to send which events) and the delivery queue."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin, utcnow

KINDS = ("slack", "teams", "webhook")


class Destination(Audited, OwnedMixin, TimestampMixin, Base):
    """The URL is a secret (Slack and Teams webhook URLs carry their token): encrypted, write-only, never logged."""

    __tablename__ = "outbound_destinations"
    __audit_redact__ = ("url_enc", "signing_secret_enc")
    REF_PREFIX = "OUT"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(10), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    url_enc: Mapped[str] = mapped_column(Text, nullable=False)
    url_host: Mapped[str] = mapped_column(String(253), nullable=False)  # shown instead of the URL
    events: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    signing_secret_enc: Mapped[str | None] = mapped_column(Text)  # webhooks: HMAC key, shown once
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_status: Mapped[str | None] = mapped_column(String(20))
    last_error: Mapped[str | None] = mapped_column(String(300))
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime)


class Delivery(Base):
    __tablename__ = "outbound_deliveries"
    __table_args__ = (Index("ix_outbound_due", "status", "next_attempt_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uid: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    destination_id: Mapped[int] = mapped_column(ForeignKey("outbound_destinations.id", ondelete="CASCADE"), nullable=False, index=True)
    event: Mapped[str] = mapped_column(String(50), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="pending")  # pending | sent | failed | cancelled
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    last_error: Mapped[str | None] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime)
