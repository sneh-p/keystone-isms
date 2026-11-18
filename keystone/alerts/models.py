"""The security alert inbox: alerts your security tools send to Keystone, and the sources allowed to send them."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin

SEVERITIES = ("info", "low", "medium", "high", "critical")
CATEGORIES = ("phishing", "malware", "ransomware", "account_compromise", "data_breach", "unauthorised_access", "denial_of_service",
              "lost_or_stolen_device", "misconfiguration", "vulnerability", "backup", "policy_violation", "physical", "other")
STATUSES = ("new", "acknowledged", "incident", "closed")
CLOSE_REASONS = {"benign": "Benign: expected activity", "false_positive": "False positive", "resolved": "Resolved without an incident", "duplicate": "Duplicate"}


class AlertSource(Audited, OwnedMixin, TimestampMixin, Base):
    """A tool allowed to send alerts. Its token is shown once and stored only as a SHA-256 hash."""

    __tablename__ = "alert_sources"
    __audit_redact__ = ("token_hash",)
    REF_PREFIX = "SRC"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    kind: Mapped[str] = mapped_column(String(30), nullable=False)  # edr | siem | email | cloud | backup | identity | other
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_received_at: Mapped[datetime | None] = mapped_column(DateTime)
    received: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class Alert(Audited, TimestampMixin, Base):
    __tablename__ = "alerts"
    __table_args__ = (UniqueConstraint("source_id", "external_id"), Index("ix_alerts_status", "status"), Index("ix_alerts_fingerprint", "source_id", "fingerprint"))
    REF_PREFIX = "ALR"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("alert_sources.id", ondelete="CASCADE"), nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(200))
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)  # for alerts without an id: title, host and account
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    category: Mapped[str] = mapped_column(String(30), nullable=False)
    host: Mapped[str | None] = mapped_column(String(253))
    account: Mapped[str | None] = mapped_column(String(320))
    description: Mapped[str | None] = mapped_column(Text)
    link: Mapped[str | None] = mapped_column(String(2000))  # back to the alert in the tool (https only)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(15), nullable=False, default="new")
    asset_id: Mapped[int | None] = mapped_column(Integer)  # matched by host name (no FK: assets can be deleted)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))
    close_reason: Mapped[str | None] = mapped_column(String(20))
    note: Mapped[str | None] = mapped_column(Text)
    handled_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    handled_at: Mapped[datetime | None] = mapped_column(DateTime)
