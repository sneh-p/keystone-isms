from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin

CATEGORIES = ("phishing", "malware", "ransomware", "account_compromise", "data_breach", "unauthorised_access", "denial_of_service", "lost_or_stolen_device", "misconfiguration", "vendor_incident", "physical", "policy_violation", "other")
SEVERITIES = ("low", "medium", "high", "critical")
STATUSES = ("new", "triage", "contained", "eradicated", "recovered", "closed")
RESOLUTIONS = ("resolved", "false_positive", "duplicate")

incident_assets = Table(
    "incident_assets",
    Base.metadata,
    Column("incident_id", ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("asset_id", ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
)


class Incident(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "incidents"
    REF_PREFIX = "INC"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(30), nullable=False, default="other")
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="new")
    detected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    reported_by: Mapped[str | None] = mapped_column(String(200))
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    vendor_id: Mapped[int | None] = mapped_column(ForeignKey("vendors.id"))
    risk_id: Mapped[int | None] = mapped_column(ForeignKey("risks.id"))
    personal_data_involved: Mapped[bool | None] = mapped_column(Boolean)
    notification_required: Mapped[bool | None] = mapped_column(Boolean)
    regulator_notified_at: Mapped[datetime | None] = mapped_column(DateTime)
    contained_at: Mapped[datetime | None] = mapped_column(DateTime)
    root_cause: Mapped[str | None] = mapped_column(Text)
    lessons_learned: Mapped[str | None] = mapped_column(Text)
    resolution: Mapped[str | None] = mapped_column(String(20))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime)

    assets = relationship("Asset", secondary=incident_assets, lazy="selectin")
    events: Mapped[list[IncidentEvent]] = relationship(back_populates="incident", cascade="all, delete-orphan", order_by="IncidentEvent.occurred_at")


class IncidentEvent(Audited, TimestampMixin, Base):
    """Timeline entry. Entries are never edited, only added (ISO 27001 A.5.28 evidence)."""

    __tablename__ = "incident_events"
    REF_PREFIX = "IEV"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    entry: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped[str] = mapped_column(String(150), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False, default="note")  # note | status | system

    incident: Mapped[Incident] = relationship(back_populates="events")
