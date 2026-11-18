from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Column, Date, DateTime, ForeignKey, Integer, String, Table, Text
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
    playbook_done: Mapped[dict | None] = mapped_column(JSON)  # {step index: {"by", "at"}} for the category's playbook
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


class IncidentAction(Audited, OwnedMixin, TimestampMixin, Base):
    """A response action with an owner and a due date (contain, eradicate, recover, notify)."""

    __tablename__ = "incident_actions"
    REF_PREFIX = "INA"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    due_date: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="open")  # open | done
    done_at: Mapped[datetime | None] = mapped_column(DateTime)


class IncidentEvidence(Audited, OwnedMixin, TimestampMixin, Base):
    """Evidence collected during an incident (ISO 27001 A.5.28): the file, its SHA-256 at collection, where it came
    from, and a chain of custody recording every download."""

    __tablename__ = "incident_evidence"
    REF_PREFIX = "INE"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    attachment_id: Mapped[int] = mapped_column(ForeignKey("attachments.id"), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str | None] = mapped_column(String(300))  # where and how it was obtained
    collected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    collected_by: Mapped[str] = mapped_column(String(150), nullable=False)
    custody: Mapped[list] = mapped_column(JSON, nullable=False, default=list)  # [{"at", "by", "action"}]


REPORT_KINDS = {
    "phishing": "Suspicious email, message or call",
    "lost_device": "Lost or stolen device",
    "account": "Someone may be using my account",
    "data": "Information sent or shared by mistake",
    "malware": "Device behaving strangely, pop-ups or ransom note",
    "physical": "Stranger, tailgating or open door",
    "other": "Something else",
}
REPORT_CATEGORY = {"phishing": "phishing", "lost_device": "lost_or_stolen_device", "account": "account_compromise", "data": "data_breach",
                   "malware": "malware", "physical": "physical", "other": "other"}


class SecurityReport(Audited, TimestampMixin, Base):
    """Something an employee reported from the portal (ISO 27001 A.6.8). The security team triages it: it becomes an
    incident, or is closed with a message back to the reporter."""

    __tablename__ = "security_reports"
    REF_PREFIX = "REP"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    reporter_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    sender: Mapped[str | None] = mapped_column(String(320))  # suspicious email: who it came from
    subject: Mapped[str | None] = mapped_column(String(300))
    where: Mapped[str | None] = mapped_column(String(300))  # which device, office or system
    clicked: Mapped[bool | None] = mapped_column(Boolean)  # opened a link or attachment, or entered a password
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="new")  # new | incident | closed
    outcome: Mapped[str | None] = mapped_column(String(20))  # incident | phishing_blocked | not_a_threat | duplicate
    reply: Mapped[str | None] = mapped_column(Text)  # message back to the reporter
    triaged_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))
