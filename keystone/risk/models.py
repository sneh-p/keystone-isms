from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Column, Date, DateTime, ForeignKey, Integer, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin

RISK_CATEGORIES = ("strategic", "operational", "technology", "third_party", "compliance", "people", "physical", "privacy")
TREATMENT_OPTIONS = ("mitigate", "accept", "transfer", "avoid")
RISK_STATUSES = ("identified", "assessed", "treatment", "monitoring", "accepted", "closed")
ACTION_STATUSES = ("open", "in_progress", "done", "cancelled")

risk_assets = Table(
    "risk_assets",
    Base.metadata,
    Column("risk_id", ForeignKey("risks.id", ondelete="CASCADE"), primary_key=True),
    Column("asset_id", ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
)
risk_controls = Table(
    "risk_controls",
    Base.metadata,
    Column("risk_id", ForeignKey("risks.id", ondelete="CASCADE"), primary_key=True),
    Column("common_control_id", ForeignKey("common_controls.id", ondelete="CASCADE"), primary_key=True),
)


class Risk(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "risks"
    REF_PREFIX = "RSK"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(30), nullable=False, default="operational")
    threat: Mapped[str | None] = mapped_column(Text)
    vulnerability: Mapped[str | None] = mapped_column(Text)
    consequence: Mapped[str | None] = mapped_column(Text)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    inherent_likelihood: Mapped[int | None] = mapped_column(Integer)
    inherent_impact: Mapped[int | None] = mapped_column(Integer)
    residual_likelihood: Mapped[int | None] = mapped_column(Integer)
    residual_impact: Mapped[int | None] = mapped_column(Integer)
    treatment_option: Mapped[str | None] = mapped_column(String(20))
    treatment_rationale: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="identified")
    review_date: Mapped[date | None] = mapped_column(Date)
    last_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime)
    fair_inputs: Mapped[dict | None] = mapped_column(JSON)
    fair_result: Mapped[dict | None] = mapped_column(JSON)
    fair_run_at: Mapped[datetime | None] = mapped_column(DateTime)

    assets = relationship("Asset", secondary=risk_assets, lazy="selectin")
    controls = relationship("CommonControl", secondary=risk_controls, lazy="selectin")
    actions: Mapped[list[TreatmentAction]] = relationship(back_populates="risk", cascade="all, delete-orphan", order_by="TreatmentAction.due_date")
    acceptances: Mapped[list[RiskAcceptance]] = relationship(back_populates="risk", cascade="all, delete-orphan", order_by="RiskAcceptance.accepted_at.desc()")


class TreatmentAction(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "treatment_actions"
    REF_PREFIX = "TRT"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    risk_id: Mapped[int] = mapped_column(ForeignKey("risks.id", ondelete="CASCADE"), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    common_control_id: Mapped[int | None] = mapped_column(ForeignKey("common_controls.id"))
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    due_date: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)

    risk: Mapped[Risk] = relationship(back_populates="actions")


class RiskAcceptance(Audited, TimestampMixin, Base):
    __tablename__ = "risk_acceptances"
    REF_PREFIX = "ACC"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    risk_id: Mapped[int] = mapped_column(ForeignKey("risks.id", ondelete="CASCADE"), nullable=False)
    level_at_acceptance: Mapped[str] = mapped_column(String(20), nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    accepted_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    accepted_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    expires_on: Mapped[date] = mapped_column(Date, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime)
    revoked_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))

    risk: Mapped[Risk] = relationship(back_populates="acceptances")
