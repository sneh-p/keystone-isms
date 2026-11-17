from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Column, Date, DateTime, Float, ForeignKey, Integer, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin

VENDOR_STATUSES = ("prospective", "active", "offboarding", "terminated")
SENSITIVITY = ("none", "internal", "confidential", "restricted")
CRITICALITY = ("low", "medium", "high")
ACCESS_LEVELS = ("none", "sso", "delegated", "tenant_wide")
QUESTIONNAIRE_STATUSES = ("draft", "sent", "received", "reviewed")
ASSESSMENT_STATUSES = ("draft", "in_review", "approved")

vendor_assets = Table(
    "vendor_assets",
    Base.metadata,
    Column("vendor_id", ForeignKey("vendors.id", ondelete="CASCADE"), primary_key=True),
    Column("asset_id", ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
)
vendor_risks = Table(
    "vendor_risks",
    Base.metadata,
    Column("vendor_id", ForeignKey("vendors.id", ondelete="CASCADE"), primary_key=True),
    Column("risk_id", ForeignKey("risks.id", ondelete="CASCADE"), primary_key=True),
)


class Vendor(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "vendors"
    REF_PREFIX = "VEN"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    legal_name: Mapped[str | None] = mapped_column(String(300))
    website: Mapped[str | None] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text)
    services: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str | None] = mapped_column(String(100))
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="prospective")
    data_sensitivity: Mapped[str] = mapped_column(String(20), nullable=False, default="none")
    operational_criticality: Mapped[str] = mapped_column(String(20), nullable=False, default="low")
    access_level: Mapped[str] = mapped_column(String(20), nullable=False, default="none")
    processes_personal_data: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    computed_tier: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    tier_override: Mapped[int | None] = mapped_column(Integer)
    tier_override_reason: Mapped[str | None] = mapped_column(Text)
    contract_start: Mapped[date | None] = mapped_column(Date)
    contract_end: Mapped[date | None] = mapped_column(Date)
    dpa_signed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    next_review_date: Mapped[date | None] = mapped_column(Date)
    notes: Mapped[str | None] = mapped_column(Text)
    offboarding: Mapped[dict | None] = mapped_column(JSON)  # checklist item -> {"by", "at"} while offboarding

    assets = relationship("Asset", secondary=vendor_assets, lazy="selectin")
    risks = relationship("Risk", secondary=vendor_risks, lazy="selectin")

    @property
    def tier(self) -> int:
        return self.tier_override or self.computed_tier


class QuestionnaireTemplate(Audited, TimestampMixin, Base):
    __tablename__ = "questionnaire_templates"
    REF_PREFIX = "QT"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    questions: Mapped[list] = mapped_column(JSON, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class VendorQuestionnaire(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "vendor_questionnaires"
    REF_PREFIX = "VQ"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vendor_id: Mapped[int] = mapped_column(ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False)
    template_id: Mapped[int] = mapped_column(ForeignKey("questionnaire_templates.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    responses: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    score: Mapped[float | None] = mapped_column(Float)
    due_date: Mapped[date | None] = mapped_column(Date)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime)
    received_at: Mapped[datetime | None] = mapped_column(DateTime)
    reviewed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime)
    review_notes: Mapped[str | None] = mapped_column(Text)

    template: Mapped[QuestionnaireTemplate] = relationship(lazy="joined")


class VendorAssessment(Audited, OwnedMixin, TimestampMixin, Base):
    """FAIR-based vendor risk assessment. Ranges are {"min", "ml", "max"} dicts."""

    __tablename__ = "vendor_assessments"
    REF_PREFIX = "VA"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vendor_id: Mapped[int] = mapped_column(ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False)
    entra_tenant_id: Mapped[int | None] = mapped_column(ForeignKey("entra_tenants.id"))
    questionnaire_id: Mapped[int | None] = mapped_column(ForeignKey("vendor_questionnaires.id"))
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    scenario: Mapped[str | None] = mapped_column(Text)
    integration_depth: Mapped[str | None] = mapped_column(String(100))
    tef: Mapped[dict | None] = mapped_column(JSON)
    tcap: Mapped[dict | None] = mapped_column(JSON)
    control_strength: Mapped[dict | None] = mapped_column(JSON)
    plm: Mapped[dict | None] = mapped_column(JSON)
    slef: Mapped[dict | None] = mapped_column(JSON)
    slm: Mapped[dict | None] = mapped_column(JSON)
    result: Mapped[dict | None] = mapped_column(JSON)
    run_at: Mapped[datetime | None] = mapped_column(DateTime)
    conclusion: Mapped[str | None] = mapped_column(Text)
    approved_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime)

    vendor: Mapped[Vendor] = relationship(lazy="joined")


class VendorPortalLink(Audited, OwnedMixin, TimestampMixin, Base):
    """A vendor's access to one questionnaire. Only the SHA-256 of the token is stored (SC-AUTHN-007).
    expires_at is optional by design (the default is no expiry); staff can set one or revoke the link."""

    __tablename__ = "vendor_portal_links"
    __audit_redact__ = ("token_hash",)
    REF_PREFIX = "VPL"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    questionnaire_id: Mapped[int] = mapped_column(ForeignKey("vendor_questionnaires.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    contact_name: Mapped[str | None] = mapped_column(String(200))
    contact_email: Mapped[str | None] = mapped_column(String(320))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime)
