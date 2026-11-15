"""Vendor exposure map models (Entra ID third-party application inventory)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin


class EntraTenant(Audited, OwnedMixin, TimestampMixin, Base):
    """An Entra ID tenant owned by the organisation (main tenant, subsidiaries...)."""

    __tablename__ = "entra_tenants"
    REF_PREFIX = "TEN"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    entra_tenant_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    default_domain: Mapped[str | None] = mapped_column(String(255))

OWNER_CLASSES = ("microsoft", "internal", "third_party", "unknown")
EXPOSURE_LEVELS = ("Critical", "High", "Medium", "Low")


class ExposureSnapshot(Audited, TimestampMixin, Base):
    __tablename__ = "exposure_snapshots"
    __table_args__ = (UniqueConstraint("tenant_id", "collected_at_utc", name="uq_snapshot_tenant_time"),)
    REF_PREFIX = "SNP"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("entra_tenants.id", ondelete="CASCADE"), nullable=False)
    collected_at_utc: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    collector_version: Mapped[str] = mapped_column(String(20), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(10), nullable=False)
    operator_upn: Mapped[str] = mapped_column(String(320), nullable=False)
    ticket_number: Mapped[str | None] = mapped_column(String(100))
    entra_p1_available: Mapped[bool | None] = mapped_column(Boolean)
    write_scopes_present: Mapped[bool] = mapped_column(Boolean, nullable=False)
    granted_scopes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    microsoft_owned_skipped_count: Mapped[int | None] = mapped_column(Integer)
    endpoint_status: Mapped[dict] = mapped_column(JSON, nullable=False)
    imported_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    imported_by: Mapped[str] = mapped_column(String(150), nullable=False)

    tenant: Mapped[EntraTenant] = relationship(lazy="joined")
    apps: Mapped[list[TenantApp]] = relationship(back_populates="snapshot", cascade="all, delete-orphan")
    consent: Mapped[ConsentPosture | None] = relationship(back_populates="snapshot", cascade="all, delete-orphan", uselist=False)


class ConsentPosture(Audited, TimestampMixin, Base):
    __tablename__ = "consent_postures"
    REF_PREFIX = "CP"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("exposure_snapshots.id", ondelete="CASCADE"), unique=True, nullable=False)
    users_can_consent: Mapped[bool | None] = mapped_column(Boolean)
    permission_grant_policies_raw: Mapped[list | None] = mapped_column(JSON)
    admin_consent_workflow_enabled: Mapped[bool | None] = mapped_column(Boolean)

    snapshot: Mapped[ExposureSnapshot] = relationship(back_populates="consent")


class TenantApp(Audited, TimestampMixin, Base):
    __tablename__ = "tenant_apps"
    REF_PREFIX = "APP"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("exposure_snapshots.id", ondelete="CASCADE"), nullable=False, index=True)
    sp_object_id: Mapped[str] = mapped_column(String(36), nullable=False)
    app_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    display_name: Mapped[str | None] = mapped_column(String(300))
    service_principal_type: Mapped[str | None] = mapped_column(String(50))
    owner_org_id: Mapped[str | None] = mapped_column(String(36), index=True)
    owner_class: Mapped[str] = mapped_column(String(20), nullable=False)
    needs_review: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    publisher_name: Mapped[str | None] = mapped_column(String(300))
    verified_publisher_name: Mapped[str | None] = mapped_column(String(300))
    publisher_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    account_enabled: Mapped[bool | None] = mapped_column(Boolean)
    last_sign_in_utc: Mapped[datetime | None] = mapped_column(DateTime)
    sign_in_data_available: Mapped[bool] = mapped_column(Boolean, nullable=False)
    homepage: Mapped[str | None] = mapped_column(String(1000))
    reply_url_domains: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    snapshot: Mapped[ExposureSnapshot] = relationship(back_populates="apps")
    permissions: Mapped[list[AppPermission]] = relationship(back_populates="app", cascade="all, delete-orphan")
    credentials: Mapped[list[AppCredential]] = relationship(back_populates="app", cascade="all, delete-orphan")
    exposure: Mapped[AppExposure | None] = relationship(back_populates="app", cascade="all, delete-orphan", uselist=False)


class AppPermission(Audited, TimestampMixin, Base):
    __tablename__ = "app_permissions"
    REF_PREFIX = "PRM"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_app_id: Mapped[int] = mapped_column(ForeignKey("tenant_apps.id", ondelete="CASCADE"), nullable=False, index=True)
    permission_type: Mapped[str] = mapped_column(String(20), nullable=False)  # application | delegated
    resource_app_id: Mapped[str | None] = mapped_column(String(36))
    resource_name: Mapped[str | None] = mapped_column(String(300))
    value: Mapped[str] = mapped_column(String(300), nullable=False)
    consent_type: Mapped[str] = mapped_column(String(20), nullable=False)  # AllPrincipals | Principal | n/a
    user_count: Mapped[int | None] = mapped_column(Integer)
    tier: Mapped[str] = mapped_column(String(20), nullable=False)

    app: Mapped[TenantApp] = relationship(back_populates="permissions")


class AppCredential(Audited, TimestampMixin, Base):
    __tablename__ = "app_credentials"
    REF_PREFIX = "CRD"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_app_id: Mapped[int] = mapped_column(ForeignKey("tenant_apps.id", ondelete="CASCADE"), nullable=False, index=True)
    owner_type: Mapped[str] = mapped_column(String(20), nullable=False)  # application | servicePrincipal
    key_id: Mapped[str] = mapped_column(String(36), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(300))
    credential_type: Mapped[str] = mapped_column(String(20), nullable=False)
    start_utc: Mapped[datetime | None] = mapped_column(DateTime)
    end_utc: Mapped[datetime | None] = mapped_column(DateTime)
    lifetime_days: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # valid | expiring_30d | expired

    app: Mapped[TenantApp] = relationship(back_populates="credentials")


class AppExposure(Audited, TimestampMixin, Base):
    __tablename__ = "app_exposures"
    REF_PREFIX = "EXP"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_app_id: Mapped[int] = mapped_column(ForeignKey("tenant_apps.id", ondelete="CASCADE"), unique=True, nullable=False)
    exposure_level: Mapped[str] = mapped_column(String(20), nullable=False)
    has_app_only: Mapped[bool] = mapped_column(Boolean, nullable=False)
    max_permission_tier: Mapped[str | None] = mapped_column(String(20))
    admin_consented: Mapped[bool] = mapped_column(Boolean, nullable=False)
    user_consent_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    dormant: Mapped[bool | None] = mapped_column(Boolean)
    credential_flags: Mapped[dict | None] = mapped_column(JSON)
    incomplete_data: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reasons: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    app: Mapped[TenantApp] = relationship(back_populates="exposure")


class VendorAppMapping(Audited, TimestampMixin, Base):
    """Owner organisation (vendor's Entra tenant) -> Keystone vendor. Applies across all tenants."""

    __tablename__ = "vendor_app_mappings"
    REF_PREFIX = "MAP"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vendor_id: Mapped[int | None] = mapped_column(ForeignKey("vendors.id", ondelete="SET NULL"))
    owner_org_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # suggested | confirmed | ignored
    match_score: Mapped[float | None] = mapped_column(Float)
    match_signals: Mapped[dict | None] = mapped_column(JSON)
    confirmed_by: Mapped[str | None] = mapped_column(String(150))
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime)


class FairSuggestion(Audited, TimestampMixin, Base):
    __tablename__ = "fair_suggestions"
    REF_PREFIX = "SUG"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("vendor_assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    snapshot_id: Mapped[int | None] = mapped_column(ForeignKey("exposure_snapshots.id", ondelete="SET NULL"))
    field: Mapped[str] = mapped_column(String(40), nullable=False)
    current_value: Mapped[dict | str | None] = mapped_column(JSON)
    suggested_value: Mapped[dict | str | None] = mapped_column(JSON)
    rule_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    reasons: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    decided_by: Mapped[str | None] = mapped_column(String(150))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime)
    note: Mapped[str | None] = mapped_column(Text)
