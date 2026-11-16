"""Single sign-on (OIDC) configuration and in-flight logins."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, TimestampMixin, utcnow

PROVIDERS = ("entra", "google")
JIT_ROLES = ("employee", "viewer")  # automatic accounts never get more than a basic role


class SsoProvider(Audited, TimestampMixin, Base):
    """One row per provider kind. The client secret is Fernet-encrypted, write-only and redacted in the audit log."""

    __tablename__ = "sso_providers"
    __audit_redact__ = ("client_secret_enc",)
    REF_PREFIX = "SSO"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    client_id: Mapped[str | None] = mapped_column(String(200))
    client_secret_enc: Mapped[str | None] = mapped_column(Text)
    tenant_id: Mapped[str | None] = mapped_column(String(36))  # Entra ID: the organisation's tenant (single-tenant only)
    allowed_domains: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    jit_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    jit_role: Mapped[str] = mapped_column(String(30), nullable=False, default="employee")


class OidcLogin(Base):
    """A login in progress (10 minutes, single use). state and the browser binding are stored as hashes."""

    __tablename__ = "oidc_logins"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    state_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    browser_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce: Mapped[str] = mapped_column(String(100), nullable=False)
    code_verifier_enc: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    used_at: Mapped[datetime | None] = mapped_column(DateTime)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))


class SsoPolicy(Audited, TimestampMixin, Base):
    """Single row. required=True turns password sign-in off for everyone except administrators (break-glass)."""

    __tablename__ = "sso_policy"
    REF_PREFIX = "SSOP"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
