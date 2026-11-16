"""The bearer token an identity provider uses for SCIM. Stored as a SHA-256 hash; shown once when created."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, utcnow


class ScimToken(Audited, OwnedMixin, Base):
    __tablename__ = "scim_tokens"
    __audit_redact__ = ("token_hash",)
    REF_PREFIX = "SCIM"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    label: Mapped[str] = mapped_column(String(100), nullable=False)
    default_role: Mapped[str] = mapped_column(String(30), nullable=False, default="employee")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime)
