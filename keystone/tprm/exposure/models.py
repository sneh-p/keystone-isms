"""Vendor exposure map models (Entra ID third-party application inventory)."""

from __future__ import annotations

from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin


class EntraTenant(Audited, OwnedMixin, TimestampMixin, Base):
    """An Entra ID tenant owned by the organisation (main tenant, subsidiaries...)."""

    __tablename__ = "entra_tenants"
    REF_PREFIX = "TEN"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    entra_tenant_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    default_domain: Mapped[str | None] = mapped_column(String(255))
