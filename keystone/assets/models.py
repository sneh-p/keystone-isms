from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Date, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin

ASSET_TYPES = ("information", "application", "hardware", "software", "cloud_service", "service", "people", "site")
CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")
ASSET_STATUSES = ("active", "planned", "retired")
CIA_LABELS = {1: "Very low", 2: "Low", 3: "Medium", 4: "High", 5: "Very high"}


class Asset(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "assets"
    REF_PREFIX = "AST"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(30), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    custodian: Mapped[str | None] = mapped_column(String(200))
    location: Mapped[str | None] = mapped_column(String(200))
    classification: Mapped[str] = mapped_column(String(20), nullable=False, default="internal")
    confidentiality: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    integrity: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    availability: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    contains_personal_data: Mapped[bool] = mapped_column(nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    tags: Mapped[str | None] = mapped_column(String(300))
    # A.5.9: the inventory is reviewed; A.5.11/A.7.14: when it was acquired and disposed of.
    review_date: Mapped[date | None] = mapped_column(Date)
    last_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime)
    acquired_on: Mapped[date | None] = mapped_column(Date)
    disposed_on: Mapped[date | None] = mapped_column(Date)

    @property
    def criticality(self) -> int:
        return max(self.confidentiality, self.integrity, self.availability)
