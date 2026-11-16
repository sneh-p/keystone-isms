from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, TimestampMixin


class OnboardingProfile(Audited, TimestampMixin, Base):
    """Answers from the setup wizard (single row). Re-running onboarding updates it."""

    __tablename__ = "onboarding_profile"
    REF_PREFIX = "ONB"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    profile: Mapped[dict] = mapped_column(JSON, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
