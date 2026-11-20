"""Phishing simulations: practice emails to staff, to measure and improve how people spot and report phishing."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin


class PhishingCampaign(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "phishing_campaigns"
    REF_PREFIX = "PHS"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    template: Mapped[str] = mapped_column(String(60), nullable=False)
    audience: Mapped[dict | None] = mapped_column(JSON)  # keystone/core/audience.py; None: everyone with a portal account
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="draft")  # draft | running | completed | cancelled
    launched_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    launched_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)


class PhishingTarget(Base):
    """One person in a campaign. The link token is stored only as a hash. Individual results are need-to-know."""

    __tablename__ = "phishing_targets"
    __table_args__ = (UniqueConstraint("campaign_id", "user_id"), Index("ix_phishing_targets_token", "token_hash"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("phishing_campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    department: Mapped[str | None] = mapped_column(String(200))  # at launch, for results by department
    token_hash: Mapped[str | None] = mapped_column(String(64))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime)
    send_error: Mapped[str | None] = mapped_column(String(200))
    clicked_at: Mapped[datetime | None] = mapped_column(DateTime)
    clicks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reported_at: Mapped[datetime | None] = mapped_column(DateTime)
    note: Mapped[str | None] = mapped_column(Text)
