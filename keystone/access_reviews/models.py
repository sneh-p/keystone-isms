"""A campaign and its items: one account each, with a reviewer and a decision."""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Date, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin

SOURCES = ("keystone", "identities")
DECISIONS = ("keep", "revoke", "change")


class AccessReview(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "access_reviews"
    REF_PREFIX = "AR"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    sources: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    due_date: Mapped[date] = mapped_column(Date, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")  # open | completed
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    repeat_months: Mapped[int | None] = mapped_column(Integer)  # 3, 6 or 12: the next campaign starts by itself
    next_start_on: Mapped[date | None] = mapped_column(Date)


class AccessReviewItem(Audited, TimestampMixin, Base):
    __tablename__ = "access_review_items"
    REF_PREFIX = "ARI"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    review_id: Mapped[int] = mapped_column(ForeignKey("access_reviews.id", ondelete="CASCADE"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    subject: Mapped[str] = mapped_column(String(320), nullable=False)  # the account: name and username / UPN
    access: Mapped[str] = mapped_column(String(500), nullable=False)  # what it can do (role, admin, last sign-in)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))  # the Keystone account, for source=keystone
    identity_id: Mapped[int | None] = mapped_column(Integer)  # asm_identities.id, for source=identities (snapshot; no FK)
    reviewer_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    decision: Mapped[str | None] = mapped_column(String(10))
    comment: Mapped[str | None] = mapped_column(Text)
    decided_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime)
    actioned_at: Mapped[datetime | None] = mapped_column(DateTime)  # the revoke or change was carried out
    task_id: Mapped[int | None] = mapped_column(ForeignKey("tasks.id", ondelete="SET NULL"))
