"""Comments on records, and saved register views."""

from __future__ import annotations

from sqlalchemy import ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin


class Comment(Audited, OwnedMixin, TimestampMixin, Base):
    """A comment on a record. Comments are records too: they can't be edited or deleted, only added."""

    __tablename__ = "comments"
    __table_args__ = (Index("ix_comments_entity", "entity_type", "entity_id"),)
    REF_PREFIX = "CMT"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(40), nullable=False)
    entity_id: Mapped[int] = mapped_column(Integer, nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)


class SavedView(TimestampMixin, Base):
    """A user's named filter set for a register page (their own; not shared)."""

    __tablename__ = "saved_views"
    __table_args__ = (UniqueConstraint("user_id", "page", "name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    page: Mapped[str] = mapped_column(String(40), nullable=False)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    query: Mapped[str] = mapped_column(String(1000), nullable=False)
