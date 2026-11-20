"""On-call rotas and pages: who is called first about critical incidents and alerts, and the escalation."""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Date, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin


class OnCallRota(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "oncall_rotas"
    REF_PREFIX = "ROT"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    member_ids: Mapped[list] = mapped_column(JSON, nullable=False)  # user ids in rotation order
    start_on: Mapped[date] = mapped_column(Date, nullable=False)  # the first member's first day
    rotation_days: Mapped[int] = mapped_column(Integer, nullable=False, default=7)
    escalate_after_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=15)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class Page(Base):
    """One call to one person. Unacknowledged pages escalate to the next member, then to the ISMS managers."""

    __tablename__ = "oncall_pages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rota_id: Mapped[int] = mapped_column(ForeignKey("oncall_rotas.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    level: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  # 0: on call; 1+: escalations
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    page: Mapped[str] = mapped_column(String(200), nullable=False)  # where in Keystone
    source: Mapped[str] = mapped_column(String(60), nullable=False)  # e.g. "incident:12"
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    emailed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    acked_at: Mapped[datetime | None] = mapped_column(DateTime)
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime)
