"""Daily metric snapshots for dashboard trends."""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Date, DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Base


class MetricSnapshot(Base):
    """One row per day: headline counts as they stood that day. Derived data, so not audited."""

    __tablename__ = "metric_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    day: Mapped[date] = mapped_column(Date, nullable=False, unique=True)
    values: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    taken_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
