"""Security indicators (key risk and performance indicators): a figure measured over time against amber and red
thresholds (ISO 27001 9.1)."""

from __future__ import annotations

from datetime import date

from sqlalchemy import Boolean, Date, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin


class Indicator(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "indicators"
    REF_PREFIX = "KRI"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    metric_key: Mapped[str | None] = mapped_column(String(60))  # measured every day by Keystone; None: entered by hand
    unit: Mapped[str | None] = mapped_column(String(20))
    higher_is_better: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    amber: Mapped[float] = mapped_column(Float, nullable=False)
    red: Mapped[float] = mapped_column(Float, nullable=False)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_value: Mapped[float | None] = mapped_column(Float)
    last_state: Mapped[str | None] = mapped_column(String(10))  # green | amber | red
    last_measured_on: Mapped[date | None] = mapped_column(Date)


class IndicatorValue(Base):
    __tablename__ = "indicator_values"
    __table_args__ = (UniqueConstraint("indicator_id", "measured_on"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    measured_on: Mapped[date] = mapped_column(Date, nullable=False)
    value: Mapped[float] = mapped_column(Float, nullable=False)
    source: Mapped[str] = mapped_column(String(10), nullable=False)  # metric | manual
    note: Mapped[str | None] = mapped_column(String(500))
