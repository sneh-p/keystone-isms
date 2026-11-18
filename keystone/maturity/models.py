"""Security maturity self-assessments against the NIST CSF 2.0 categories (current and target tier, 0 to 4)."""

from __future__ import annotations

from datetime import date

from sqlalchemy import JSON, Date, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin


class MaturityAssessment(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "maturity_assessments"
    REF_PREFIX = "MAT"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    assessed_on: Mapped[date] = mapped_column(Date, nullable=False)
    scores: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)  # {"GV.OC": {"current": 2, "target": 3, "note": "..."}}
    summary: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="draft")  # draft | final
