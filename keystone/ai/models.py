from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, TimestampMixin, utcnow


class AiSettings(Audited, TimestampMixin, Base):
    """Single row. AI is off until an administrator turns it on and a key is available."""

    __tablename__ = "ai_settings"
    __audit_redact__ = ("api_key_enc",)
    REF_PREFIX = "AIS"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    model: Mapped[str] = mapped_column(String(80), nullable=False)
    effort: Mapped[str] = mapped_column(String(10), nullable=False, default="medium")
    api_key_enc: Mapped[str | None] = mapped_column(Text)
    # SC-LLM-005: bounded consumption.
    max_calls_per_user_hour: Mapped[int] = mapped_column(Integer, nullable=False, default=100, server_default="100")
    monthly_token_budget: Mapped[int] = mapped_column(Integer, nullable=False, default=2_000_000, server_default="2000000")


class AiUsage(Base):
    """One row per Claude API call: who, which feature, tokens. Calls are also written to the audit log."""

    __tablename__ = "ai_usage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    feature: Mapped[str] = mapped_column(String(40), nullable=False)
    model: Mapped[str] = mapped_column(String(80), nullable=False)
    ok: Mapped[bool] = mapped_column(Boolean, nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cache_read_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cache_write_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    error: Mapped[str | None] = mapped_column(String(500))
