"""In-app notifications, per-user digest preferences and the SMTP relay used for email digests."""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Date, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, TimestampMixin, utcnow


class Notification(Base):
    """Something a user should do. Generated from the same rules as "My tasks"; derived data, so not audited."""

    __tablename__ = "notifications"
    __table_args__ = (UniqueConstraint("user_id", "key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    key: Mapped[str] = mapped_column(String(64), nullable=False)  # stable id of the underlying item (dedupe)
    kind: Mapped[str] = mapped_column(String(30), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    page: Mapped[str] = mapped_column(String(200), nullable=False)  # internal path, never a full URL
    due: Mapped[date | None] = mapped_column(Date)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    read_at: Mapped[datetime | None] = mapped_column(DateTime)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime)  # the underlying item no longer needs action
    emailed_at: Mapped[datetime | None] = mapped_column(DateTime)


class NotificationPrefs(Base):
    __tablename__ = "notification_prefs"

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    email_digest: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    digest_muted: Mapped[list | None] = mapped_column(JSON)  # categories left out of the email digest (still in the bell)
    last_digest_on: Mapped[date | None] = mapped_column(Date)


class SmtpSettings(Audited, TimestampMixin, Base):
    """Single row. The password is encrypted at rest, write-only in the API and bound to the host it was entered for."""

    __tablename__ = "smtp_settings"
    __audit_redact__ = ("password_enc",)
    REF_PREFIX = "SMTP"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    host: Mapped[str | None] = mapped_column(String(253))
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=587)
    security: Mapped[str] = mapped_column(String(10), nullable=False, default="starttls")  # starttls | tls
    username: Mapped[str | None] = mapped_column(String(320))
    password_enc: Mapped[str | None] = mapped_column(Text)
    password_host: Mapped[str | None] = mapped_column(String(253))  # the host the password was entered for
    from_address: Mapped[str | None] = mapped_column(String(320))
    from_name: Mapped[str] = mapped_column(String(100), nullable=False, default="Keystone ISMS")
    digest_hour_utc: Mapped[int] = mapped_column(Integer, nullable=False, default=7)
    last_error: Mapped[str | None] = mapped_column(Text)
