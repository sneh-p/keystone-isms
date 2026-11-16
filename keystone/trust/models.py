from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin


class TrustSettings(Audited, TimestampMixin, Base):
    __tablename__ = "trust_settings"
    REF_PREFIX = "TRS"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    published: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    slug: Mapped[str] = mapped_column(String(60), unique=True, nullable=False)
    headline: Mapped[str | None] = mapped_column(String(200))
    overview: Mapped[str | None] = mapped_column(Text)
    contact_email: Mapped[str | None] = mapped_column(String(320))
    brand_color: Mapped[str] = mapped_column(String(7), nullable=False, default="#4f46e5")
    show_frameworks: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Per framework code: "aligned" (default), "certified" (the organisation states it holds the certificate) or
    # "hidden". Alignment is never presented as certification on the public page.
    framework_status: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    show_controls: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    show_policies: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    show_subprocessors: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    nda_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    nda_text: Mapped[str | None] = mapped_column(Text)
    nda_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    access_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)


class TrustDocument(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "trust_documents"
    REF_PREFIX = "TDOC"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(20), nullable=False, default="report")  # report | certificate | policy | other
    access: Mapped[str] = mapped_column(String(10), nullable=False, default="nda")  # public | nda
    attachment_id: Mapped[int] = mapped_column(ForeignKey("attachments.id"), nullable=False)
    published: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class TrustFaq(Audited, TimestampMixin, Base):
    __tablename__ = "trust_faqs"
    REF_PREFIX = "FAQ"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    question: Mapped[str] = mapped_column(String(300), nullable=False)
    answer: Mapped[str] = mapped_column(Text, nullable=False)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class TrustSubprocessor(Audited, TimestampMixin, Base):
    __tablename__ = "trust_subprocessors"
    REF_PREFIX = "SUB"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vendor_id: Mapped[int] = mapped_column(ForeignKey("vendors.id", ondelete="CASCADE"), unique=True, nullable=False)
    purpose: Mapped[str] = mapped_column(String(300), nullable=False)
    location: Mapped[str | None] = mapped_column(String(120))


class AccessRequest(Audited, TimestampMixin, Base):
    """External request to see gated Trust Center documents."""

    __tablename__ = "trust_access_requests"
    REF_PREFIX = "TAR"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    company: Mapped[str] = mapped_column(String(200), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")  # pending | approved | denied | revoked
    requested_ip: Mapped[str | None] = mapped_column(String(64))
    decided_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)
    token_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    nda_accepted_at: Mapped[datetime | None] = mapped_column(DateTime)
    nda_version: Mapped[int | None] = mapped_column(Integer)
    nda_signed_name: Mapped[str | None] = mapped_column(String(200))
    nda_ip: Mapped[str | None] = mapped_column(String(64))
    view_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_viewed_at: Mapped[datetime | None] = mapped_column(DateTime)
