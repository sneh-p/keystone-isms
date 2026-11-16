"""Security questionnaires received from customers, and the answer knowledge base."""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Date, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin

ITEM_STATUSES = ("open", "drafted", "approved")
ORIGINS = ("manual", "ai", "knowledge")
CONFIDENCE = ("high", "medium", "low", "none")


class KnowledgeEntry(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "knowledge_entries"
    REF_PREFIX = "KB"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    question: Mapped[str] = mapped_column(Text, nullable=False)
    answer: Mapped[str] = mapped_column(Text, nullable=False)
    tags: Mapped[str | None] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="draft")  # draft | approved
    approved_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime)


class SecurityQuestionnaire(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "security_questionnaires"
    REF_PREFIX = "SQ"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    requester: Mapped[str | None] = mapped_column(String(200))
    due_date: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="open")  # open | completed
    source_kind: Mapped[str] = mapped_column(String(10), nullable=False, default="manual")  # xlsx | csv | manual
    attachment_id: Mapped[int | None] = mapped_column(ForeignKey("attachments.id"))
    answer_col: Mapped[int | None] = mapped_column(Integer)  # 1-based column for answers in the original sheet
    header_row: Mapped[int | None] = mapped_column(Integer)
    job_status: Mapped[str | None] = mapped_column(String(10))  # running | done | failed
    job_progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    job_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    job_error: Mapped[str | None] = mapped_column(Text)

    items: Mapped[list["QuestionnaireItem"]] = relationship(back_populates="questionnaire", cascade="all, delete-orphan", order_by="QuestionnaireItem.position")


class QuestionnaireItem(Audited, TimestampMixin, Base):
    __tablename__ = "questionnaire_items"
    REF_PREFIX = "SQI"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    questionnaire_id: Mapped[int] = mapped_column(ForeignKey("security_questionnaires.id", ondelete="CASCADE"), nullable=False, index=True)
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    section: Mapped[str | None] = mapped_column(String(300))
    question: Mapped[str] = mapped_column(Text, nullable=False)
    answer: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="open")
    origin: Mapped[str | None] = mapped_column(String(10))
    confidence: Mapped[str | None] = mapped_column(String(10))
    citations: Mapped[list | None] = mapped_column(JSON)
    note: Mapped[str | None] = mapped_column(Text)
    sheet: Mapped[str | None] = mapped_column(String(100))
    row: Mapped[int | None] = mapped_column(Integer)
    reviewed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime)

    questionnaire: Mapped[SecurityQuestionnaire] = relationship(back_populates="items")
