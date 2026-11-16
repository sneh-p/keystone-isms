"""Business processes with their recovery objectives, the plans that cover them, and the tests of those plans."""

from __future__ import annotations

from datetime import date

from sqlalchemy import JSON, Date, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin

CRITICALITY = ("critical", "high", "medium", "low")
TEST_TYPES = ("tabletop", "walkthrough", "simulation", "backup_restore", "full_interruption")
TEST_OUTCOMES = ("passed", "passed_with_issues", "failed")
IMPACT_AREAS = ("financial", "operational", "legal", "reputational")


class BusinessProcess(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "business_processes"
    REF_PREFIX = "BIA"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    criticality: Mapped[str] = mapped_column(String(10), nullable=False, default="medium")
    impact: Mapped[dict | None] = mapped_column(JSON)  # {financial|operational|legal|reputational: 1-5} after one day's outage
    mtpd_hours: Mapped[float | None] = mapped_column(Float)  # maximum tolerable period of disruption
    rto_hours: Mapped[float | None] = mapped_column(Float)  # recovery time objective
    rpo_hours: Mapped[float | None] = mapped_column(Float)  # recovery point objective (data loss tolerated)
    asset_ids: Mapped[list | None] = mapped_column(JSON)
    vendor_ids: Mapped[list | None] = mapped_column(JSON)
    minimum_staff: Mapped[int | None] = mapped_column(Integer)
    workarounds: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="active")
    next_review_date: Mapped[date | None] = mapped_column(Date)


class ContinuityPlan(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "continuity_plans"
    REF_PREFIX = "BCP"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    process_ids: Mapped[list | None] = mapped_column(JSON)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    strategy: Mapped[str | None] = mapped_column(Text)  # how the processes are recovered
    activation: Mapped[str | None] = mapped_column(Text)  # who invokes the plan, and when
    policy_id: Mapped[int | None] = mapped_column(ForeignKey("policy_documents.id", ondelete="SET NULL"))  # the plan document, if kept as a policy
    test_interval_months: Mapped[int] = mapped_column(Integer, nullable=False, default=12)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="active")


class ContinuityTest(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "continuity_tests"
    REF_PREFIX = "BCT"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    plan_id: Mapped[int] = mapped_column(ForeignKey("continuity_plans.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    test_type: Mapped[str] = mapped_column(String(20), nullable=False, default="tabletop")
    planned_on: Mapped[date | None] = mapped_column(Date)
    performed_on: Mapped[date | None] = mapped_column(Date)
    participants: Mapped[str | None] = mapped_column(Text)
    objectives: Mapped[str | None] = mapped_column(Text)
    results: Mapped[list | None] = mapped_column(JSON)  # [{process_id, recovered_hours, data_loss_hours}]
    findings: Mapped[str | None] = mapped_column(Text)
    outcome: Mapped[str | None] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="planned")  # planned | completed
    nonconformity_id: Mapped[int | None] = mapped_column(ForeignKey("nonconformities.id", ondelete="SET NULL"))
