from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Date, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin


class Organisation(Audited, TimestampMixin, Base):
    """Single row: the organisation whose ISMS this is (ISO 27001 clause 4)."""

    __tablename__ = "organisation"
    REF_PREFIX = "ORG"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    legal_name: Mapped[str | None] = mapped_column(String(300))
    industry: Mapped[str | None] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    internal_issues: Mapped[str | None] = mapped_column(Text)  # 4.1
    external_issues: Mapped[str | None] = mapped_column(Text)  # 4.1
    scope_statement: Mapped[str | None] = mapped_column(Text)  # 4.3
    scope_inclusions: Mapped[str | None] = mapped_column(Text)
    scope_exclusions: Mapped[str | None] = mapped_column(Text)
    scope_interfaces: Mapped[str | None] = mapped_column(Text)
    scope_approved_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    scope_approved_at: Mapped[datetime | None] = mapped_column(DateTime)
    risk_appetite: Mapped[str | None] = mapped_column(Text)


class InterestedParty(Audited, OwnedMixin, TimestampMixin, Base):
    """ISO 27001 clause 4.2."""

    __tablename__ = "interested_parties"
    REF_PREFIX = "IP"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    party_type: Mapped[str] = mapped_column(String(20), nullable=False, default="external")  # internal|external
    needs: Mapped[str | None] = mapped_column(Text)
    addressed_by: Mapped[str | None] = mapped_column(Text)


class IsmsRoleAssignment(Audited, OwnedMixin, TimestampMixin, Base):
    """ISO 27001 clause 5.3."""

    __tablename__ = "isms_roles"
    REF_PREFIX = "ROL"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    responsibilities: Mapped[str | None] = mapped_column(Text)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    deputy_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))


class SecurityObjective(Audited, OwnedMixin, TimestampMixin, Base):
    """ISO 27001 clause 6.2."""

    __tablename__ = "security_objectives"
    REF_PREFIX = "OBJ"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    measure: Mapped[str | None] = mapped_column(Text)
    target: Mapped[str | None] = mapped_column(String(200))
    current_value: Mapped[str | None] = mapped_column(String(200))
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    due_date: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="on_track")  # on_track|at_risk|achieved|missed
