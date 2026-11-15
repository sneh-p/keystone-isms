from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keystone.core.db import Audited, Base, TimestampMixin

CONTROL_STATUSES = ("not_started", "planned", "partial", "implemented", "not_applicable")
STATUS_LABELS = {
    "not_started": "Not started",
    "planned": "Planned",
    "partial": "Partially implemented",
    "implemented": "Implemented",
    "not_applicable": "Not applicable",
}


class Framework(Audited, TimestampMixin, Base):
    __tablename__ = "frameworks"
    REF_PREFIX = "FW"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    publisher: Mapped[str | None] = mapped_column(String(200))
    license: Mapped[str] = mapped_column(String(40), nullable=False)  # public_domain | proprietary | cc_by_nc_nd
    text_level: Mapped[str] = mapped_column(String(20), nullable=False)  # full | summary
    source_url: Mapped[str | None] = mapped_column(String(500))
    notice: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    requirements: Mapped[list[Requirement]] = relationship(back_populates="framework", order_by="Requirement.sort_order")


class Requirement(Audited, TimestampMixin, Base):
    __tablename__ = "requirements"
    __table_args__ = (UniqueConstraint("framework_id", "ref", name="uq_requirement_ref"),)
    REF_PREFIX = "REQ"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    framework_id: Mapped[int] = mapped_column(ForeignKey("frameworks.id"), nullable=False)
    ref: Mapped[str] = mapped_column(String(40), nullable=False)
    parent_ref: Mapped[str | None] = mapped_column(String(40))
    kind: Mapped[str] = mapped_column(String(30), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    # Official text imported from the organisation's licensed copy. Never shipped in the repo.
    licensed_text: Mapped[str | None] = mapped_column(Text)
    is_leaf: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    framework: Mapped[Framework] = relationship(back_populates="requirements")
    mappings: Mapped[list[ControlMapping]] = relationship(back_populates="requirement", cascade="all, delete-orphan")


class CommonControl(Audited, TimestampMixin, Base):
    """Keystone's internal control set. Each maps to requirements in many frameworks."""

    __tablename__ = "common_controls"
    REF_PREFIX = "KC"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    domain: Mapped[str] = mapped_column(String(60), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    # Implementation (managed in keystone.controls)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="not_started")
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    implementation_notes: Mapped[str | None] = mapped_column(Text)
    na_justification: Mapped[str | None] = mapped_column(Text)
    review_interval_days: Mapped[int] = mapped_column(Integer, nullable=False, default=365)
    last_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime)
    next_review_date: Mapped[date | None] = mapped_column(Date)

    mappings: Mapped[list[ControlMapping]] = relationship(back_populates="control", cascade="all, delete-orphan")

    @property
    def ref(self) -> str:
        return self.code


class ControlMapping(Audited, TimestampMixin, Base):
    __tablename__ = "control_mappings"
    __table_args__ = (UniqueConstraint("common_control_id", "requirement_id", name="uq_control_mapping"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    common_control_id: Mapped[int] = mapped_column(ForeignKey("common_controls.id"), nullable=False)
    requirement_id: Mapped[int] = mapped_column(ForeignKey("requirements.id"), nullable=False)
    source: Mapped[str] = mapped_column(String(30), nullable=False, default="keystone")  # keystone | user

    control: Mapped[CommonControl] = relationship(back_populates="mappings")
    requirement: Mapped[Requirement] = relationship(back_populates="mappings")
