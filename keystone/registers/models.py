"""Entries in the declared registers (keystone/registers/spec.py): typed core columns plus validated fields."""

from __future__ import annotations

from datetime import date

from sqlalchemy import JSON, Date, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin


class RegisterEntry(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "register_entries"
    __table_args__ = (Index("ix_register_entries_register_status", "register", "status"), UniqueConstraint("register", "seq"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    register: Mapped[str] = mapped_column(String(40), nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  # numbered per register: CHG-0001, CHG-0002, ...
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    person_id: Mapped[int | None] = mapped_column(ForeignKey("people.id"), index=True)  # registers about a person
    due_on: Mapped[date | None] = mapped_column(Date)  # the register's due date (review, expiry, next check)
    data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    decisions: Mapped[list | None] = mapped_column(JSON)  # [{"at", "by", "from", "to", "note"}] for each move

    @property
    def ref(self) -> str:
        from .spec import REGISTERS

        r = REGISTERS.get(self.register)
        return f"{r.prefix if r else 'REG'}-{(self.seq or self.id or 0):04d}"
