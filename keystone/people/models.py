from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Date, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin

PERSON_STATUSES = ("onboarding", "active", "offboarding", "offboarded")
OFFBOARDING_ITEMS = {
    "access_revoked": "All system access revoked",
    "accounts_disabled": "Accounts disabled in the identity provider",
    "assets_returned": "Company devices and assets returned",
    "data_handover": "Work data handed over",
    "manager_signoff": "Manager sign-off",
}
DEVICE_CHECKS = {
    "disk_encryption": "Disk encryption is on (BitLocker / FileVault)",
    "screen_lock": "Screen locks automatically within 5 minutes",
    "antivirus": "Anti-malware is installed and running",
    "auto_updates": "Automatic OS updates are on",
    "firewall": "Firewall is on",
    "password_manager": "Company password manager is installed",
}


class Person(Audited, OwnedMixin, TimestampMixin, Base):
    """A member of the workforce. May or may not have a Keystone sign-in (user_id)."""

    __tablename__ = "people"
    REF_PREFIX = "PER"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    job_title: Mapped[str | None] = mapped_column(String(200))
    department: Mapped[str | None] = mapped_column(String(200))
    employment_type: Mapped[str] = mapped_column(String(20), nullable=False, default="employee")  # employee | contractor
    manager_id: Mapped[int | None] = mapped_column(ForeignKey("people.id"))
    start_date: Mapped[date | None] = mapped_column(Date)
    end_date: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="onboarding")
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), unique=True)
    offboarding: Mapped[dict | None] = mapped_column(JSON)  # {item: {"by": username, "at": iso}}
    # Set when an HR system integration manages this person (round 3): which one, and its id for them.
    # No foreign key on purpose: adding one would rebuild this table on SQLite (see migration 0015); a removed
    # integration just leaves a stale id, which only affects matching.
    hr_integration_id: Mapped[int | None] = mapped_column(Integer)
    hr_external_id: Mapped[str | None] = mapped_column(String(100))


class Invitation(Base):
    """One-time sign-up link. Only the SHA-256 of the token is stored."""

    __tablename__ = "invitations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    person_id: Mapped[int] = mapped_column(ForeignKey("people.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime)


class TrainingCompletion(Audited, TimestampMixin, Base):
    __tablename__ = "training_completions"
    REF_PREFIX = "TRN"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    module_key: Mapped[str] = mapped_column(String(60), nullable=False)
    module_version: Mapped[int] = mapped_column(Integer, nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    out_of: Mapped[int] = mapped_column(Integer, nullable=False)
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class DeviceAttestation(Audited, TimestampMixin, Base):
    __tablename__ = "device_attestations"
    __table_args__ = (UniqueConstraint("user_id", "device_name", name="uq_device_per_user"),)
    REF_PREFIX = "DEV"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    device_name: Mapped[str] = mapped_column(String(200), nullable=False)
    os: Mapped[str] = mapped_column(String(60), nullable=False)
    checks: Mapped[dict] = mapped_column(JSON, nullable=False)
    attested_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    attachment_id: Mapped[int | None] = mapped_column(ForeignKey("attachments.id"))


class TrainingAssignment(Audited, TimestampMixin, Base):
    """Who must complete a training module, and how soon (ISO 27001 A.6.3). Modules without an assignment apply to
    everyone. Completions stay valid for a year; a new module version asks for it again."""

    __tablename__ = "training_assignments"
    REF_PREFIX = "TRA"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    module_key: Mapped[str] = mapped_column(String(60), unique=True, nullable=False)
    audience: Mapped[dict | None] = mapped_column(JSON)  # keystone/core/audience.py; None means everyone
    due_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)  # after starting (or after assignment)
    active: Mapped[bool | None] = mapped_column(Boolean)  # False: switched off (not offered, not due); None or True: on


class TrainingModule(Audited, TimestampMixin, Base):
    """A training module written by the organisation, alongside the built-in ones in content/training. Its quiz
    answers stay on the server. `version` goes up when everyone must take it again."""

    __tablename__ = "training_modules"
    REF_PREFIX = "TRM"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(60), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    summary: Mapped[str] = mapped_column(String(300), nullable=False)
    minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    quiz: Mapped[list] = mapped_column(JSON, nullable=False)  # [{"q": str, "options": [str], "answer": int}]
    pass_mark: Mapped[int] = mapped_column(Integer, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    copied_from: Mapped[str | None] = mapped_column(String(60))  # the built-in module it started as


class ExternalTraining(Audited, TimestampMixin, Base):
    """Training a person completed outside Keystone (a classroom session, an external course), recorded by whoever
    manages people, optionally with a certificate. When it names a module it counts as passing that module."""

    __tablename__ = "external_trainings"
    REF_PREFIX = "EXT"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    person_id: Mapped[int] = mapped_column(ForeignKey("people.id"), nullable=False, index=True)
    module_key: Mapped[str | None] = mapped_column(String(60))
    module_version: Mapped[int | None] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    provider: Mapped[str | None] = mapped_column(String(200))
    completed_on: Mapped[date] = mapped_column(Date, nullable=False)
    valid_until: Mapped[date] = mapped_column(Date, nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    attachment_id: Mapped[int | None] = mapped_column(ForeignKey("attachments.id"))

    @property
    def completed_at(self) -> datetime:
        return datetime.combine(self.completed_on, datetime.min.time())
