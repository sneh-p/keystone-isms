"""Configuration baselines: what each platform's settings should be, the hosts and firewalls checked against them, and
the results.

Targets, findings and snapshots change on every agent report (every few hours per host), so they are not `Audited`
row by row; administrative actions on them (enrolment, renaming, revocation, uploads, exceptions) are written to the
audit log explicitly by the service. Baselines, rules and the agent settings are audited like other configuration.
"""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Date, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin, utcnow


class ConfigBaseline(Audited, OwnedMixin, TimestampMixin, Base):
    """The required settings for one platform, e.g. "Windows workstations"."""

    __tablename__ = "config_baselines"
    REF_PREFIX = "CFB"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    platform: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Applies to every target of the platform that has no baseline of its own. At most one per platform.
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Also applies to targets matching {"tags": [...], "names": [glob, ...]} (either matches). None: no scope.
    scope: Mapped[dict | None] = mapped_column(JSON)


class ConfigRule(Audited, TimestampMixin, Base):
    __tablename__ = "config_rules"
    __table_args__ = (UniqueConstraint("baseline_id", "key"),)
    REF_PREFIX = "CFR"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    baseline_id: Mapped[int] = mapped_column(ForeignKey("config_baselines.id", ondelete="CASCADE"), nullable=False, index=True)
    key: Mapped[str] = mapped_column(String(60), nullable=False)
    operator: Mapped[str] = mapped_column(String(10), nullable=False)
    expected: Mapped[object | None] = mapped_column(JSON)
    severity: Mapped[str] = mapped_column(String(10), nullable=False, default="medium")
    controls: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    applies_to_tags: Mapped[list | None] = mapped_column(JSON)  # only targets with one of these tags; None: all
    remediation: Mapped[str | None] = mapped_column(Text)  # shown on failing results


class ConfigCustomCheck(Audited, OwnedMixin, TimestampMixin, Base):
    """A read-only probe defined by an administrator (keystone/configcheck/custom.py). Its value is the fact
    `custom.<slug>`, compared by rules like any built-in setting."""

    __tablename__ = "config_custom_checks"
    __table_args__ = (UniqueConstraint("platform", "slug"),)
    REF_PREFIX = "CFC"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    platform: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    slug: Mapped[str] = mapped_column(String(41), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    probe: Mapped[str] = mapped_column(String(40), nullable=False)
    params: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    value_type: Mapped[str] = mapped_column(String(10), nullable=False)
    default_value: Mapped[object | None] = mapped_column(JSON)
    recommended: Mapped[dict | None] = mapped_column(JSON)  # {"operator", "expected", "severity", "controls"} to pre-fill rules
    library_key: Mapped[str | None] = mapped_column(String(60))


class ConfigTarget(Base):
    """A host running the agent, or a firewall whose configuration export was uploaded."""

    __tablename__ = "config_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(10), nullable=False)  # agent | firewall
    platform: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(253))
    baseline_id: Mapped[int | None] = mapped_column(ForeignKey("config_baselines.id", ondelete="SET NULL"))
    os_name: Mapped[str | None] = mapped_column(String(200))
    os_version: Mapped[str | None] = mapped_column(String(100))
    agent_version: Mapped[str | None] = mapped_column(String(20))
    # Agents: SHA-256 of the device token (shown to the agent once, at enrolment). Never the token itself.
    token_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_ip: Mapped[str | None] = mapped_column(String(64))
    # Firewalls: the uploaded file's name and SHA-256. The file itself is never stored (it holds secrets).
    source_filename: Mapped[str | None] = mapped_column(String(200))
    source_sha256: Mapped[str | None] = mapped_column(String(64))
    facts: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    facts_at: Mapped[datetime | None] = mapped_column(DateTime, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    tags: Mapped[list | None] = mapped_column(JSON)
    asset_id: Mapped[int | None] = mapped_column(Integer)  # the Asset this host or firewall is (no FK: plain add_column)
    # Custom checks the agent couldn't evaluate: {"custom.x": "refused" | "missing" | "unsupported" | "error"}.
    check_errors: Mapped[dict | None] = mapped_column(JSON)
    custom_checks: Mapped[str | None] = mapped_column(String(10))  # "disabled" when the host opted out at install


class ConfigFinding(Base):
    """The current result of one rule on one target."""

    __tablename__ = "config_findings"
    __table_args__ = (UniqueConstraint("target_id", "rule_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("config_targets.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("config_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(10), nullable=False)  # pass | fail | unknown | na | excepted
    actual: Mapped[object | None] = mapped_column(JSON)
    detail: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    since: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)  # when it entered this status
    evaluated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    exception_reason: Mapped[str | None] = mapped_column(Text)
    exception_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    exception_until: Mapped[date | None] = mapped_column(Date)


class ConfigSnapshot(Base):
    """One report or upload: the values and how the results changed from the previous one (drift history)."""

    __tablename__ = "config_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("config_targets.id", ondelete="CASCADE"), nullable=False, index=True)
    at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow, index=True)
    source: Mapped[str] = mapped_column(String(10), nullable=False)  # agent | upload | evaluate
    baseline_id: Mapped[int | None] = mapped_column(Integer)
    counts: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)  # {"pass": n, "fail": n, ...}
    changes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)  # [{"key", "from", "to", "value_from", "value_to"}]


class ConfigAgentSettings(Audited, TimestampMixin, Base):
    """Single row: the enrolment key agents exchange for their own device token, and the report interval."""

    __tablename__ = "config_agent_settings"
    __audit_redact__ = ("enrollment_key_enc",)
    REF_PREFIX = "CFA"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enrollment_key_enc: Mapped[str | None] = mapped_column(Text)  # Fernet-encrypted; shown to administrators
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime)
    report_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
