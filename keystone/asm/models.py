"""Attack surface management: what the connected tools report, what the organisation requires, and the gaps.

Devices, identities, vulnerabilities and posture settings are derived data, refreshed from the connected tools
(RMM, EDR, vulnerability scanners, Microsoft). Baselines (the organisation's requirements) and exceptions are
audited; findings are the evaluated gaps.
"""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Date, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin, utcnow

SEVERITIES = ("critical", "high", "medium", "low")
ENTITIES = ("device", "identity", "setting")


class AsmDevice(Base):
    """One real device, merged from every tool that reports it (matched by serial, Entra device ID or host name)."""

    __tablename__ = "asm_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)  # lower case, no domain
    serial: Mapped[str | None] = mapped_column(String(120), index=True)
    aad_device_id: Mapped[str | None] = mapped_column(String(64), index=True)
    os: Mapped[str | None] = mapped_column(String(120))
    os_version: Mapped[str | None] = mapped_column(String(120))
    device_type: Mapped[str] = mapped_column(String(20), nullable=False, default="workstation")  # workstation | server | mobile | other
    owner_email: Mapped[str | None] = mapped_column(String(320))
    owner_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime)
    # property -> {"value", "source", "at"}: the latest value any tool reported, and which tool said so
    properties: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    retired: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class AsmSourceRecord(Base):
    """A device as one tool reports it. Links tool records to the merged device; also tells which tools cover it."""

    __tablename__ = "asm_source_records"
    __table_args__ = (UniqueConstraint("integration_id", "external_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    integration_id: Mapped[int | None] = mapped_column(ForeignKey("integrations.id", ondelete="CASCADE"), index=True)  # None: CSV import
    category: Mapped[str] = mapped_column(String(20), nullable=False)  # rmm | edr | vuln | mdm | manual
    external_id: Mapped[str] = mapped_column(String(200), nullable=False)
    device_id: Mapped[int] = mapped_column(ForeignKey("asm_devices.id", ondelete="CASCADE"), nullable=False, index=True)
    properties: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime)
    collected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)


class AsmIdentity(Base):
    __tablename__ = "asm_identities"
    __table_args__ = (UniqueConstraint("source", "upn"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(40), nullable=False)  # e.g. "entra"
    integration_id: Mapped[int | None] = mapped_column(ForeignKey("integrations.id", ondelete="CASCADE"), index=True)
    upn: Mapped[str] = mapped_column(String(320), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255))
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    properties: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    collected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)


class AsmVulnerability(Base):
    __tablename__ = "asm_vulnerabilities"
    __table_args__ = (UniqueConstraint("integration_id", "device_id", "vuln_key"), Index("ix_asm_vuln_open", "device_id", "state"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    integration_id: Mapped[int | None] = mapped_column(ForeignKey("integrations.id", ondelete="CASCADE"), index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("asm_devices.id", ondelete="CASCADE"), nullable=False)
    vuln_key: Mapped[str] = mapped_column(String(120), nullable=False)  # plugin/QID/vulnerability id from the tool
    cve: Mapped[str | None] = mapped_column(String(200))
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)  # critical | high | medium | low
    cvss: Mapped[float | None] = mapped_column(Float)
    exploitable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    first_seen: Mapped[date | None] = mapped_column(Date)
    last_seen: Mapped[date | None] = mapped_column(Date)
    state: Mapped[str] = mapped_column(String(10), nullable=False, default="open")  # open | fixed
    # Prioritisation (keystone/asm/vulnintel.py), recomputed after each import, feed refresh or policy change.
    kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)  # a CVE on CISA's KEV catalogue
    epss: Mapped[float | None] = mapped_column(Float)  # highest EPSS probability among its CVEs
    priority: Mapped[str | None] = mapped_column(String(2))  # P1 (known exploited) .. P4
    fix_by: Mapped[date | None] = mapped_column(Date)


class AsmSetting(Base):
    """A tenant or cloud configuration item (for example a Secure Score control) and whether it meets its target."""

    __tablename__ = "asm_settings"
    __table_args__ = (UniqueConstraint("integration_id", "key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    integration_id: Mapped[int | None] = mapped_column(ForeignKey("integrations.id", ondelete="CASCADE"), index=True)
    key: Mapped[str] = mapped_column(String(200), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    category: Mapped[str | None] = mapped_column(String(80))
    compliant: Mapped[bool | None] = mapped_column(Boolean)  # None = not reported
    detail: Mapped[str | None] = mapped_column(Text)
    collected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)


class Baseline(Audited, OwnedMixin, TimestampMixin, Base):
    """A requirement the organisation sets, e.g. "Workstations: disk encryption on"."""

    __tablename__ = "asm_baselines"
    REF_PREFIX = "BL"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    entity: Mapped[str] = mapped_column(String(20), nullable=False)  # device | identity | setting
    property: Mapped[str] = mapped_column(String(60), nullable=False)
    operator: Mapped[str] = mapped_column(String(10), nullable=False)  # is_true | is_false | lte | gte | eq | ne
    value: Mapped[str | None] = mapped_column(String(100))
    scope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)  # e.g. {"device_types": ["workstation"], "os": ["windows"]}
    severity: Mapped[str] = mapped_column(String(10), nullable=False, default="medium")
    controls: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    missing: Mapped[str] = mapped_column(String(10), nullable=False, default="flag")  # flag | ignore: no tool reports the property
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class AsmFinding(Audited, TimestampMixin, Base):
    """A gap between a baseline and what the tools report. Opens and resolves automatically; exceptions are approved."""

    __tablename__ = "asm_findings"
    __table_args__ = (UniqueConstraint("baseline_id", "entity_type", "entity_id"),)
    REF_PREFIX = "ASM"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    baseline_id: Mapped[int] = mapped_column(ForeignKey("asm_baselines.id", ondelete="CASCADE"), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False)
    entity_id: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="open")  # open | resolved | excepted
    no_data: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)  # open because no tool reports it
    detail: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime)
    exception_reason: Mapped[str | None] = mapped_column(Text)
    exception_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    exception_until: Mapped[date | None] = mapped_column(Date)


class KevEntry(Base):
    """CISA Known Exploited Vulnerabilities catalogue (public feed, replaced on each refresh)."""

    __tablename__ = "threat_kev"

    cve: Mapped[str] = mapped_column(String(30), primary_key=True)
    vendor: Mapped[str | None] = mapped_column(String(200))
    product: Mapped[str | None] = mapped_column(String(200))
    name: Mapped[str | None] = mapped_column(String(500))
    date_added: Mapped[date | None] = mapped_column(Date)
    due_date: Mapped[date | None] = mapped_column(Date)
    ransomware: Mapped[bool | None] = mapped_column(Boolean)


class EpssScore(Base):
    """FIRST EPSS probability for the CVEs Keystone has seen (taken from the full daily file, so nothing is sent)."""

    __tablename__ = "threat_epss"

    cve: Mapped[str] = mapped_column(String(30), primary_key=True)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    percentile: Mapped[float | None] = mapped_column(Float)
    score_date: Mapped[date | None] = mapped_column(Date)


class VulnPolicy(Audited, TimestampMixin, Base):
    """Single row: which public feeds to use, the EPSS threshold and the fix-by deadlines per severity."""

    __tablename__ = "vuln_policy"
    REF_PREFIX = "VULNPOL"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kev_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    epss_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    epss_threshold: Mapped[float] = mapped_column(Float, nullable=False, default=0.1)
    sla_critical: Mapped[int] = mapped_column(Integer, nullable=False, default=15)
    sla_high: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    sla_medium: Mapped[int] = mapped_column(Integer, nullable=False, default=90)
    sla_low: Mapped[int] = mapped_column(Integer, nullable=False, default=180)
    sla_kev: Mapped[int] = mapped_column(Integer, nullable=False, default=14)
    kev_refreshed_at: Mapped[datetime | None] = mapped_column(DateTime)
    epss_refreshed_at: Mapped[datetime | None] = mapped_column(DateTime)
    epss_score_date: Mapped[date | None] = mapped_column(Date)
    last_error: Mapped[str | None] = mapped_column(String(500))


class ExternalDomain(Audited, TimestampMixin, Base):
    """A domain the organisation owns; checked only while its verification TXT record is in place."""

    __tablename__ = "external_domains"
    REF_PREFIX = "DOM"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(253), nullable=False, unique=True)
    verification_token: Mapped[str] = mapped_column(String(100), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime)
    scan_error: Mapped[str | None] = mapped_column(String(500))
    email: Mapped[dict | None] = mapped_column(JSON)  # SPF, DMARC, CAA as found
    issues: Mapped[list | None] = mapped_column(JSON)


class ExternalHost(Base):
    """A host name under a verified domain, from certificate transparency, DNS or added by hand. Derived data."""

    __tablename__ = "external_hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("external_domains.id", ondelete="CASCADE"), nullable=False, index=True)
    host: Mapped[str] = mapped_column(String(253), nullable=False, unique=True)
    source: Mapped[str] = mapped_column(String(10), nullable=False, default="ct")  # ct | dns | manual
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime)
    checked_at: Mapped[datetime | None] = mapped_column(DateTime)
    current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)  # found in the latest scan
    facts: Mapped[dict | None] = mapped_column(JSON)
    issues: Mapped[list | None] = mapped_column(JSON)
    worst: Mapped[str | None] = mapped_column(String(10))
