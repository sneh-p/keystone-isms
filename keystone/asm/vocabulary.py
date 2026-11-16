"""The common language connectors translate into, and what connectors return.

Every tool names things differently; connectors map their fields onto these properties so baselines can be written
once ("disk encrypted") and checked against whichever tools report it. A property a tool doesn't report is simply
absent, never assumed (null versus unknown, as elsewhere in Keystone).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

# name -> (entity, type, label). type: bool | int
PROPERTIES: dict[str, tuple[str, str, str]] = {
    # devices, reported by tools
    "disk_encrypted": ("device", "bool", "Disk encrypted"),
    "edr_active": ("device", "bool", "EDR agent active and healthy"),
    "av_up_to_date": ("device", "bool", "Anti-malware signatures up to date"),
    "firewall_on": ("device", "bool", "Firewall on"),
    "tamper_protection": ("device", "bool", "Tamper protection on"),
    "mdm_compliant": ("device", "bool", "Compliant in device management"),
    "patches_pending": ("device", "int", "Security patches pending"),
    "patches_failed": ("device", "int", "Patches failed"),
    "threats_active": ("device", "int", "Active threats"),
    # devices, worked out by Keystone
    "last_seen_days": ("device", "int", "Days since any tool last saw it"),
    "covered_by_edr": ("device", "bool", "Seen by an EDR tool"),
    "covered_by_rmm": ("device", "bool", "Managed by an RMM tool"),
    "covered_by_vuln": ("device", "bool", "Scanned for vulnerabilities"),
    "covered_by_mdm": ("device", "bool", "Enrolled in device management"),
    "critical_vulns": ("device", "int", "Open critical vulnerabilities"),
    "high_vulns": ("device", "int", "Open high vulnerabilities"),
    "oldest_critical_vuln_days": ("device", "int", "Age of the oldest open critical vulnerability (days)"),
    "oldest_high_vuln_days": ("device", "int", "Age of the oldest open high vulnerability (days)"),
    "exploitable_vulns": ("device", "int", "Open vulnerabilities with a known exploit"),
    # identities
    "mfa_registered": ("identity", "bool", "MFA registered"),
    "is_admin": ("identity", "bool", "Holds an administrator role"),
    "account_enabled": ("identity", "bool", "Account enabled"),
    "is_guest": ("identity", "bool", "Guest account"),
    "last_sign_in_days": ("identity", "int", "Days since last sign-in"),
    # settings
    "compliant": ("setting", "bool", "Meets its target"),
}

CATEGORIES = ("rmm", "edr", "vuln", "mdm", "identity", "posture", "manual")
DEVICE_TYPES = ("workstation", "server", "mobile", "other")
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class DeviceObs:
    external_id: str
    name: str
    category: str  # rmm | edr | vuln | mdm | manual
    hostname: str | None = None
    serial: str | None = None
    aad_device_id: str | None = None
    os: str | None = None
    os_version: str | None = None
    device_type: str | None = None
    owner_email: str | None = None
    last_seen: datetime | None = None
    props: dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnObs:
    device_external_id: str  # the device's external_id in the same connector run
    key: str
    title: str
    severity: str
    cve: str | None = None
    cvss: float | None = None
    exploitable: bool = False
    first_seen: date | None = None
    last_seen: date | None = None


@dataclass
class IdentityObs:
    upn: str
    display_name: str | None = None
    props: dict[str, Any] = field(default_factory=dict)


@dataclass
class SettingObs:
    key: str
    title: str
    compliant: bool | None
    category: str | None = None
    detail: str | None = None


@dataclass
class Inventory:
    """What one connector run found. `complete` lists the kinds this run fully enumerated, so records of those
    kinds that weren't seen can be retired; a partial or failed source never retires anything."""

    devices: list[DeviceObs] = field(default_factory=list)
    vulns: list[VulnObs] = field(default_factory=list)
    identities: list[IdentityObs] = field(default_factory=list)
    settings: list[SettingObs] = field(default_factory=list)
    complete: set[str] = field(default_factory=set)  # devices | vulns | identities | settings
    notes: list[str] = field(default_factory=list)  # e.g. "Intune not licensed: skipped"
    sample_fields: dict[str, list[str]] = field(default_factory=dict)  # field names seen per endpoint (no values)


def norm_hostname(name: str | None) -> str | None:
    if not name:
        return None
    h = name.strip().lower().split(".")[0]
    return h or None


GENERIC_SERIALS = {"", "0", "none", "default string", "to be filled by o.e.m.", "system serial number", "not specified", "123456789", "0123456789"}


def norm_serial(serial: str | None) -> str | None:
    if not serial:
        return None
    s = serial.strip().upper()
    return None if s.lower() in GENERIC_SERIALS or len(s) < 4 else s


def device_type_from(text: str | None) -> str:
    t = (text or "").lower()
    if any(w in t for w in ("server", "domain controller", "dc")):
        return "server"
    if any(w in t for w in ("ios", "android", "iphone", "ipad", "mobile", "phone", "tablet")):
        return "mobile"
    if any(w in t for w in ("workstation", "desktop", "laptop", "windows", "mac", "linux", "computer")):
        return "workstation"
    return "other"


def severity_from(value: Any) -> str:
    """Map vendor severities (words or 0-10 scores or 1-5 levels) onto critical/high/medium/low."""
    if isinstance(value, (int, float)):
        v = float(value)
        if v > 10:  # not a CVSS score
            return "low"
        return "critical" if v >= 9 else "high" if v >= 7 else "medium" if v >= 4 else "low"
    t = str(value or "").strip().lower()
    if t in ("critical", "urgent", "5"):
        return "critical"
    if t in ("high", "severe", "important", "4"):
        return "high"
    if t in ("medium", "moderate", "3"):
        return "medium"
    return "low"


def pick(obj: Any, *paths: str, default=None):
    """First present value among dotted paths, tolerant of missing keys (vendor schemas vary between versions)."""
    for p in paths:
        cur = obj
        ok = True
        for part in p.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and cur is not None and cur != "":
            return cur
    return default


def as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    t = str(value).strip().lower()
    if t in ("true", "yes", "1", "on", "enabled", "encrypted", "fullyencrypted", "protected", "compliant", "active", "good", "healthy"):
        return True
    if t in ("false", "no", "0", "off", "disabled", "notencrypted", "unprotected", "noncompliant", "inactive", "bad", "unhealthy"):
        return False
    return None


def parse_time(value: Any) -> datetime | None:
    """ISO 8601 strings or Unix epoch (seconds or milliseconds) to naive UTC."""
    from datetime import timezone

    if value in (None, ""):
        return None
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and value.replace(".", "", 1).isdigit()):
            v = float(value)
            if v > 1e12:
                v /= 1000
            return datetime.fromtimestamp(v, tz=timezone.utc).replace(tzinfo=None)
        s = str(value).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt
    except (ValueError, OverflowError, OSError):
        return None
