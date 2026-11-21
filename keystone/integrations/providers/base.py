from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Outcome:
    key: str
    result: str  # pass | fail | error | unknown
    summary: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class PermissionReport:
    """What the stored key can do beyond reading, as far as the tool tells its own key (Test connection)."""

    result: str  # pass: read-only as far as can be seen | fail: more than needed | unknown: the tool doesn't say
    summary: str
    extra: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CheckDef:
    key: str
    title: str
    controls: tuple[str, ...]


@dataclass(frozen=True)
class ConfigField:
    name: str
    label: str
    secret: bool = False
    required: bool = True
    help: str = ""
    example: str = ""  # used in setup commands until the field is filled in (never for secrets)
    options: tuple[tuple[str, str], ...] = ()  # (value, label): shown as a choice; any other value is refused


def pull_alerts_field(permission: str) -> ConfigField:
    return ConfigField("pull_alerts", "Bring alerts into the Alert inbox", required=False, options=(("", "No"), ("on", "Yes")),
                       help=f"Off by default. When on, each run also reads the tool's new alerts (needs {permission}, read-only) into Operations → Alert inbox.")


def alert_severity(value) -> str:
    """A tool's alert severity (a word, or a 0-100 score) as the inbox's info/low/medium/high/critical."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "critical" if value >= 90 else "high" if value >= 70 else "medium" if value >= 40 else "low"
    word = str(value or "").strip().lower()
    return {"critical": "critical", "high": "high", "medium": "medium", "moderate": "medium", "low": "low", "informational": "info", "info": "info"}.get(word, "medium")


@dataclass(frozen=True)
class SetupStep:
    """One step of the setup guide. `code` may use {field} placeholders for non-secret fields
    (and {host} for a URL's host name); secrets are never put into commands."""

    title: str
    text: str
    kind: str = "do"  # do | verify
    code: str = ""
    link: str = ""
    link_label: str = ""


class Provider:
    key: str = ""
    name: str = ""
    description: str = ""
    fields: tuple[ConfigField, ...] = ()
    checks: tuple[CheckDef, ...] = ()
    setup: tuple[SetupStep, ...] = ()
    stores_results: bool = False  # run() writes records itself when given a session: Test connection then passes none

    def run(self, config: dict, secrets: dict, session=None) -> list[Outcome]:  # pragma: no cover - interface
        raise NotImplementedError

    def permissions(self, config: dict, secrets: dict) -> PermissionReport | None:
        """Override where the tool lets a key see its own permissions. None: Keystone can't check them."""
        return None

    def check(self, key: str) -> CheckDef:
        return next(c for c in self.checks if c.key == key)

    def describe(self) -> dict:
        return {
            "key": self.key, "name": self.name, "description": self.description,
            "fields": [f.__dict__ for f in self.fields],
            "checks": [{"key": c.key, "title": c.title, "controls": list(c.controls)} for c in self.checks],
            "setup": [st.__dict__ for st in self.setup],
            "checks_permissions": type(self).permissions is not Provider.permissions,
        }


class InventoryProvider(Provider):
    """A read-only source for attack surface management: returns devices, vulnerabilities, identities and settings
    (keystone/asm/vocabulary.Inventory) instead of pass/fail checks. Baselines turn the data into findings."""

    category: str = ""  # rmm | edr | vuln | mdm | identity | posture (several for multi-purpose sources)
    categories: tuple[str, ...] = ()
    host_field: str | None = None  # self-hosted server field: stored credentials are bound to it (SC-SSRF-003)
    mapping_note: str = ""  # how the field mapping was verified, shown on the integration

    def collect(self, config: dict, secrets: dict, preview: bool = False):  # pragma: no cover - interface
        """preview=True (Test connection): read only the first page of each endpoint."""
        raise NotImplementedError

    needs_session: bool = False  # sources inside Keystone (its own agents) read the database: they implement collect_in
    pulls_alerts: bool = False  # can also bring the tool's alerts into the Alert inbox (when the integration turns it on)

    def fetch_alerts(self, config: dict, secrets: dict, since) -> list[dict]:  # pragma: no cover - interface
        """Alerts raised since `since`: dicts with external_id, title, severity, category, host, account, description,
        link and occurred_at. Read-only."""
        raise NotImplementedError

    def collect_in(self, session, config: dict, secrets: dict, preview: bool = False):  # pragma: no cover - interface
        raise NotImplementedError

    def assess(self, inventory) -> list[Outcome]:
        """Pass/fail control checks worked out from what a full run collected (no extra calls). Sources with
        `checks` override this; a check whose data is missing is "unknown", never a pass."""
        return []

    def describe(self) -> dict:
        return {**super().describe(), "inventory": True, "categories": list(self.categories or (self.category,)), "mapping_note": self.mapping_note}
