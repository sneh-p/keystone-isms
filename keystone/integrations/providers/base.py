from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Outcome:
    key: str
    result: str  # pass | fail | error | unknown
    summary: str
    details: dict[str, Any] = field(default_factory=dict)


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

    def run(self, config: dict, secrets: dict, session=None) -> list[Outcome]:  # pragma: no cover - interface
        raise NotImplementedError

    def check(self, key: str) -> CheckDef:
        return next(c for c in self.checks if c.key == key)

    def describe(self) -> dict:
        return {
            "key": self.key, "name": self.name, "description": self.description,
            "fields": [f.__dict__ for f in self.fields],
            "checks": [{"key": c.key, "title": c.title, "controls": list(c.controls)} for c in self.checks],
            "setup": [st.__dict__ for st in self.setup],
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

    def describe(self) -> dict:
        return {**super().describe(), "inventory": True, "categories": list(self.categories or (self.category,)), "mapping_note": self.mapping_note}
