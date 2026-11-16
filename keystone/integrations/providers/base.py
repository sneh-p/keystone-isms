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


class Provider:
    key: str = ""
    name: str = ""
    description: str = ""
    fields: tuple[ConfigField, ...] = ()
    checks: tuple[CheckDef, ...] = ()

    def run(self, config: dict, secrets: dict, session=None) -> list[Outcome]:  # pragma: no cover - interface
        raise NotImplementedError

    def check(self, key: str) -> CheckDef:
        return next(c for c in self.checks if c.key == key)

    def describe(self) -> dict:
        return {
            "key": self.key, "name": self.name, "description": self.description,
            "fields": [f.__dict__ for f in self.fields],
            "checks": [{"key": c.key, "title": c.title, "controls": list(c.controls)} for c in self.checks],
        }
