"""Validation of collected.json against schemas/collected.schema.json."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match

from .paths import SCHEMA_PATH


class CollectedFileInvalid(ValueError):
    """Raised when a collected.json document does not match the schema."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("collected.json failed schema validation:\n- " + "\n- ".join(errors))


@lru_cache(maxsize=1)
def _validator(schema_path: str = str(SCHEMA_PATH)) -> Draft202012Validator:
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def validation_errors(doc: Any) -> list[str]:
    """Return human-readable validation errors (empty list when valid)."""
    errors = sorted(_validator().iter_errors(doc), key=lambda e: list(e.absolute_path))
    out = []
    for err in errors[:50]:
        # oneOf (data-or-null) wraps the real problem; report the most specific one.
        leaf = best_match([err]) or err
        where = "/".join(str(p) for p in leaf.absolute_path) or "(root)"
        out.append(f"{where}: {_short(leaf)}")
    return out


def _short(err) -> str:
    """Error text without echoing large data blobs back into logs or the UI."""
    if err.validator == "additionalProperties":
        return err.message[:300]
    if err.validator in ("enum", "const", "type", "required", "pattern"):
        return f"{err.validator} check failed: {err.message[:200]}"
    return f"{err.validator} check failed"


def validate_collected(doc: Any) -> None:
    errors = validation_errors(doc)
    if errors:
        raise CollectedFileInvalid(errors)
