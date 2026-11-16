"""Explicit output shaping: only listed fields leave the API (no accidental leaks)."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, Iterable


def ser(obj, fields: Iterable[str], **extra) -> dict[str, Any]:
    out = {f: getattr(obj, f) for f in fields}
    if hasattr(obj, "ref") and "ref" not in out:
        out["ref"] = obj.ref
    out.update(extra)
    return out


def iso(v: date | datetime | None) -> str | None:
    return v.isoformat() if v else None
