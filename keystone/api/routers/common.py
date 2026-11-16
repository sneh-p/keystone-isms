"""Shared bits for routers."""

import math
from datetime import date

import annotated_types
from pydantic import BaseModel, ConfigDict, model_validator

# SC-VAL-002: defaults for every request body. A field that needs more text declares its own max_length.
MAX_STR = 20_000
MAX_ITEMS = 1_000
MAX_KEYS = 200
MAX_DEPTH = 8
MAX_ABS_NUMBER = 1e15


def _check_bounds(value, depth: int = 0, str_limit: int | None = MAX_STR) -> None:
    if depth > MAX_DEPTH:
        raise ValueError("Request is nested too deeply.")
    if isinstance(value, str):
        if str_limit is not None and len(value) > str_limit:
            raise ValueError(f"A text value is longer than {str_limit} characters.")
    elif isinstance(value, bool) or value is None:
        return
    elif isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("Numbers must be finite.")
        if abs(value) > MAX_ABS_NUMBER:
            raise ValueError("A number is out of range.")
    elif isinstance(value, dict):
        if len(value) > MAX_KEYS:
            raise ValueError(f"An object has more than {MAX_KEYS} keys.")
        for k, v in value.items():
            _check_bounds(k, depth + 1, 200)
            _check_bounds(v, depth + 1)
    elif isinstance(value, (list, tuple)):
        if len(value) > MAX_ITEMS:
            raise ValueError(f"A list has more than {MAX_ITEMS} items.")
        for v in value:
            _check_bounds(v, depth + 1)


class In(BaseModel):
    """Request bodies: unknown fields are rejected (no mass assignment, SC-VAL-001/SC-AUTHZ-004) and every value
    is bounded (SC-VAL-002): strings, list lengths, object sizes, nesting depth and number magnitude."""

    model_config = ConfigDict(extra="forbid", str_max_length=MAX_STR)

    @model_validator(mode="before")
    @classmethod
    def _bounded(cls, data):
        if not isinstance(data, dict):
            return data
        if len(data) > MAX_KEYS:
            raise ValueError("Too many fields.")
        for key, value in data.items():
            field = cls.model_fields.get(key)
            own = next((m.max_length for m in (field.metadata if field else []) if isinstance(m, annotated_types.MaxLen)), None)
            _check_bounds(value, 1, own if (own and isinstance(value, str)) else MAX_STR)
        return data


def public_link(path: str) -> dict:
    """A link to hand out: the path (the browser adds its own origin) and, if KEYSTONE_PUBLIC_URL is set, the full
    URL. Never built from the request's Host header. Secrets go after '#', which browsers never send to servers."""
    from keystone.core.settings import get_settings

    base = get_settings().public_url
    return {"path": path, "url": f"{base}{path}" if base else None}


def people_names(db) -> dict[int | None, str]:  # keyed lookups by optional user ids
    from keystone.core.auth import list_users

    return {u.id: u.display_name for u in list_users(db)}


def xlsx_response(data: bytes, filename: str):
    from fastapi.responses import Response

    return Response(data, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def docx_response(data: bytes, filename: str):
    from fastapi.responses import Response

    return Response(data, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


__all__ = ["In", "people_names", "xlsx_response", "docx_response", "date"]
