"""Helpers shared by module services."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, Iterable

from sqlalchemy.orm import Session


class NotFound(LookupError):
    pass


def get_or_404(session: Session, model, obj_id: int):
    obj = session.get(model, obj_id)
    if obj is None:
        raise NotFound(f"{model.__name__} {obj_id} not found")
    return obj


def apply_fields(obj, data: dict[str, Any], allowed: Iterable[str]) -> None:
    """Assign only whitelisted fields (prevents mass-assignment of e.g. status or owner)."""
    allowed = set(allowed)
    unknown = set(data) - allowed
    if unknown:
        raise ValueError(f"fields not editable here: {', '.join(sorted(unknown))}")
    for key, value in data.items():
        if isinstance(value, str):
            value = value.strip()
        setattr(obj, key, value)


def require_text(value: str | None, label: str) -> str:
    if not value or not value.strip():
        raise ValueError(f"{label} is required")
    return value.strip()


def today() -> date:
    return datetime.now().date()


def authorize(session: Session, actor, permission: str) -> None:
    """Check the permission and bind the actor to the session, so audit rows and
    created_by always name the person who made the change."""
    from .rbac import require

    require(actor, permission)
    session.info["actor"] = actor
