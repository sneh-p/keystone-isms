"""Helpers shared by module services."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, Iterable, TypeVar

from sqlalchemy.orm import Session


_T = TypeVar("_T")


class NotFound(LookupError):
    pass


def get_or_404(session: Session, model: type[_T], obj_id: int) -> _T:
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


BULK_MAX = 500


def bulk_targets(session: Session, model, ids: Iterable[int]) -> list:
    """Load every record a bulk change names, or refuse the whole change (no partial updates)."""
    from sqlalchemy import select

    wanted = set(ids)
    if not wanted:
        raise ValueError("Select at least one record.")
    if len(wanted) > BULK_MAX:
        raise ValueError(f"Change at most {BULK_MAX} records at a time.")
    found = list(session.scalars(select(model).where(model.id.in_(wanted)).order_by(model.id)))
    if len(found) != len(wanted):
        raise NotFound(f"{len(wanted) - len(found)} of the selected records no longer exist")
    return found


def require_active_user(session: Session, user_id: int | None) -> None:
    """Owners and assignees must be existing, active users."""
    if user_id is None:
        return
    from .auth import User

    u = session.get(User, user_id)
    if u is None or not u.active:
        raise ValueError("Choose an active user.")
