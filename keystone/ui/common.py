"""Shared Streamlit helpers. Pages stay thin: they call services and render results."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import date, datetime, timedelta
from typing import Any, Iterable

import streamlit as st

from keystone.core import db
from keystone.core.auth import User
from keystone.core.rbac import PermissionDenied, has_permission
from keystone.core.settings import get_settings

CALIBRATION_NOTE = "Values are calibration starting points from config files. Review them before relying on them."


def init_db_once() -> None:
    if not st.session_state.get("_db_ready"):
        db.configure()
        db.create_all()
        st.session_state["_db_ready"] = True


def current_user() -> User | None:
    uid = st.session_state.get("uid")
    if uid is None:
        return None
    with db.session_scope() as s:
        user = s.get(User, uid)
        if user is None or not user.active:
            logout()
            return None
        s.expunge(user)
        return user


def touch_session() -> bool:
    """Return False (and log out) when the session has been idle too long."""
    now = datetime.now()
    last = st.session_state.get("last_seen")
    if last and now - last > timedelta(minutes=get_settings().session_timeout_minutes):
        logout()
        st.session_state["flash"] = ("warning", "Signed out after inactivity.")
        return False
    st.session_state["last_seen"] = now
    return True


def logout() -> None:
    for key in ("uid", "last_seen"):
        st.session_state.pop(key, None)


@contextmanager
def session():
    """DB session bound to the signed-in user. Errors are shown, not raised."""
    user = current_user()
    with db.session_scope(user) as s:
        yield s


def guard(permission: str = "read") -> User:
    """Call at the top of every page."""
    user = current_user()
    if user is None or not has_permission(user, permission):
        st.error("You do not have access to this page.")
        st.stop()
    return user


def can(permission: str) -> bool:
    user = current_user()
    return user is not None and has_permission(user, permission)


def run_action(fn, *args, success: str | None = None, **kwargs) -> Any:
    """Run a service call in its own transaction; show validation/permission errors nicely."""
    try:
        with session() as s:
            result = fn(s, current_user(), *args, **kwargs)
        if success:
            st.session_state["flash"] = ("success", success)
        return result if result is not None else True
    except PermissionDenied as e:
        st.error(f"Not allowed: {e}")
    except (ValueError, LookupError) as e:
        st.error(str(e))
    return None


def show_flash() -> None:
    msg = st.session_state.pop("flash", None)
    if msg:
        getattr(st, msg[0])(msg[1])


def user_options(s) -> dict[int | None, str]:
    from keystone.core.auth import list_users

    return {None: "(unassigned)", **{u.id: u.display_name for u in list_users(s, active_only=True)}}


def select_user(label: str, options: dict, current: int | None, key: str) -> int | None:
    keys = list(options)
    idx = keys.index(current) if current in keys else 0
    return st.selectbox(label, keys, index=idx, format_func=lambda k: options[k], key=key)


def fmt_date(value: date | datetime | None) -> str:
    if value is None:
        return "—"
    return value.strftime("%Y-%m-%d %H:%M" if isinstance(value, datetime) else "%Y-%m-%d")


def tri(value: bool | None, yes: str = "Yes", no: str = "No", unknown: str = "Unknown") -> str:
    return unknown if value is None else (yes if value else no)


def table(rows: Iterable[dict], **kwargs) -> None:
    rows = list(rows)
    if not rows:
        st.info("Nothing to show yet.")
        return
    st.dataframe(rows, use_container_width=True, hide_index=True, **kwargs)


LEVEL_COLOURS = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", None: "⚪"}


def badge(level: str | None) -> str:
    return f"{LEVEL_COLOURS.get(level, '⚪')} {level or 'Unknown'}"
