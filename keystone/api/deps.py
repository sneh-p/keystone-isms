"""Request dependencies: database session, signed-in user, permissions, CSRF."""

from __future__ import annotations

from typing import Iterator

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from keystone.core import db as dbmod
from keystone.core import sessions
from keystone.core.auth import User
from keystone.core.rbac import has_permission

COOKIE = "ks_session"
CSRF_HEADER = "X-CSRF-Token"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


def get_db() -> Iterator[Session]:
    with dbmod.session_scope() as s:
        yield s


def current_session(request: Request, db: Session = Depends(get_db)) -> sessions.WebSession:
    ws = sessions.resolve(db, request.cookies.get(COOKIE))
    if ws is None:
        raise HTTPException(401, "Not signed in or session expired.")
    if request.method in UNSAFE and not sessions.csrf_ok(ws, request.headers.get(CSRF_HEADER)):
        raise HTTPException(403, "Missing or invalid CSRF token.")
    return ws


def current_user(ws: sessions.WebSession = Depends(current_session), db: Session = Depends(get_db)) -> User:
    user = db.get(User, ws.user_id)
    if user is None or not user.active:
        raise HTTPException(401, "Account disabled.")
    db.info["actor"] = user
    return user


def perm(permission: str):
    """Dependency that requires a permission. Recorded on the route for the authz test."""

    def checker(user: User = Depends(current_user)) -> User:
        if not has_permission(user, permission):
            raise HTTPException(403, f"Your role does not allow {permission}.")
        if user.must_change_password and permission != "read":
            raise HTTPException(403, "Change your password first.")
        return user

    checker.permission = permission  # type: ignore[attr-defined]
    return checker


Reader = Depends(perm("read"))
