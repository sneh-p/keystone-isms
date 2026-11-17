"""Request dependencies: database session, signed-in user, permissions, CSRF."""

from __future__ import annotations

from typing import Iterator

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from keystone.core import db as dbmod
from keystone.core import sessions
from keystone.core.auth import User, expired as auth_expired
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


def _bearer_user_id(request: Request, db: Session) -> int | None:
    """A personal API token in "Authorization: Bearer kst_…" (keystone/apitokens). Returns its owner's id, None when
    the request has no API token (then the cookie session applies), or raises 401/403."""
    from keystone.apitokens import service as tokens

    auth = request.headers.get("authorization") or ""
    if not auth.startswith("Bearer " + tokens.PREFIX):
        return None
    try:
        t = tokens.resolve(db, auth[7:].strip(), request.method, request.url.path, request.client.host if request.client else None)
    except tokens.TokenRejected as e:
        raise HTTPException(e.status, e.detail) from None
    request.state.api_token_id = t.id
    return t.user_id


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """The signed-in user, from an API token or else the browser session (with its CSRF check)."""
    uid = _bearer_user_id(request, db)
    if uid is None:
        uid = current_session(request, db).user_id
    user = db.get(User, uid)
    if user is None or not user.active:
        raise HTTPException(401, "Account disabled.")
    if auth_expired(user):  # checked on every request, so a session can't outlive the account
        raise HTTPException(401, "Account expired.")
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
