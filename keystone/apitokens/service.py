"""Personal API tokens.

- A token acts as its owner, with the owner's current permissions (checked on every request, like a session), so
  it stops working when the account is deactivated or expires, or its role loses a permission.
- Scope "read" allows only GET and HEAD; "write" allows everything the owner may do.
- Never usable for account and security administration: signing in and passwords, tokens themselves, users, single
  sign-on, provisioning and other settings (BLOCKED_PREFIXES). Those need a signed-in browser session.
- Stored as a SHA-256 hash; shown once; expire within a year; revocable by the owner or a user administrator.
- Bearer requests carry no cookie, so CSRF protection (for cookie sessions) doesn't apply to them.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets as pysecrets
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.db import utcnow
from keystone.core.rbac import PermissionDenied, has_permission
from keystone.core.services import authorize, get_or_404, require_text

from .models import ApiToken

PREFIX = "kst_"
MAX_DAYS = 365
MAX_PER_USER = 10
READ_METHODS = {"GET", "HEAD"}
BLOCKED_PREFIXES = ("/api/auth/", "/api/tokens", "/api/users", "/api/settings/", "/api/scim/")


class TokenRejected(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def create(session: Session, actor, name: str, scope: str = "read", days: int = 90) -> tuple[ApiToken, str]:
    authorize(session, actor, "read")  # staff only: employees use the portal
    if actor.must_change_password:
        raise ValueError("Change your password first.")
    if scope not in ("read", "write"):
        raise ValueError("Scope is read or write.")
    if not 1 <= days <= MAX_DAYS:
        raise ValueError(f"Tokens expire within {MAX_DAYS} days.")
    active = [t for t in session.scalars(select(ApiToken).where(ApiToken.user_id == actor.id, ApiToken.revoked_at.is_(None))) if t.expires_at > utcnow()]
    if len(active) >= MAX_PER_USER:
        raise ValueError(f"You have {MAX_PER_USER} active tokens; revoke one first.")
    raw = PREFIX + pysecrets.token_urlsafe(32)
    t = ApiToken(user_id=actor.id, name=require_text(name, "Name")[:100], token_hash=_hash(raw), scope=scope, expires_at=utcnow() + timedelta(days=days))
    session.add(t)
    session.flush()
    return t, raw


def tokens(session: Session, actor, everyone: bool = False) -> list[ApiToken]:
    authorize(session, actor, "users.manage" if everyone else "read")
    q = select(ApiToken).order_by(ApiToken.id.desc())
    if not everyone:
        q = q.where(ApiToken.user_id == actor.id)
    return list(session.scalars(q))


def revoke(session: Session, actor, token_id: int) -> ApiToken:
    authorize(session, actor, "read")
    t = get_or_404(session, ApiToken, token_id)
    if t.user_id != actor.id and not has_permission(actor, "users.manage"):
        raise PermissionDenied("You can only revoke your own tokens.")
    t.revoked_at = t.revoked_at or utcnow()
    session.flush()
    return t


def resolve(session: Session, raw: str, method: str, path: str, ip: str | None) -> ApiToken:
    """Check a bearer token for this request. Raises TokenRejected (401 or 403)."""
    if not raw.startswith(PREFIX) or len(raw) > 200:
        raise TokenRejected(401, "Invalid API token.")
    digest = _hash(raw)
    t = session.scalar(select(ApiToken).where(ApiToken.token_hash == digest))
    if t is None or not hmac.compare_digest(t.token_hash, digest) or t.revoked_at or t.expires_at <= utcnow():
        raise TokenRejected(401, "Invalid, revoked or expired API token.")
    if any(path.startswith(p) for p in BLOCKED_PREFIXES):
        raise TokenRejected(403, "API tokens can't be used for account and security administration; sign in instead.")
    if t.scope == "read" and method not in READ_METHODS:
        raise TokenRejected(403, "This token is read-only.")
    t.last_used_at, t.last_used_ip = utcnow(), (ip or "")[:64] or None
    return t
