"""SCIM 2.0 Users: what an identity provider may do to Keystone accounts.

Rules (the identity provider is trusted less than an administrator):
- One bearer token per identity provider, created by an administrator, stored as a SHA-256 hash, shown once, with an
  optional expiry and revocable at any time. Every SCIM change is audited as that token.
- New accounts get the token's basic role (employee or viewer) and sign in with single sign-on only: no password.
  SCIM never changes a role; administrators do that in Keystone.
- Administrator accounts are invisible to SCIM: they can't be listed, changed or deactivated through it, so a
  compromised identity provider can't lock the administrators out (they are the break-glass accounts).
- Deleting deactivates (and ends sessions): accounts are never removed, so their history stays in the audit log.
- Supported: Users list (filter userName/externalId eq), get, create, replace (PUT), patch (replace/add on active,
  displayName, name, emails, userName, externalId), delete. No Groups and no bulk operations.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets as pysecrets
from datetime import timedelta
from types import SimpleNamespace

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from keystone.core import sessions
from keystone.core.auth import SSO_ONLY_MARKER, User
from keystone.core.db import utcnow
from keystone.core.rbac import Role
from keystone.core.services import authorize, get_or_404
from keystone.sso.models import JIT_ROLES

from .models import ScimToken

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCIM_PREFIX = "kscim_"
MAX_PAGE = 200
EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")
FILTER = re.compile(r'^\s*(userName|externalId|emails\.value)\s+eq\s+"([^"]{1,320})"\s*$', re.IGNORECASE)


class ScimError(Exception):
    def __init__(self, status: int, detail: str, scim_type: str | None = None):
        super().__init__(detail)
        self.status, self.detail, self.scim_type = status, detail, scim_type

    def body(self) -> dict:
        out = {"schemas": [ERROR_SCHEMA], "status": str(self.status), "detail": self.detail}
        if self.scim_type:
            out["scimType"] = self.scim_type
        return out


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ---- tokens (administrators) -------------------------------------------------------------------------------------

def create_token(session: Session, actor, label: str, default_role: str = "employee", days: int | None = 365) -> tuple[ScimToken, str]:
    authorize(session, actor, "users.manage")
    if default_role not in JIT_ROLES:
        raise ValueError(f"Provisioned accounts can only get a basic role: {', '.join(JIT_ROLES)}.")
    if days is not None and not 1 <= days <= 3 * 365:
        raise ValueError("Expiry must be between 1 day and 3 years.")
    raw = SCIM_PREFIX + pysecrets.token_urlsafe(32)
    t = ScimToken(token_hash=_hash(raw), label=(label or "Identity provider").strip()[:100], default_role=default_role,
                  expires_at=utcnow() + timedelta(days=days) if days else None)
    session.add(t)
    session.flush()
    return t, raw


def revoke_token(session: Session, actor, token_id: int) -> ScimToken:
    authorize(session, actor, "users.manage")
    t = get_or_404(session, ScimToken, token_id)
    t.revoked_at = t.revoked_at or utcnow()
    session.flush()
    return t


def tokens(session: Session, actor) -> list[ScimToken]:
    authorize(session, actor, "users.manage")
    return list(session.scalars(select(ScimToken).order_by(ScimToken.id.desc())))


def check_token(session: Session, header: str | None) -> ScimToken:
    """Resolve 'Authorization: Bearer kscim_…'. Raises ScimError(401) for anything else."""
    if not header or not header.startswith("Bearer ") or len(header) > 300:
        raise ScimError(401, "Bearer token required.")
    raw = header[7:].strip()
    if not raw.startswith(SCIM_PREFIX):
        raise ScimError(401, "Invalid token.")
    digest = _hash(raw)
    t = session.scalar(select(ScimToken).where(ScimToken.token_hash == digest))
    if t is None or not hmac.compare_digest(t.token_hash, digest) or t.revoked_at or (t.expires_at and t.expires_at < utcnow()):
        raise ScimError(401, "Invalid, revoked or expired token.")
    t.last_used_at = utcnow()
    # Audit entries name the token ("scim:<label>"); there's no Keystone user behind a provisioning call.
    session.info["actor"] = SimpleNamespace(id=None, username=f"scim:{t.label}"[:150], role=None, active=True)
    return t


# ---- users -------------------------------------------------------------------------------------------------------------

def _visible(u: User) -> bool:
    return u.role != Role.ADMIN.value


def to_scim(u: User, base: str) -> dict:
    given, _, family = (u.display_name or "").partition(" ")
    out = {"schemas": [USER_SCHEMA], "id": str(u.id), "userName": u.username, "displayName": u.display_name, "active": bool(u.active),
           "name": {"formatted": u.display_name, "givenName": given, "familyName": family},
           "meta": {"resourceType": "User", "created": u.created_at.isoformat() + "Z" if u.created_at else None,
                    "lastModified": u.updated_at.isoformat() + "Z" if u.updated_at else None, "location": f"{base}/Users/{u.id}"}}
    if u.email:
        out["emails"] = [{"value": u.email, "type": "work", "primary": True}]
    if u.scim_external_id:
        out["externalId"] = u.scim_external_id
    return out


def _get(session: Session, user_id: str) -> User:
    u = session.get(User, int(user_id)) if user_id.isdigit() else None
    if u is None or not _visible(u):
        raise ScimError(404, "User not found.")
    return u


def get_user(session: Session, user_id: str, base: str) -> dict:
    return to_scim(_get(session, user_id), base)


def list_users(session: Session, base: str, filter_: str | None, start: int = 1, count: int = 100) -> dict:
    q = select(User).where(User.role != Role.ADMIN.value)
    if filter_:
        m = FILTER.match(filter_)
        if not m:
            raise ScimError(400, "Only filters of the form: userName eq \"value\", externalId eq \"value\" or emails.value eq \"value\".", "invalidFilter")
        attr, value = m.group(1).lower(), m.group(2)
        if attr == "username":
            q = q.where(func.lower(User.username) == value.lower())
        elif attr == "externalid":
            q = q.where(User.scim_external_id == value)
        else:
            q = q.where(func.lower(User.email) == value.lower())
    total = session.scalar(select(func.count()).select_from(q.subquery())) or 0
    start, count = max(1, start), max(0, min(count, MAX_PAGE))
    rows = session.scalars(q.order_by(User.id).offset(start - 1).limit(count))
    return {"schemas": [LIST_SCHEMA], "totalResults": total, "startIndex": start, "itemsPerPage": count, "Resources": [to_scim(u, base) for u in rows]}


def _attrs(body: dict) -> dict:
    """Pull the attributes Keystone uses out of a SCIM User body."""
    out: dict = {}
    if "userName" in body:
        out["username"] = str(body["userName"] or "").strip()
    raw_name = body.get("name")
    name: dict = raw_name if isinstance(raw_name, dict) else {}
    display = body.get("displayName") or name.get("formatted") or " ".join(x for x in (name.get("givenName"), name.get("familyName")) if x)
    if display:
        out["display_name"] = str(display).strip()[:200]
    emails = body.get("emails")
    if isinstance(emails, list) and emails:
        primary = next((e for e in emails if isinstance(e, dict) and e.get("primary")), emails[0])
        if isinstance(primary, dict) and primary.get("value"):
            out["email"] = str(primary["value"]).strip().lower()
    if "externalId" in body:
        out["scim_external_id"] = (str(body["externalId"]).strip()[:200] or None) if body["externalId"] is not None else None
    if "active" in body:
        if not isinstance(body["active"], bool):
            raise ScimError(400, "active must be true or false.", "invalidValue")
        out["active"] = body["active"]
    return out


def _apply(session: Session, u: User, attrs: dict) -> None:
    if "username" in attrs:
        un = attrs["username"]
        if not un or len(un) > 150:
            raise ScimError(400, "userName is required (at most 150 characters).", "invalidValue")
        clash = session.scalar(select(User).where(func.lower(User.username) == un.lower(), User.id != (u.id or 0)))
        if clash is not None:
            raise ScimError(409, "userName is already used by another account.", "uniqueness")
        u.username = un
    if "email" in attrs:
        if not EMAIL.match(attrs["email"]):
            raise ScimError(400, "emails.value isn't an email address.", "invalidValue")
        taken = session.scalar(select(User).where(func.lower(User.email) == attrs["email"], User.id != (u.id or 0)))
        if taken is not None:  # single sign-on finds accounts by email, so it must stay unique
            raise ScimError(409, "This email address belongs to another account.", "uniqueness")
        u.email = attrs["email"]
    if "display_name" in attrs:
        u.display_name = attrs["display_name"]
    if "scim_external_id" in attrs:
        u.scim_external_id = attrs["scim_external_id"]
    if "active" in attrs and attrs["active"] != u.active:
        u.active = attrs["active"]
        if not u.active and u.id:
            sessions.destroy_all_for(session, u.id)


def create_user(session: Session, token: ScimToken, body: dict, base: str) -> dict:
    attrs = _attrs(body)
    if not attrs.get("username"):
        raise ScimError(400, "userName is required.", "invalidValue")
    if session.scalar(select(User).where(func.lower(User.username) == attrs["username"].lower())):
        raise ScimError(409, "A user with this userName already exists.", "uniqueness")
    u = User(username=attrs["username"], display_name=attrs.get("display_name") or attrs["username"], role=token.default_role,
             password_hash=SSO_ONLY_MARKER, must_change_password=False, active=attrs.get("active", True), failed_logins=0)
    _apply(session, u, {k: v for k, v in attrs.items() if k != "username"})
    session.add(u)
    session.flush()
    return to_scim(u, base)


def replace_user(session: Session, user_id: str, body: dict, base: str) -> dict:
    u = _get(session, user_id)
    _apply(session, u, _attrs(body))
    session.flush()
    return to_scim(u, base)


PATCH_PATHS = {"active": "active", "displayname": "displayName", "username": "userName", "externalid": "externalId",
               "name.givenname": None, "name.familyname": None, "name.formatted": None, 'emails[type eq "work"].value': "email", "emails": "emails"}


def patch_user(session: Session, user_id: str, body: dict, base: str) -> dict:
    u = _get(session, user_id)
    if PATCH_SCHEMA not in (body.get("schemas") or []) or not isinstance(body.get("Operations"), list):
        raise ScimError(400, "Expected a PatchOp with Operations.", "invalidSyntax")
    for op in body["Operations"][:50]:
        if not isinstance(op, dict):
            raise ScimError(400, "Each operation is an object.", "invalidSyntax")
        kind = str(op.get("op") or "").lower()
        if kind not in ("replace", "add"):
            raise ScimError(400, "Only replace and add operations are supported.", "invalidSyntax")
        path, value = op.get("path"), op.get("value")
        if path is None:  # Entra sends {"op":"replace","value":{"active":false}}
            if not isinstance(value, dict):
                raise ScimError(400, "A replace without a path needs an object value.", "invalidValue")
            body_like = dict(value)
        else:
            key = str(path).strip().lower()
            if key not in PATCH_PATHS:
                raise ScimError(400, f"Unsupported path {path}.", "invalidPath")
            if key == "active" and isinstance(value, str):  # some providers send "False"
                value = value.strip().lower() == "true"
            if key.startswith("name."):
                part = key.split(".", 1)[1]
                given, _, family = (u.display_name or "").partition(" ")
                body_like = {"displayName": " ".join(x for x in ((value if part == "givenname" else given), (value if part == "familyname" else family)) if x)
                             if part != "formatted" else value}
            elif PATCH_PATHS[key] == "email":
                body_like = {"emails": [{"value": value, "primary": True}]}
            else:
                body_like = {PATCH_PATHS[key]: value}
        _apply(session, u, _attrs(body_like))
    session.flush()
    return to_scim(u, base)


def delete_user(session: Session, user_id: str) -> None:
    u = _get(session, user_id)
    _apply(session, u, {"active": False})
    session.flush()


def service_provider_config(base: str) -> dict:
    return {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"], "documentationUri": None,
            "patch": {"supported": True}, "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": MAX_PAGE}, "changePassword": {"supported": False}, "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer token", "description": "Token created under Settings > Provisioning", "primary": True}],
            "meta": {"resourceType": "ServiceProviderConfig", "location": f"{base}/ServiceProviderConfig"}}

