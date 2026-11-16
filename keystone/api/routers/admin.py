from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core import auth, sessions
from keystone.core.audit import AuditLog, verify_chain
from keystone.core.rbac import ROLE_LABELS, Role
from keystone.core.services import get_or_404

from ..deps import get_db, perm
from ..serialize import ser

router = APIRouter(tags=["admin"])
USER_FIELDS = ("id", "username", "display_name", "email", "role", "active", "must_change_password", "last_login_at", "locked_until", "created_at", "expires_at")


def user_out(u) -> dict:
    return ser(u, USER_FIELDS, sso_linked=bool(u.sso_subject), sso_only=u.password_hash == auth.SSO_ONLY_MARKER)


class UserIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str
    display_name: str
    password: str | None = None  # not needed for SSO-only accounts
    role: str = "viewer"
    email: str | None = None
    expires_at: datetime | None = None
    sso_only: bool = False


class UserPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str | None = None
    active: bool | None = None
    display_name: str | None = None
    email: str | None = None
    expires_at: datetime | None = None


class ResetIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str


def _naive_utc(dt: datetime | None) -> datetime | None:
    """Stored times are naive UTC; accept an aware value from the client and convert it."""
    if dt is None or dt.tzinfo is None:
        return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


@router.get("/people-directory")
def directory(user=Depends(perm("read")), db: Session = Depends(get_db)):
    """Minimal list of active users for owner pickers."""
    return [{"id": u.id, "display_name": u.display_name, "role": u.role} for u in auth.list_users(db, active_only=True)]


@router.get("/roles")
def roles(user=Depends(perm("read"))):
    return [{"value": r.value, "label": ROLE_LABELS[r]} for r in Role]


@router.get("/users")
def list_users(user=Depends(perm("users.manage")), db: Session = Depends(get_db)):
    return [user_out(u) for u in auth.list_users(db)]


@router.post("/users")
def create_user(body: UserIn, user=Depends(perm("users.manage")), db: Session = Depends(get_db)):
    u = auth.create_user(db, user, username=body.username, display_name=body.display_name, password=body.password, role=body.role, email=body.email, expires_at=_naive_utc(body.expires_at), sso_only=body.sso_only)
    return user_out(u)


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserPatch, user=Depends(perm("users.manage")), db: Session = Depends(get_db)):
    target = get_or_404(db, auth.User, user_id)
    fields = body.model_dump(exclude_unset=True)
    if "expires_at" in fields:
        fields["expires_at"] = _naive_utc(fields["expires_at"])
    old_role = target.role
    auth.update_user(db, user, target, **fields)
    # SC-AUTHN-003: sessions end when an account is disabled or its role changes.
    if body.active is False or target.role != old_role:
        sessions.destroy_all_for(db, target.id)
    return user_out(target)


@router.post("/users/{user_id}/reset-password")
def reset_password(user_id: int, body: ResetIn, user=Depends(perm("users.manage")), db: Session = Depends(get_db)):
    target = get_or_404(db, auth.User, user_id)
    auth.admin_reset_password(db, user, target, body.password)
    sessions.destroy_all_for(db, target.id)
    return {"ok": True}


@router.get("/audit-log")
def audit_log(limit: int = Query(200, ge=1, le=5000), entity_type: str | None = None, actor: str | None = None, user=Depends(perm("audit_log.view")), db: Session = Depends(get_db)):
    q = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
    if entity_type:
        q = q.where(AuditLog.entity_type == entity_type)
    if actor:
        q = q.where(AuditLog.actor_name.contains(actor.lower()))
    return [ser(r, ("id", "ts", "actor_name", "action", "entity_type", "entity_id", "summary", "changes")) for r in db.scalars(q)]


@router.get("/audit-log/verify")
def audit_verify(user=Depends(perm("audit_log.view")), db: Session = Depends(get_db)):
    ok, bad = verify_chain(db)
    return {"ok": ok, "first_bad_id": bad}


# ---- single sign-on settings ---------------------------------------------------------------------------

@router.get("/settings/sso")
def sso_settings(user=Depends(perm("users.manage")), db: Session = Depends(get_db)):
    from keystone.sso import service as sso
    from keystone.sso.models import PROVIDERS

    return [sso.view(sso.provider(db, k)) for k in PROVIDERS]


class SsoIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    client_id: str | None = Field(default=None, max_length=200)
    client_secret: str | None = Field(default=None, max_length=1000)  # write-only
    clear_secret: bool | None = None
    tenant_id: str | None = Field(default=None, max_length=36)
    org_domain: str | None = Field(default=None, max_length=253)
    allowed_domains: list[str] | None = Field(default=None, max_length=50)
    jit_enabled: bool | None = None
    jit_role: str | None = None


@router.put("/settings/sso/{kind}")
def update_sso(kind: str, body: SsoIn, user=Depends(perm("users.manage")), db: Session = Depends(get_db)):
    from keystone.sso import service as sso

    return sso.view(sso.update(db, user, kind, **body.model_dump(exclude_unset=True)))


@router.get("/settings/sso-policy")
def sso_policy(user=Depends(perm("users.manage")), db: Session = Depends(get_db)):
    from keystone.sso import service as sso

    return {"required": sso.policy(db).required, "providers_on": sso.enabled_providers(db)}


class SsoPolicyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    required: bool


@router.put("/settings/sso-policy")
def set_sso_policy(body: SsoPolicyIn, user=Depends(perm("users.manage")), db: Session = Depends(get_db)):
    from keystone.sso import service as sso

    return {"required": sso.set_required(db, user, body.required).required, "providers_on": sso.enabled_providers(db)}
