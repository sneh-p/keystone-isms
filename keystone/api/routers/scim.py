"""SCIM 2.0 endpoints for identity providers (bearer token, no session), and token management for administrators."""

import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.core.settings import get_settings
from keystone.scim import service as scim
from keystone.trust.service import rate_limit

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(tags=["scim"])
MEDIA = "application/scim+json"
MAX_BODY = 256 * 1024


def _base(request: Request) -> str:
    return f"{get_settings().public_url}/api/scim/v2"


def _ok(body, status: int = 200) -> JSONResponse:
    return JSONResponse(body, status_code=status, media_type=MEDIA)


def _err(e: scim.ScimError) -> JSONResponse:
    return JSONResponse(e.body(), status_code=e.status, media_type=MEDIA)


async def _json(request: Request) -> dict:
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise scim.ScimError(413, "Request too large.")
    try:
        body = json.loads(raw or b"{}")
    except ValueError:
        raise scim.ScimError(400, "Body isn't JSON.", "invalidSyntax") from None
    if not isinstance(body, dict):
        raise scim.ScimError(400, "Body must be an object.", "invalidSyntax")
    return body


def _guard(request: Request, db: Session):
    ip = request.client.host if request.client else "?"
    try:
        rate_limit(f"scim:{ip}", limit=6000, window=3600)
    except PermissionError:
        raise scim.ScimError(429, "Too many requests.") from None
    return scim.check_token(db, request.headers.get("authorization"))


@router.get("/scim/v2/ServiceProviderConfig")
def provider_config(request: Request, db: Session = Depends(get_db)):
    try:
        _guard(request, db)
    except scim.ScimError as e:
        return _err(e)
    return _ok(scim.service_provider_config(_base(request)))


@router.get("/scim/v2/Users")
def list_users(request: Request, db: Session = Depends(get_db)):
    try:
        _guard(request, db)
        q = request.query_params
        start = int(q.get("startIndex", "1")) if q.get("startIndex", "1").isdigit() else 1
        count = int(q.get("count", "100")) if q.get("count", "100").isdigit() else 100
        return _ok(scim.list_users(db, _base(request), q.get("filter"), start, count))
    except scim.ScimError as e:
        return _err(e)


@router.get("/scim/v2/Users/{uid}")
def get_user(uid: str, request: Request, db: Session = Depends(get_db)):
    try:
        _guard(request, db)
        return _ok(scim.get_user(db, uid, _base(request)))
    except scim.ScimError as e:
        return _err(e)


@router.post("/scim/v2/Users")
async def create_user(request: Request, db: Session = Depends(get_db)):
    try:
        token = _guard(request, db)
        return _ok(scim.create_user(db, token, await _json(request), _base(request)), 201)
    except scim.ScimError as e:
        db.rollback()
        return _err(e)


@router.put("/scim/v2/Users/{uid}")
async def replace_user(uid: str, request: Request, db: Session = Depends(get_db)):
    try:
        _guard(request, db)
        return _ok(scim.replace_user(db, uid, await _json(request), _base(request)))
    except scim.ScimError as e:
        db.rollback()
        return _err(e)


@router.patch("/scim/v2/Users/{uid}")
async def patch_user(uid: str, request: Request, db: Session = Depends(get_db)):
    try:
        _guard(request, db)
        return _ok(scim.patch_user(db, uid, await _json(request), _base(request)))
    except scim.ScimError as e:
        db.rollback()
        return _err(e)


@router.delete("/scim/v2/Users/{uid}")
def delete_user(uid: str, request: Request, db: Session = Depends(get_db)):
    try:
        _guard(request, db)
        scim.delete_user(db, uid)
    except scim.ScimError as e:
        db.rollback()
        return _err(e)
    return Response(status_code=204)


# ---- tokens (administrators) -------------------------------------------------------------------------------------

TOKEN = ("id", "label", "default_role", "created_at", "expires_at", "revoked_at", "last_used_at")


@router.get("/settings/scim")
def tokens(user=Depends(perm("users.manage")), db: Session = Depends(get_db)):
    base = get_settings().public_url
    return {"base_url": f"{base}/api/scim/v2" if base else None, "tokens": [ser(t, TOKEN) for t in scim.tokens(db, user)]}


class TokenIn(In):
    label: str = Field(min_length=1, max_length=100)
    default_role: str = Field(default="employee", max_length=30)
    days: int | None = Field(default=365, ge=1, le=3 * 365)


@router.post("/settings/scim")
def create_token(body: TokenIn, user=Depends(perm("users.manage")), db: Session = Depends(get_db)):
    t, raw = scim.create_token(db, user, body.label, body.default_role, body.days)
    return {**ser(t, TOKEN), "token": raw}  # shown once


@router.post("/settings/scim/{tid}/revoke")
def revoke_token(tid: int, user=Depends(perm("users.manage")), db: Session = Depends(get_db)):
    return ser(scim.revoke_token(db, user, tid), TOKEN)
