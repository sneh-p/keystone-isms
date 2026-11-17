"""Personal API tokens: scope, blocked areas, expiry, revocation, the owner's state, and storage."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from keystone.apitokens.models import ApiToken
from keystone.core.auth import User
from keystone.core.db import utcnow

from .conftest import api_login


def _new_token(api, user, scope="read", days=30) -> str:
    api_login(api, user.username)
    r = api.post("/api/tokens", json={"name": "BI export", "scope": scope, "days": days})
    assert r.status_code == 200, r.text
    raw = r.json()["token"]
    api.post("/api/auth/logout")
    api.cookies.clear()
    api.headers.pop("X-CSRF-Token", None)
    return raw


def bearer(raw: str) -> dict:
    return {"Authorization": f"Bearer {raw}"}


def test_read_token(api, ready_users, db):
    raw = _new_token(api, ready_users["isms_manager"])
    assert api.get("/api/risks", headers=bearer(raw)).status_code == 200
    assert api.post("/api/risks", json={"title": "x"}, headers=bearer(raw)).status_code == 403  # read-only
    for path in ("/api/auth/me", "/api/tokens", "/api/users", "/api/settings/sso"):
        assert api.get(path, headers=bearer(raw)).status_code == 403, path  # never for account and security administration
    assert api.get("/api/risks", headers=bearer("kst_wrong")).status_code == 401
    with db.session_scope() as s:
        t = s.scalars(select(ApiToken)).one()
        assert raw not in t.token_hash and t.last_used_at and t.last_used_ip


def test_write_token_acts_as_its_owner_without_csrf(api, ready_users, db):
    owner = ready_users["risk_owner"]
    raw = _new_token(api, owner, scope="write")
    r = api.post("/api/risks", json={"title": "Created by a script", "category": "technology", "owner_id": owner.id}, headers=bearer(raw))
    assert r.status_code == 200, r.text
    assert api.post("/api/vendors", json={"name": "x"}, headers=bearer(raw)).status_code == 403  # the owner's permissions, not more
    from keystone.core.audit import AuditLog

    with db.session_scope() as s:
        assert s.scalars(select(AuditLog.actor_name).where(AuditLog.entity_type == "Risk", AuditLog.action == "create")).first() == owner.username


def test_token_dies_with_revocation_expiry_and_the_account(api, ready_users, db):
    viewer = ready_users["viewer"]
    raw = _new_token(api, viewer)
    with db.session_scope() as s:
        t = s.scalars(select(ApiToken)).one()
        t.expires_at = utcnow() - timedelta(seconds=1)
    assert api.get("/api/risks", headers=bearer(raw)).status_code == 401
    raw2 = _new_token(api, viewer)
    with db.session_scope() as s:
        s.get(User, viewer.id).active = False
    assert api.get("/api/risks", headers=bearer(raw2)).status_code == 401
    with db.session_scope() as s:
        s.get(User, viewer.id).active = True
    assert api.get("/api/risks", headers=bearer(raw2)).status_code == 200
    api_login(api, "admin")
    tid = next(t["id"] for t in api.get("/api/tokens?all=true").json() if t["revoked_at"] is None)
    assert api.post(f"/api/tokens/{tid}/revoke").status_code == 200  # an administrator can revoke anyone's
    api.cookies.clear()
    api.headers.pop("X-CSRF-Token", None)
    assert api.get("/api/risks", headers=bearer(raw2)).status_code == 401


def test_who_can_create_and_see_tokens(api, ready_users):
    api_login(api, ready_users["employee"].username)
    assert api.post("/api/tokens", json={"name": "x"}).status_code == 403  # employees use the portal only
    api.post("/api/auth/logout")
    api_login(api, ready_users["viewer"].username)
    assert api.post("/api/tokens", json={"name": "x", "days": 400}).status_code == 422
    assert api.get("/api/tokens?all=true").status_code == 403
    mine = api.post("/api/tokens", json={"name": "x"}).json()
    api.post("/api/auth/logout")
    api_login(api, ready_users["auditor"].username)
    assert api.post(f"/api/tokens/{mine['id']}/revoke").status_code == 403  # not their token
