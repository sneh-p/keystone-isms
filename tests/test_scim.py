"""SCIM 2.0 provisioning: token handling, the Entra/Okta request shapes, and what SCIM may never do."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from keystone.core.audit import AuditLog
from keystone.core.auth import User
from keystone.core.db import utcnow

from .conftest import PASSWORD, api_login

SCIM = "application/scim+json"


@pytest.fixture
def token(api, ready_users):
    api_login(api, "admin")
    r = api.post("/api/settings/scim", json={"label": "Entra", "default_role": "employee", "days": 30})
    assert r.status_code == 200
    raw = r.json()["token"]
    assert raw.startswith("kscim_") and "token" not in api.get("/api/settings/scim").json()["tokens"][0]  # shown once
    api.post("/api/auth/logout")
    api.cookies.clear()
    api.headers.pop("X-CSRF-Token", None)
    return raw


def h(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}", "Content-Type": SCIM}


def test_token_is_required_and_checked(api, token, db):
    assert api.get("/api/scim/v2/Users").status_code == 401
    assert api.get("/api/scim/v2/Users", headers={"Authorization": "Bearer kscim_wrong"}).status_code == 401
    assert api.get("/api/scim/v2/Users", headers={"Authorization": "Basic abc"}).status_code == 401
    r = api.get("/api/scim/v2/ServiceProviderConfig", headers=h(token))
    assert r.status_code == 200 and r.headers["content-type"].startswith(SCIM) and r.json()["patch"]["supported"] is True
    from keystone.scim.models import ScimToken

    with db.session_scope() as s:
        t = s.scalars(select(ScimToken)).one()
        assert token not in t.token_hash and len(t.token_hash) == 64 and t.last_used_at
        t.expires_at = utcnow() - timedelta(seconds=1)
    assert api.get("/api/scim/v2/Users", headers=h(token)).status_code == 401


def test_entra_style_provisioning_lifecycle(api, token, db, ready_users):
    # 1. Entra looks the user up by userName, finds nothing, creates them
    r = api.get('/api/scim/v2/Users?filter=userName eq "jo.rivera@alpine.example"', headers=h(token))
    assert r.json()["totalResults"] == 0
    body = {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "jo.rivera@alpine.example", "externalId": "aad-123", "active": True,
            "displayName": "Jo Rivera", "emails": [{"primary": True, "type": "work", "value": "Jo.Rivera@alpine.example"}], "roles": [{"value": "admin"}]}
    r = api.post("/api/scim/v2/Users", json=body, headers=h(token))
    assert r.status_code == 201, r.text
    uid = r.json()["id"]
    assert r.json()["emails"][0]["value"] == "jo.rivera@alpine.example" and r.json()["externalId"] == "aad-123"
    with db.session_scope() as s:
        u = s.get(User, int(uid))
        assert u.role == "employee" and u.password_hash == "!sso-only"  # basic role; SSO only; "roles" ignored
    assert api.post("/api/scim/v2/Users", json=body, headers=h(token)).status_code == 409
    # 2. attribute change and Entra's deactivation shape
    patch = {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "Replace", "path": "displayName", "value": "Jo Rivera-Smith"}]}
    assert api.patch(f"/api/scim/v2/Users/{uid}", json=patch, headers=h(token)).json()["displayName"] == "Jo Rivera-Smith"
    patch = {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "Replace", "path": "active", "value": "False"}]}
    assert api.patch(f"/api/scim/v2/Users/{uid}", json=patch, headers=h(token)).json()["active"] is False
    # Okta's shape: replace without a path
    patch = {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "value": {"active": True}}]}
    assert api.patch(f"/api/scim/v2/Users/{uid}", json=patch, headers=h(token)).json()["active"] is True
    # 3. delete deactivates; the account (and its history) stays
    assert api.delete(f"/api/scim/v2/Users/{uid}", headers=h(token)).status_code == 204
    with db.session_scope() as s:
        assert s.get(User, int(uid)).active is False
        changes = set(s.scalars(select(AuditLog.actor_name).where(AuditLog.entity_type == "User", AuditLog.entity_id == int(uid), AuditLog.action.in_(("create", "update")))))
        assert changes == {"scim:Entra"}  # every account change is attributed to the token
    # the account has no password: password sign-in is refused
    assert api.post("/api/auth/login", json={"username": "jo.rivera@alpine.example", "password": PASSWORD}).status_code == 401


def test_scim_cannot_touch_administrators_or_roles(api, token, db, ready_users):
    admin_id = ready_users["admin"].id
    assert api.get(f"/api/scim/v2/Users/{admin_id}", headers=h(token)).status_code == 404
    assert api.get('/api/scim/v2/Users?filter=userName eq "admin"', headers=h(token)).json()["totalResults"] == 0
    patch = {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "active", "value": False}]}
    assert api.patch(f"/api/scim/v2/Users/{admin_id}", json=patch, headers=h(token)).status_code == 404
    assert api.delete(f"/api/scim/v2/Users/{admin_id}", headers=h(token)).status_code == 404
    mgr = ready_users["isms_manager"]
    r = api.put(f"/api/scim/v2/Users/{mgr.id}", json={"userName": mgr.username, "displayName": "Renamed", "roles": [{"value": "admin"}]}, headers=h(token))
    assert r.status_code == 200
    with db.session_scope() as s:
        assert s.get(User, admin_id).active is True and s.get(User, mgr.id).role == "isms_manager"


def test_scim_input_validation(api, token, ready_users):
    assert api.get('/api/scim/v2/Users?filter=name sw "a"', headers=h(token)).status_code == 400
    assert api.post("/api/scim/v2/Users", content=b"not json", headers=h(token)).status_code == 400
    assert api.post("/api/scim/v2/Users", json={"displayName": "No user name"}, headers=h(token)).status_code == 400
    taken = ready_users["viewer"].email
    if taken:
        assert api.post("/api/scim/v2/Users", json={"userName": "new.person", "emails": [{"value": taken}]}, headers=h(token)).status_code == 409
    bad = {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "remove", "path": "active"}]}
    uid = api.post("/api/scim/v2/Users", json={"userName": "p.q@alpine.example"}, headers=h(token)).json()["id"]
    assert api.patch(f"/api/scim/v2/Users/{uid}", json=bad, headers=h(token)).status_code == 400
    assert api.post("/api/scim/v2/Users", content=b"{" + b" " * (300 * 1024) + b"}", headers=h(token)).status_code == 413


def test_token_management_is_admin_only(api, ready_users):
    api_login(api, ready_users["isms_manager"].username)
    assert api.post("/api/settings/scim", json={"label": "x"}).status_code == 403
    api.post("/api/auth/logout")
    api_login(api, "admin")
    assert api.post("/api/settings/scim", json={"label": "x", "default_role": "admin"}).status_code == 400
    t = api.post("/api/settings/scim", json={"label": "Okta"}).json()
    assert api.post(f"/api/settings/scim/{t['id']}/revoke").json()["revoked_at"]
    api.cookies.clear()
    api.headers.pop("X-CSRF-Token", None)
    assert api.get("/api/scim/v2/Users", headers=h(t["token"])).status_code == 401
