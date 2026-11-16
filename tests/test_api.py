"""API foundation: auth, sessions, CSRF, permission matrix, output shaping."""

import re
from datetime import timedelta

import pytest
from fastapi.routing import APIRoute

from keystone.api.routers import ROUTERS
from keystone.core.rbac import Role, has_permission
from tests.conftest import PASSWORD, api_login

UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
PUBLIC = {"/auth/status", "/auth/bootstrap", "/auth/login", "/public/invite/{token}", "/public/trust/{slug}", "/public/trust/{slug}/requests", "/public/trust/{slug}/access/{token}", "/public/trust/{slug}/access/{token}/nda", "/public/trust/{slug}/documents/{public_id}"}


def all_routes():
    for router in ROUTERS:
        for r in router.routes:
            if isinstance(r, APIRoute):
                yield r


def route_permission(route: APIRoute) -> str | None:
    for dep in route.dependant.dependencies:
        if getattr(dep.call, "permission", None):
            return dep.call.permission
    return None


def concrete(path: str) -> str:
    return "/api" + re.sub(r"\{[^}]+\}", "1", path).replace("{fmt}", "xlsx")


# ---- auth ---------------------------------------------------------------------------------

def test_bootstrap_then_login(api):
    assert api.get("/api/auth/status").json()["needs_bootstrap"] is True
    r = api.post("/api/auth/bootstrap", json={"username": "boss", "display_name": "Boss", "password": PASSWORD})
    assert r.status_code == 200 and r.json()["role"] == "admin"
    assert api.post("/api/auth/bootstrap", json={"username": "x", "display_name": "x", "password": PASSWORD}).status_code == 409
    assert api.get("/api/auth/me").json()["username"] == "boss"


def test_login_cookie_and_logout(api, ready_users):
    r = api.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    assert "password_hash" not in r.text
    api.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    assert api.get("/api/auth/me").status_code == 200
    assert api.post("/api/auth/logout").status_code == 200
    assert api.get("/api/auth/me").status_code == 401


def test_bad_login_generic_and_lockout_persists(api, ready_users):
    for _ in range(5):
        r = api.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
        assert r.status_code == 401 and r.json()["detail"] == "Invalid username or password."
    r = api.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
    assert r.status_code == 401 and "locked" in r.json()["detail"]


def test_extra_fields_rejected(api, ready_users):
    api_login(api, "admin")
    r = api.post("/api/assets", json={"name": "x", "asset_type": "hardware", "created_by_id": 99})
    assert r.status_code == 422


def test_csrf_required_for_writes(api, ready_users):
    api_login(api, "admin")
    token = api.headers.pop("X-CSRF-Token")
    assert api.post("/api/assets", json={"name": "x", "asset_type": "hardware"}).status_code == 403
    api.headers["X-CSRF-Token"] = "not-the-token"
    assert api.post("/api/assets", json={"name": "x", "asset_type": "hardware"}).status_code == 403
    api.headers["X-CSRF-Token"] = token
    assert api.post("/api/assets", json={"name": "x", "asset_type": "hardware"}).status_code == 200


def test_idle_session_expires(api, ready_users, db):
    from keystone.core.sessions import WebSession

    api_login(api, "admin")
    with db.session_scope() as s:
        for ws in s.query(WebSession).all():
            ws.last_seen_at -= timedelta(hours=2)
    assert api.get("/api/auth/me").status_code == 401


def test_password_change_required_blocks_writes(api, users):
    api_login(api, "viewer")
    assert api.get("/api/dashboard").status_code == 200  # reading is fine
    api_login(api, "riskowner")
    r = api.post("/api/assets", json={"name": "x", "asset_type": "hardware"})
    assert r.status_code == 403 and "Change your password" in r.json()["detail"]
    assert api.post("/api/auth/change-password", json={"current": PASSWORD, "new": "Brand-New-Pass-42"}).status_code == 200
    assert api.post("/api/assets", json={"name": "x", "asset_type": "hardware"}).status_code == 200


def test_disabling_user_kills_sessions(api, ready_users):
    from fastapi.testclient import TestClient

    other = TestClient(api.app)
    api_login(other, "viewer")
    api_login(api, "admin")
    assert api.patch(f"/api/users/{ready_users['viewer'].id}", json={"active": False}).status_code == 200
    assert other.get("/api/auth/me").status_code == 401


# ---- permission matrix ------------------------------------------------------------------------

def test_every_write_route_declares_a_permission():
    missing = [f"{m} {r.path}" for r in all_routes() for m in r.methods & UNSAFE if r.path not in PUBLIC | {"/auth/logout", "/auth/change-password"} and route_permission(r) is None]
    assert missing == []


@pytest.mark.parametrize("role", ["viewer", "auditor", "control_owner"])
def test_roles_cannot_call_write_routes_they_lack(api, ready_users, role):
    user = ready_users[role]
    api_login(api, user.username)
    checked = 0
    for r in all_routes():
        p = route_permission(r)
        for m in r.methods & UNSAFE:
            if p is None or has_permission(user, p):
                continue
            resp = api.request(m, concrete(r.path), json={})
            assert resp.status_code == 403, f"{role}: {m} {r.path} -> {resp.status_code}"
            checked += 1
    assert checked > 20


def test_every_route_requires_sign_in(api, ready_users):
    for r in all_routes():
        if r.path in PUBLIC:
            continue
        for m in r.methods:
            resp = api.request(m, concrete(r.path), json={})
            assert resp.status_code == 401, f"{m} {r.path} -> {resp.status_code}"


def test_user_admin_only_and_no_secrets(api, ready_users):
    api_login(api, "ismsmanager")
    assert api.get("/api/users").status_code == 403
    api_login(api, "admin")
    body = api.get("/api/users").text
    assert "argon2" not in body and "password_hash" not in body


# ---- functional smoke on the demo organisation ----------------------------------------------------

@pytest.fixture
def demo_api(api, db):
    from keystone import demo
    from keystone.core import auth

    with db.session_scope() as s:
        admin = auth.create_user(s, None, username="admin", display_name="Admin", password=demo.DEMO_PASSWORD)
    with db.session_scope(admin) as s:
        demo.seed(s, s.get(auth.User, admin.id))
    api_login(api, "admin", demo.DEMO_PASSWORD)
    return api


GETS = [
    "/api/dashboard", "/api/org", "/api/org/parties", "/api/org/roles", "/api/org/objectives", "/api/frameworks", "/api/frameworks/ISO27001_2022/requirements",
    "/api/controls", "/api/controls/1", "/api/evidence", "/api/soa/ISO27001_2022", "/api/assets", "/api/risk-matrix", "/api/risks", "/api/risks/1",
    "/api/vendors", "/api/vendors/1", "/api/questionnaires", "/api/questionnaires/1", "/api/questionnaire-templates", "/api/assessments", "/api/assessments/2",
    "/api/exposure/tenants", "/api/exposure/tenants/1", "/api/exposure/cross-tenant", "/api/exposure/matching", "/api/exposure/remediation",
    "/api/policies", "/api/policies/1", "/api/policies/pending", "/api/incidents", "/api/incidents/1", "/api/nonconformities", "/api/audits", "/api/reviews", "/api/reviews/1",
    "/api/users", "/api/audit-log", "/api/audit-log/verify", "/api/people-directory", "/api/roles", "/api/reports",
]


@pytest.mark.parametrize("path", GETS)
def test_get_endpoints_on_demo(demo_api, path):
    r = demo_api.get(path)
    assert r.status_code == 200, r.text[:300]


@pytest.mark.parametrize("path", ["/api/soa/ISO27001_2022/export.xlsx", "/api/soa/SOC2_TSC_2017/export.docx", "/api/reports/Risk register.xlsx", "/api/exposure/remediation.xlsx", "/api/attachments/1"])
def test_downloads(demo_api, path):
    r = demo_api.get(path)
    assert r.status_code == 200 and len(r.content) > 20 and "attachment" in r.headers["content-disposition"]


def test_write_flow_through_api(demo_api):
    r = demo_api.post("/api/risks", json={"title": "API-created risk", "inherent_likelihood": 4, "inherent_impact": 5, "category": "technology"})
    assert r.status_code == 200 and r.json()["inherent_level"] == "Critical"
    rid = r.json()["id"]
    r = demo_api.post(f"/api/risks/{rid}/fair", json={"inputs": {"tef": [0.5, 1, 2], "vuln": [0.2, 0.3, 0.5], "plm": [1000, 5000, 20000]}, "iterations": 1000})
    assert r.status_code == 200 and r.json()["fair_result"]["ale_mean"] > 0
    assert demo_api.post(f"/api/risks/{rid}/status", json={"status": "treatment"}).status_code == 400  # needs a treatment option
    log = demo_api.get("/api/audit-log?entity_type=Risk").json()
    assert log[0]["actor_name"] == "admin"


def test_service_errors_map_to_http(demo_api):
    assert demo_api.get("/api/risks/9999").status_code == 404
    assert demo_api.post("/api/risks", json={"title": " "}).status_code == 400
    assert demo_api.get("/api/nope").status_code == 404


def test_security_headers(demo_api):
    h = demo_api.get("/api/dashboard").headers
    assert h["x-content-type-options"] == "nosniff" and h["cache-control"] == "no-store" and "default-src 'self'" in h["content-security-policy"]


def test_framing_is_same_origin_by_default(monkeypatch):
    from keystone.api.app import security_headers

    monkeypatch.delenv("KEYSTONE_FRAME_ANCESTORS", raising=False)
    h = security_headers()
    assert "frame-ancestors 'self'" in h["Content-Security-Policy"] and h["X-Frame-Options"] == "SAMEORIGIN"
    monkeypatch.setenv("KEYSTONE_FRAME_ANCESTORS", "https://intranet.example")
    h = security_headers()
    assert "frame-ancestors https://intranet.example;" in h["Content-Security-Policy"] and "X-Frame-Options" not in h
