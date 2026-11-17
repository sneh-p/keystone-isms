"""API foundation: auth, sessions, CSRF, permission matrix, output shaping."""

import re
from datetime import timedelta

import pytest
from fastapi.routing import APIRoute

from keystone.api.routers import ROUTERS
from keystone.core.rbac import Role, has_permission
from tests.conftest import PASSWORD, api_login

UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
PUBLIC = {"/auth/status", "/auth/bootstrap", "/auth/login", "/public/invite", "/public/trust/{slug}", "/public/trust/{slug}/requests", "/public/trust/{slug}/access", "/public/trust/{slug}/access/nda", "/public/trust/{slug}/documents/{public_id}",
          # Vendor portal (reviewed design, docs/feature-security-designs.md): token in the X-Vendor-Token header.
          "/public/vendor-portal", "/public/vendor-portal/files", "/public/vendor-portal/files/{file_id}",
          # Single sign-on redirects (reviewed design): state, nonce, PKCE and a browser-binding cookie.
          "/auth/oidc/{kind}/start", "/auth/oidc/{kind}/callback",
          # SCIM provisioning (reviewed design, round 3): no session; a hashed bearer token per identity provider,
          # checked in keystone/scim/service.check_token. Unauthenticated calls get 401 (tested in test_scim.py).
          "/scim/v2/ServiceProviderConfig", "/scim/v2/Users", "/scim/v2/Users/{uid}",
          # Configuration agents (reviewed design, configuration baselines): no session. Enrolment needs the
          # organisation's enrolment key; reports need a per-device token (hashed), checked in
          # keystone/configcheck/service.py. Both are rate-limited and size-capped (tested in test_configcheck.py).
          "/agent/v1/enrol", "/agent/v1/report"}


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
    r = api.post("/api/auth/change-password", json={"current": PASSWORD, "new": "Brand-New-Pass-42"})
    assert r.status_code == 200
    api.headers["X-CSRF-Token"] = r.json()["csrf_token"]  # the session was rotated (SC-AUTHN-003)
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


@pytest.mark.parametrize("path", ["/api/soa/ISO27001_2022/export.xlsx", "/api/soa/SOC2_TSC_2017/export.docx", "/api/reports/Risk register.xlsx", "/api/exposure/remediation.xlsx", "/api/attachments/1", "/api/exposure/collector/script", "/api/exposure/collector/tenants-csv"])
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


def test_collector_script_offered_with_hash(demo_api):
    import hashlib

    from keystone.core.settings import PROJECT_ROOT

    on_disk = (PROJECT_ROOT / "collector" / "Invoke-VendorExposureCollector.ps1").read_bytes()
    meta = demo_api.get("/api/exposure/collector").json()
    assert meta["sha256"] == hashlib.sha256(on_disk).hexdigest().upper() and meta["script"].encode() == on_disk
    assert demo_api.get("/api/exposure/collector/script").content == on_disk
    assert demo_api.get("/api/exposure/collector/..%2Fkeystone.db").status_code == 404


def test_unexpected_errors_are_generic_and_docs_are_off(api, ready_users, monkeypatch):
    from fastapi.testclient import TestClient

    from keystone.api import app as app_module
    from keystone.reporting import dashboard as reporting

    def boom(*a, **k):
        raise RuntimeError("SELECT secret FROM internals at /srv/keystone/keystone.db")

    monkeypatch.setattr(reporting, "overview", boom)
    client = TestClient(app_module.create_app(migrate=False), raise_server_exceptions=False)
    api_login(client, "admin")
    r = client.get("/api/dashboard")
    assert r.status_code == 500 and "request_id" in r.json() and "SELECT" not in r.text and "/srv" not in r.text
    assert api.get("/api/docs").status_code == 404 and api.get("/api/openapi.json").status_code == 404
    monkeypatch.setenv("KEYSTONE_API_DOCS", "1")
    assert TestClient(app_module.create_app(migrate=False)).get("/api/openapi.json").status_code == 200


def test_request_bodies_forbid_unknown_fields():
    """SC-VAL-001 / SC-AUTHZ-004: every JSON body model rejects unknown keys (no mass assignment)."""
    from pydantic import BaseModel

    loose = []
    for r in all_routes():
        for param in r.dependant.body_params:
            model = getattr(param.field_info, "annotation", None) or getattr(param, "type_", None)
            if isinstance(model, type) and issubclass(model, BaseModel) and model.model_config.get("extra") != "forbid":
                loose.append(f"{sorted(r.methods)} {r.path}: {model.__name__}")
    assert not loose, "Request models must extend In (extra='forbid'):\n" + "\n".join(loose)
    assert any(r.dependant.body_params for r in all_routes())  # the check actually saw bodies


def test_request_bodies_are_bounded(api, ready_users):
    """SC-VAL-002: oversized or malformed bodies are rejected with 422 before reaching a service."""
    api_login(api, "admin")
    cases = [
        {"title": "x" * 20_001},                                   # default string cap
        {"title": "ok", "description": "x" * 20_001},
        {"title": "ok", "inherent_likelihood": 1e16},               # number magnitude
        {"title": "ok", "inherent_likelihood": float("inf")},
    ]
    for body in cases:
        r = api.post("/api/risks", content=__import__("json").dumps(body, allow_nan=True), headers={"content-type": "application/json"})
        assert r.status_code in (400, 422), (list(body), r.status_code)  # inf can't be echoed back as JSON, so it is a 400
    assert api.get("/api/risks").json()["risks"] == []  # nothing reached the service
    deep: dict = {}
    cur = deep
    for _ in range(12):
        cur["x"] = {}
        cur = cur["x"]
    for values in ({"url": "https://a.example", "extra": deep}, {f"k{i}": "v" for i in range(201)}, {"url": ["x"] * 1001}):
        assert api.post("/api/integrations", json={"provider": "website", "values": values}).status_code == 422
    # Fields that legitimately hold long text keep their own, larger limit.
    assert api.post("/api/ai/policies/1/accept", json={"body": "x" * 30_000}).status_code != 422


def test_employee_is_refused_on_every_staff_read_route(api, users, db):
    """SC-AUTHZ-005: the employee boundary holds for every read route, not just writes."""
    from keystone.core.auth import User

    with db.session_scope() as s:
        s.query(User).filter(User.username == "employee").one().must_change_password = False
    api_login(api, "employee")
    probed = []
    for r in all_routes():
        if "GET" in r.methods and r.path not in PUBLIC and not r.path.startswith(("/auth/", "/portal")):
            resp = api.get(concrete(r.path))
            probed.append(r.path)
            assert resp.status_code == 403, f"{r.path} returned {resp.status_code} to an employee"
    assert len(probed) > 50


def test_password_change_rotates_the_session(api, ready_users):
    """SC-AUTHN-003: the old session ID and CSRF token stop working; a new pair is issued."""
    me = api_login(api, "viewer")
    old_cookie, old_csrf = api.cookies.get("ks_session"), me["csrf_token"]
    other = __import__("fastapi.testclient", fromlist=["TestClient"]).TestClient(api.app)
    api_login(other, "viewer")
    r = api.post("/api/auth/change-password", json={"current": "Correct-Horse-9-Battery", "new": "Brand-New-Passphrase-77"})
    assert r.status_code == 200
    new_cookie, new_csrf = api.cookies.get("ks_session"), r.json()["csrf_token"]
    assert new_cookie and new_cookie != old_cookie and new_csrf != old_csrf
    api.headers["X-CSRF-Token"] = new_csrf
    assert api.get("/api/auth/me").status_code == 200          # the new session works
    assert other.get("/api/auth/me").status_code == 401        # other sessions were ended
    stale = __import__("fastapi.testclient", fromlist=["TestClient"]).TestClient(api.app)
    stale.cookies.set("ks_session", old_cookie)
    assert stale.get("/api/auth/me").status_code == 401        # the old session ID is gone


def test_links_never_come_from_the_host_header(api, ready_users, monkeypatch):
    """SC-CFG-006: a forged Host header can't redirect invitation links; KEYSTONE_PUBLIC_URL is used when set."""
    from keystone.core import settings as settings_mod

    api_login(api, "admin")
    pid = api.post("/api/people", json={"full_name": "Hal Host", "email": "hal@example.example"}).json()["id"]
    link = api.post(f"/api/people/{pid}/invite", headers={"Host": "evil.example"}).json()
    assert link["url"] is None and link["path"].startswith("/invite#token=") and "evil" not in str(link)
    monkeypatch.setenv("KEYSTONE_PUBLIC_URL", "https://isms.example.com")
    if hasattr(settings_mod.get_settings, "cache_clear"):
        settings_mod.get_settings.cache_clear()
    link = api.post(f"/api/people/{pid}/invite", headers={"Host": "evil.example"}).json()
    assert link["url"].startswith("https://isms.example.com/invite#token=")
    monkeypatch.setenv("KEYSTONE_PUBLIC_URL", "javascript:alert(1)")
    with pytest.raises(ValueError):
        settings_mod.Settings()
    monkeypatch.delenv("KEYSTONE_PUBLIC_URL")
    if hasattr(settings_mod.get_settings, "cache_clear"):
        settings_mod.get_settings.cache_clear()


def test_hsts_only_over_https(api):
    assert "strict-transport-security" not in api.get("/api/auth/status").headers
    h = api.get("/api/auth/status", headers={"X-Forwarded-Proto": "https"}).headers
    assert h["strict-transport-security"].startswith("max-age=31536000")


def test_dashboard_next_steps_and_trend(api, users):
    """Next steps are management actions: shown to roles that can act on controls, not to read-only roles."""
    api_login(api, "admin")
    d = api.get("/api/dashboard").json()
    assert {"next_steps", "trend", "audit_coverage"} <= set(d)
    assert d["trend"]["days"] and all(len(v) == len(d["trend"]["days"]) for v in d["trend"]["series"].values())
    api_login(api, "viewer")
    assert api.get("/api/dashboard").json()["next_steps"] == []
    api.cookies.clear()
    assert api.get("/api/dashboard").status_code == 401


def test_bulk_update_controls(api, ready_users, content, db):
    from keystone.core.audit import AuditLog
    from keystone.frameworks.models import CommonControl

    with db.session_scope() as s:
        ids = [c.id for c in s.query(CommonControl).order_by(CommonControl.id).limit(3)]
        before = s.query(AuditLog).count()
    owner = ready_users["control_owner"].id
    api_login(api, "viewer")
    assert api.post("/api/controls/bulk", json={"ids": ids, "owner_id": owner}).status_code == 403
    api_login(api, "controlowner")
    r = api.post("/api/controls/bulk", json={"ids": ids, "owner_id": owner, "status": "planned"})
    assert r.status_code == 200 and r.json() == {"updated": 3, "tasks_moved": 0}
    with db.session_scope() as s:
        assert {(c.owner_id, c.status) for c in s.query(CommonControl).filter(CommonControl.id.in_(ids))} == {(owner, "planned")}
        assert s.query(AuditLog).count() >= before + 3  # one audited change per control
    # Clearing the owner is an explicit null; leaving it out changes nothing.
    assert api.post("/api/controls/bulk", json={"ids": ids[:1], "owner_id": None}).status_code == 200
    with db.session_scope() as s:
        assert s.get(CommonControl, ids[0]).owner_id is None and s.get(CommonControl, ids[1]).owner_id == owner
    # Refusals leave every record unchanged (all-or-nothing).
    assert api.post("/api/controls/bulk", json={"ids": ids, "status": "not_applicable"}).status_code == 400
    assert api.post("/api/controls/bulk", json={"ids": ids, "status": "bogus"}).status_code == 400
    assert api.post("/api/controls/bulk", json={"ids": [*ids, 999999], "status": "implemented"}).status_code == 404
    assert api.post("/api/controls/bulk", json={"ids": ids, "owner_id": 999999}).status_code == 400
    assert api.post("/api/controls/bulk", json={"ids": ids}).status_code == 400
    assert api.post("/api/controls/bulk", json={"ids": []}).status_code == 422
    assert api.post("/api/controls/bulk", json={"ids": list(range(1, 502)), "status": "planned"}).status_code == 422
    assert api.post("/api/controls/bulk", json={"ids": ids, "implementation_notes": "x"}).status_code == 422
    with db.session_scope() as s:
        assert {c.status for c in s.query(CommonControl).filter(CommonControl.id.in_(ids))} == {"planned"}
    rows = api.get("/api/controls").json()
    assert {"readiness", "evidence_current"} <= set(rows[0])


def test_bulk_update_tasks(api, ready_users, content, db):
    from keystone.tasks.models import Task

    with db.session_scope(ready_users["admin"]) as s:
        from keystone.tasks import service as tsk

        ids = [tsk.save_task(s, ready_users["admin"], title=f"T{i}").id for i in range(3)]
        done = s.get(Task, ids[2])
        done.status = "done"
    assignee = ready_users["risk_owner"].id
    api_login(api, "auditor")
    assert api.post("/api/tasks/bulk", json={"ids": ids[:2], "assignee_id": assignee}).status_code == 403
    api_login(api, "riskowner")
    r = api.post("/api/tasks/bulk", json={"ids": ids[:2], "assignee_id": assignee, "due_date": "2027-01-31"})
    assert r.status_code == 200 and r.json() == {"updated": 2}
    with db.session_scope() as s:
        assert {(t.assignee_id, t.due_date.isoformat()) for t in s.query(Task).filter(Task.id.in_(ids[:2]))} == {(assignee, "2027-01-31")}
    r = api.post("/api/tasks/bulk", json={"ids": ids, "due_date": "2027-02-28"})
    assert r.status_code == 400 and "Completed" in r.json()["detail"]
    with db.session_scope() as s:
        assert s.get(Task, ids[0]).due_date.isoformat() == "2027-01-31"
    assert api.post("/api/tasks/bulk", json={"ids": ids[:2], "title": "x"}).status_code == 422
