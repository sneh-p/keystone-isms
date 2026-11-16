"""Comments and @mentions, saved views, workload, risk library, calendar, board report, SSO required."""

import io
from datetime import date, timedelta

import pytest
from sqlalchemy import select

from keystone import demo
from keystone.core import auth
from keystone.core.audit import AuditLog
from keystone.notifications.models import Notification

from .conftest import PASSWORD, api_login


@pytest.fixture
def demo_api(api, db):
    with db.session_scope() as s:
        admin = auth.create_user(s, None, username="admin", display_name="Admin", password=demo.DEMO_PASSWORD)
    with db.session_scope(admin) as s:
        demo.seed(s, s.get(auth.User, admin.id))
        auth.create_user(s, s.get(auth.User, admin.id), username="emp.one", display_name="Emp One", password=PASSWORD, role="employee", must_change_password=False)
    return api


# ---- comments ------------------------------------------------------------------------------------

def test_comments_and_mentions(demo_api, db):
    api = demo_api
    api_login(api, "sam.view", demo.DEMO_PASSWORD)  # a viewer can comment on what they can read
    r = api.post("/api/comments/risk/1", json={"body": "@raj.risk can we bring the restore test forward? cc @emp.one @sam.view @nobody"})
    assert r.status_code == 200 and r.json()["notified"] == ["Raj Patel"]  # not employees, not yourself, not unknown names
    assert [c["body"][:4] for c in api.get("/api/comments/risk/1").json()] == ["@raj"]
    assert api.post("/api/comments/risk/999999", json={"body": "x"}).status_code == 404
    assert api.post("/api/comments/payroll/1", json={"body": "x"}).status_code == 404
    assert api.post("/api/comments/risk/1", json={"body": "x" * 5001}).status_code == 422
    assert api.post("/api/comments/risk/1", json={"body": "   "}).status_code == 400
    with db.session_scope() as s:
        raj = s.scalar(select(auth.User).where(auth.User.username == "raj.risk"))
        n = s.scalar(select(Notification).where(Notification.user_id == raj.id, Notification.kind == "mention"))
        assert n and n.page == "/risks?open=1" and "Sam Jones mentioned you on RSK-0001" in n.title
        from keystone.notifications import service as ntf

        ntf.refresh_all(s)  # the hourly refresh must not resolve event notifications
        assert s.get(Notification, n.id).resolved_at is None
        assert s.scalars(select(AuditLog).where(AuditLog.entity_type == "Comment")).first() is not None
    api_login(api, "emp.one", PASSWORD)
    assert api.get("/api/comments/risk/1").status_code == 403
    assert api.post("/api/comments/risk/1", json={"body": "hi"}).status_code == 403


# ---- saved views and workload ----------------------------------------------------------------------

def test_saved_views_are_personal(demo_api):
    api = demo_api
    api_login(api, "mia.isms", demo.DEMO_PASSWORD)
    r = api.post("/api/views/controls", json={"name": "Unowned, no evidence", "query": "owner=none&flag=no_evidence&open=5&evil=1"})
    assert r.status_code == 200 and r.json()["query"] == "owner=none&flag=no_evidence"  # filters only
    vid = r.json()["id"]
    assert api.post("/api/views/controls", json={"name": "x", "query": "open=5"}).status_code == 400
    assert api.post("/api/views/payroll", json={"name": "x", "query": "a=1"}).status_code == 400
    api_login(api, "raj.risk", demo.DEMO_PASSWORD)
    assert api.get("/api/views/controls").json() == []
    assert api.delete(f"/api/views/controls/{vid}").status_code == 404
    api_login(api, "mia.isms", demo.DEMO_PASSWORD)
    assert api.delete(f"/api/views/controls/{vid}").status_code == 200


def test_workload(demo_api):
    api = demo_api
    api_login(api, "sam.view", demo.DEMO_PASSWORD)
    rows = {r["display_name"]: r for r in api.get("/api/workload").json()}
    assert rows["Mia Novak"]["open_tasks"] > 0 and "Unassigned" in rows
    assert "Emp One" not in rows  # employees aren't staff workload
    assert all(set(r) >= {"open_tasks", "overdue", "due_30", "needs_attention", "controls", "risks"} for r in rows.values())


# ---- risk library ---------------------------------------------------------------------------------

def test_risk_library(demo_api, db):
    api = demo_api
    api_login(api, "sam.view", demo.DEMO_PASSWORD)
    lib = api.get("/api/risk-library").json()
    assert len(lib) >= 20 and all({"key", "title", "category", "likelihood", "impact", "controls"} <= set(s) for s in lib)
    assert api.post("/api/risks/from-library", json={"key": "ransomware"}).status_code == 403
    api_login(api, "raj.risk", demo.DEMO_PASSWORD)
    with db.session_scope() as s:
        raj = s.scalar(select(auth.User).where(auth.User.username == "raj.risk")).id
    r = api.post("/api/risks/from-library", json={"key": "secrets-leak", "owner_id": raj})
    assert r.status_code == 200
    risk = api.get(f"/api/risks/{r.json()['id']}").json()
    assert risk["owner_id"] == raj and risk["inherent_likelihood"] == 3 and len(risk["control_ids"]) == 4 and risk["status"] == "assessed"
    assert api.post("/api/risks/from-library", json={"key": "nope"}).status_code == 404
    assert api.post("/api/risks/from-library", json={"key": "ransomware", "owner_id": 999999}).status_code == 400


def test_library_content_is_valid():
    import yaml

    from keystone.risk import service as risk
    from keystone.risk.models import RISK_CATEGORIES

    codes = {c["code"] for c in yaml.safe_load(open("content/frameworks/common_controls.yaml"))["controls"]}
    lib = risk.library()
    assert len({s["key"] for s in lib}) == len(lib)
    for s in lib:
        assert s["category"] in RISK_CATEGORIES and 1 <= s["likelihood"] <= 5 and 1 <= s["impact"] <= 5
        assert s["controls"] and set(s["controls"]) <= codes, s["key"]


# ---- calendar and board report -------------------------------------------------------------------------

def test_calendar(demo_api):
    api = demo_api
    api_login(api, "sam.view", demo.DEMO_PASSWORD)
    today = date.today()
    ev = api.get("/api/calendar", params={"start": (today - timedelta(days=30)).isoformat(), "end": (today + timedelta(days=60)).isoformat()}).json()
    kinds = {e["kind"] for e in ev}
    assert {"task", "risk_review"} <= kinds and all(e["page"].startswith("/") for e in ev)
    assert api.get("/api/calendar", params={"start": today.isoformat(), "end": (today + timedelta(days=200)).isoformat()}).status_code == 400
    assert api.get("/api/calendar", params={"start": today.isoformat(), "end": (today - timedelta(days=1)).isoformat()}).status_code == 400


def test_board_report(demo_api, db):
    from docx import Document

    api = demo_api
    api_login(api, "sam.view", demo.DEMO_PASSWORD)
    r = api.get("/api/reports/board.docx")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/vnd.openxmlformats")
    text = "\n".join(p.text for p in Document(io.BytesIO(r.content)).paragraphs)
    assert "board summary" in text and "Alpine Ski House" in text and "Top risks" in text
    with db.session_scope() as s:
        assert s.scalars(select(AuditLog).where(AuditLog.summary == "Board summary exported")).first() is not None


# ---- SSO required ---------------------------------------------------------------------------------------

def test_sso_required_keeps_admins_as_break_glass(api, ready_users, db, monkeypatch):
    monkeypatch.setenv("KEYSTONE_PUBLIC_URL", "https://isms.example.com")
    api_login(api, "admin")
    assert api.put("/api/settings/sso-policy", json={"required": True}).status_code == 400  # no provider on yet
    assert api.put("/api/settings/sso/google", json={"client_id": "client-id-12345", "client_secret": "s", "enabled": True}).status_code == 200
    assert api.put("/api/settings/sso-policy", json={"required": True}).json()["required"] is True
    assert api.get("/api/auth/status").json()["sso_required"] is True
    assert api.put("/api/settings/sso/google", json={"enabled": False}).status_code == 400  # can't remove the last provider
    api.cookies.clear()
    r = api.post("/api/auth/login", json={"username": "viewer", "password": PASSWORD})
    assert r.status_code == 401 and "Microsoft or Google" in r.json()["detail"]
    r = api.post("/api/auth/login", json={"username": "viewer", "password": "wrong-password-123"})
    assert r.status_code == 401 and r.json()["detail"] == "Invalid username or password."  # no hint without the password
    api_login(api, "admin")  # break-glass
    api_login(api, "admin2")
    with db.session_scope() as s:
        assert s.scalars(select(AuditLog).where(AuditLog.summary.like("Password sign-in refused%"))).first() is not None
    api_login(api, "admin")
    assert api.put("/api/settings/sso-policy", json={"required": False}).status_code == 200
    api.cookies.clear()
    api_login(api, "viewer")
    api_login(api, "viewer")
    assert api.get("/api/settings/sso-policy").status_code == 403
