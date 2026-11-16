"""Auditor workspace: expiring accounts, evidence request list, audit pack."""

import csv
import hashlib
import io
import zipfile
from datetime import date, datetime, timedelta

import pytest
from sqlalchemy import select

from keystone import demo
from keystone.audits import pack, service as aud
from keystone.audits.models import Audit
from keystone.controls.models import Evidence
from keystone.core import auth
from keystone.core.audit import AuditLog
from keystone.core.sessions import WebSession

from .conftest import PASSWORD, api_login


# ---- expiring accounts --------------------------------------------------------------------------------

def test_auditor_accounts_must_expire(api, ready_users):
    api_login(api, "admin")
    base = {"username": "ext.auditor", "display_name": "External Auditor", "password": "Long-Enough-Pass-123", "role": "auditor"}
    r = api.post("/api/users", json=base)
    assert r.status_code == 400 and "expiry" in r.json()["detail"]
    past = (datetime.now() - timedelta(days=1)).isoformat()
    assert api.post("/api/users", json={**base, "expires_at": past}).status_code == 400
    future = (datetime.now() + timedelta(days=30)).isoformat()
    r = api.post("/api/users", json={**base, "expires_at": future})
    assert r.status_code == 200 and r.json()["expires_at"]
    uid = r.json()["id"]
    assert api.patch(f"/api/users/{uid}", json={"expires_at": None}).status_code == 400  # an auditor can't lose the expiry
    viewer = ready_users["viewer"].id
    assert api.patch(f"/api/users/{viewer}", json={"role": "auditor"}).status_code == 400  # needs an expiry first
    me = ready_users["admin"].id
    assert api.patch(f"/api/users/{me}", json={"expires_at": future}).status_code == 400  # not on your own account


def test_expired_account_is_refused_everywhere(api, ready_users, db):
    api_login(api, "auditor")
    assert api.get("/api/dashboard").status_code == 200
    with db.session_scope() as s:
        s.get(auth.User, ready_users["auditor"].id).expires_at = datetime.now() - timedelta(minutes=1)
    r = api.get("/api/dashboard")
    assert r.status_code == 401 and r.json()["detail"] == "Account expired."  # an existing session stops working
    r = api.post("/api/auth/login", json={"username": "auditor", "password": PASSWORD})
    assert r.status_code == 401 and r.json()["detail"] == "Invalid username or password."  # same message as a wrong password
    with db.session_scope() as s:
        assert s.scalars(select(AuditLog).where(AuditLog.summary == "Account expired")).first() is not None


def test_role_change_ends_sessions(api, ready_users, db):
    """SC-AUTHN-003."""
    api_login(api, "admin")
    with db.session_scope() as s:
        from keystone.core import sessions

        sessions.create(s, ready_users["viewer"].id)
    assert api.patch(f"/api/users/{ready_users['viewer'].id}", json={"role": "control_owner"}).status_code == 200
    with db.session_scope() as s:
        assert s.scalars(select(WebSession).where(WebSession.user_id == ready_users["viewer"].id)).first() is None


# ---- evidence request list ------------------------------------------------------------------------------

@pytest.fixture
def audit_with_evidence(db, users, content):
    from keystone.controls import service as ctl
    from keystone.frameworks.service import control_by_code

    with db.session_scope(users["isms_manager"]) as s:
        c = control_by_code(s, "KC-TEC-13")
        a = aud.save_audit(s, users["isms_manager"], title="Backup audit", planned_start=date.today(), control_ids=[c.id])
        ev = ctl.add_evidence(s, users["control_owner"], c.id, title="Restore test report", kind="file", filename="restore.pdf", data=b"%PDF-1.4 restore test", valid_until=date.today() + timedelta(days=90))
        return a.id, ev.id, c.id


def test_request_list_flow(api, ready_users, audit_with_evidence, db):
    aid, eid, cid = audit_with_evidence
    api_login(api, "viewer")
    assert api.post(f"/api/audits/{aid}/requests", json={"title": "Backup restore evidence"}).status_code == 403
    api_login(api, "auditor")
    r = api.post(f"/api/audits/{aid}/requests", json={"title": "Backup restore evidence", "common_control_id": cid})
    assert r.status_code == 200
    rid = r.json()["id"]
    assert api.post(f"/api/audit-requests/{rid}/comments", json={"body": "Last two quarters, please."}).status_code == 200
    assert api.post(f"/api/audit-requests/{rid}/comments", json={"body": "x" * 5001}).status_code == 422
    assert api.post(f"/api/audit-requests/{rid}/respond", json={"evidence_ids": [eid]}).status_code == 403  # auditors don't supply evidence
    api_login(api, "controlowner")
    assert api.post(f"/api/audit-requests/{rid}/respond", json={"evidence_ids": [999999]}).status_code == 404
    r = api.post(f"/api/audit-requests/{rid}/respond", json={"evidence_ids": [eid], "body": "Attached."})
    assert r.status_code == 200 and r.json()["status"] == "provided" and [e["id"] for e in r.json()["evidence"]] == [eid]
    assert api.post(f"/api/audit-requests/{rid}/status", json={"status": "accepted"}).status_code == 403
    api_login(api, "auditor")
    r = api.post(f"/api/audit-requests/{rid}/status", json={"status": "accepted"})
    assert r.json()["status"] == "accepted" and len(r.json()["comments"]) == 2
    assert api.post(f"/api/audit-requests/{rid}/status", json={"status": "bogus"}).status_code == 400
    with db.session_scope() as s:
        s.get(Audit, aid).status = "closed"
    assert api.post(f"/api/audit-requests/{rid}/comments", json={"body": "late"}).status_code == 400


# ---- audit pack ------------------------------------------------------------------------------------

def test_audit_pack(api, ready_users, audit_with_evidence, db, monkeypatch):
    aid, eid, _cid = audit_with_evidence
    with db.session_scope() as s:
        s.get(Evidence, eid).title = "../../etc/passwd"  # hostile title must not shape the path
    api_login(api, "auditor")
    r = api.get(f"/api/audits/{aid}/pack.zip")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = z.namelist()
    assert "manifest.csv" in names and "requests.csv" in names and any(n.startswith("soa/") for n in names)
    ev = [n for n in names if n.startswith("evidence/")]
    assert ev and all(".." not in n and not n.startswith("/") for n in names)
    assert ev[0].startswith("evidence/kc-tec-13/") and ev[0].endswith(".pdf")
    rows = list(csv.DictReader(io.StringIO(z.read("manifest.csv").decode())))
    assert all(hashlib.sha256(z.read(row["file"])).hexdigest() == row["sha256"] for row in rows)
    with db.session_scope() as s:
        assert s.scalars(select(AuditLog).where(AuditLog.action == "export", AuditLog.entity_type == "Audit")).first() is not None
    monkeypatch.setattr(pack, "MAX_PACK_BYTES", 100)
    r = api.get(f"/api/audits/{aid}/pack.zip")
    assert r.status_code == 400 and "MB" in r.json()["detail"]


def test_demo_auditor_expires(db):
    with db.session_scope() as s:
        admin = auth.create_user(s, None, username="admin", display_name="Admin", password=demo.DEMO_PASSWORD)
    with db.session_scope(admin) as s:
        demo.seed(s, s.get(auth.User, admin.id))
    with db.session_scope() as s:
        omar = s.scalar(select(auth.User).where(auth.User.username == "omar.audit"))
        assert omar.expires_at and omar.expires_at > datetime.now()
