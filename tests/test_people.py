"""Phase 5: people, invitations, employee portal, training, devices, offboarding."""

from datetime import timedelta

import pytest
from sqlalchemy import select

from keystone.core import auth
from keystone.core.db import utcnow
from keystone.core.rbac import PermissionDenied, has_permission
from keystone.people import service as ppl
from keystone.people.models import DEVICE_CHECKS, OFFBOARDING_ITEMS, Invitation
from keystone.policies import service as pol
from tests.conftest import PASSWORD, api_login

ALL_OK = {k: True for k in DEVICE_CHECKS}


def _person(session, users, **kw):
    return ppl.save_person(session, users["admin"], **{"full_name": "Pat Doe", "email": "Pat.Doe@Example.Example", **kw})


def test_training_content_is_valid():
    mods = ppl.modules()
    assert len(mods) == 6 and len({m["key"] for m in mods}) == 6
    pub = ppl.public_module(mods[0])
    assert all("answer" not in q for q in pub["quiz"])


def test_person_validation_and_permissions(users, session):
    p = _person(session, users)
    assert p.email == "pat.doe@example.example" and p.status == "onboarding"
    with pytest.raises(ValueError, match="already"):
        _person(session, users)
    with pytest.raises(ValueError, match="valid email"):
        _person(session, users, email="nope")
    with pytest.raises(PermissionDenied):
        ppl.save_person(session, users["risk_owner"], full_name="x", email="x@y.example")


def test_invitation_flow(users, session):
    p = _person(session, users)
    t1 = ppl.invite(session, users["admin"], p.id)
    t2 = ppl.invite(session, users["admin"], p.id)  # revokes the first
    with pytest.raises(LookupError):
        ppl.describe_invite(session, t1)
    assert ppl.describe_invite(session, t2)["email"] == p.email
    stored = session.scalars(select(Invitation)).all()
    assert all(t1 not in i.token_hash and t2 not in i.token_hash for i in stored)  # only hashes stored
    with pytest.raises(auth.PasswordPolicyError):
        ppl.accept_invite(session, t2, "short")
    u = ppl.accept_invite(session, t2, PASSWORD)
    assert u.role == "employee" and p.user_id == u.id and not has_permission(u, "read")
    with pytest.raises(LookupError):
        ppl.accept_invite(session, t2, PASSWORD)
    with pytest.raises(ValueError, match="already has"):
        ppl.invite(session, users["admin"], p.id)


def test_expired_invite(users, session):
    p = _person(session, users)
    t = ppl.invite(session, users["admin"], p.id)
    session.scalars(select(Invitation)).one().expires_at = utcnow() - timedelta(seconds=1)
    with pytest.raises(LookupError, match="expired"):
        ppl.accept_invite(session, t, PASSWORD)


def test_quiz_grading_and_status(users, session):
    u = users["viewer"]
    m = ppl.module("phishing")
    wrong = [(q["answer"] + 1) % len(q["options"]) for q in m["quiz"]]
    assert ppl.submit_quiz(session, u, "phishing", wrong).passed is False
    right = [q["answer"] for q in m["quiz"]]
    c = ppl.submit_quiz(session, u, "phishing", right)
    assert c.passed and c.score == c.out_of
    with pytest.raises(ValueError, match="every question"):
        ppl.submit_quiz(session, u, "phishing", [0])
    st = ppl.status_for_user(session, u)
    assert st.training_done == 1 and st.training_total == 6 and st.device_ok is None and not st.complete


def test_device_attestation(users, session):
    u = users["viewer"]
    d = ppl.attest_device(session, u, device_name="Laptop", os="macos", checks={**ALL_OK, "firewall": False})
    assert not ppl.device_compliant(d)
    assert ppl.device_issues(d) == ["Not confirmed: Firewall is on"]  # T2: say which check failed
    d2 = ppl.attest_device(session, u, device_name="Laptop", os="macos", checks=ALL_OK)
    assert d2.id == d.id and ppl.device_compliant(d2)
    assert ppl.device_issues(d2) == []
    d2.attested_at = utcnow() - timedelta(days=181)
    assert not ppl.device_compliant(d2)
    assert "more than 180 days ago" in ppl.device_issues(d2)[0]
    with pytest.raises(ValueError, match="Unknown"):
        ppl.attest_device(session, u, device_name="x", os="macos", checks={"telepathy": True})


def test_full_compliance(users, session):
    u = users["viewer"]
    doc = pol.save_document(session, users["isms_manager"], code="P1", title="Policy", requires_acknowledgement=True)
    v = pol.start_version(session, users["isms_manager"], doc.id, body="x")
    pol.submit_version(session, users["isms_manager"], v.id)
    pol.approve_version(session, users["admin"], v.id)
    pol.acknowledge(session, u, v.id)
    for m in ppl.modules():
        ppl.submit_quiz(session, u, m["key"], [q["answer"] for q in m["quiz"]])
    ppl.attest_device(session, u, device_name="Laptop", os="windows", checks=ALL_OK)
    assert ppl.status_for_user(session, u).complete


def test_offboarding_disables_account(users, db):
    with db.session_scope() as s:
        p = _person(s, users)
        ppl.link_user(s, users["admin"], p.id, users["viewer"].id)
        with pytest.raises(ValueError, match="Start offboarding"):
            ppl.tick_offboarding(s, users["admin"], p.id, "access_revoked")
        ppl.set_status(s, users["admin"], p.id, "offboarding")
        with pytest.raises(ValueError, match="incomplete"):
            ppl.complete_offboarding(s, users["admin"], p.id)
        for k in OFFBOARDING_ITEMS:
            ppl.tick_offboarding(s, users["admin"], p.id, k)
        assert p.offboarding["manager_signoff"]["by"] == "admin"
        ppl.complete_offboarding(s, users["admin"], p.id)
        assert p.status == "offboarded" and not s.get(auth.User, users["viewer"].id).active


# ---- API -------------------------------------------------------------------------------------------

def test_employee_portal_via_api(api, ready_users, db):
    api_login(api, "admin")
    pid = api.post("/api/people", json={"full_name": "Erin Employee", "email": "erin@example.example", "start_date": "2026-01-01"}).json()["id"]
    link = api.post(f"/api/people/{pid}/invite").json()
    assert link["path"].startswith("/invite#token=")  # SC-CRY-005: the token stays out of paths and queries
    token = link["path"].split("#token=")[1]
    from fastapi.testclient import TestClient
    emp = TestClient(api.app)
    assert emp.get("/api/public/invite", headers={"X-Invite-Token": token}).json()["full_name"] == "Erin Employee"
    me = emp.post("/api/public/invite", json={"password": PASSWORD}, headers={"X-Invite-Token": token}).json()
    assert me["role"] == "employee" and "read" not in me["permissions"]
    emp.headers["X-CSRF-Token"] = me["csrf_token"]
    # Employees cannot see ISMS data...
    for path in ("/api/risks", "/api/dashboard", "/api/people", "/api/controls", "/api/policies"):
        assert emp.get(path).status_code == 403, path
    # ...but can use their portal.
    portal = emp.get("/api/portal").json()
    assert portal["person"]["full_name"] == "Erin Employee" and portal["status"]["training_total"] == 6
    mod = emp.get("/api/portal/training/phishing").json()
    assert all("answer" not in q for q in mod["quiz"])
    r = emp.post("/api/portal/training/phishing", json={"answers": [1, 1, 0]}).json()
    assert r["passed"] is True
    import json as _json
    d = emp.post("/api/portal/devices", data={"device_name": "Work laptop", "os": "windows", "checks": _json.dumps({k: True for k in DEVICE_CHECKS})}).json()
    assert d["compliant"] is True
    people = api.get("/api/people").json()["people"]
    erin = next(p for p in people if p["email"] == "erin@example.example")
    assert erin["status"] == "active" and erin["compliance"]["training_done"] == 1 and erin["compliance"]["device_ok"] is True


def test_employee_can_download_only_current_acknowledgement_policy_files(api, ready_users, db):
    """Portal policy files are served only for the current approved version that needs acknowledgement."""
    from fastapi.testclient import TestClient

    from keystone.policies import service as pol

    pdf = b"%PDF-1.4 acceptable use"
    with db.session_scope() as s:
        from keystone.core.auth import User

        author = s.query(User).filter(User.username == "ismsmanager").one()
        approver = s.query(User).filter(User.username == "admin").one()
        d = pol.save_document(s, author, code="POL-AUP", title="Acceptable Use", requires_acknowledgement=True)
        v1 = pol.start_version(s, author, d.id, filename="aup-v1.pdf", data=pdf)
        pol.submit_version(s, author, v1.id)
        pol.approve_version(s, approver, v1.id)
        v2 = pol.start_version(s, author, d.id, filename="aup-v2.pdf", data=b"%PDF-1.4 draft v2")  # draft, not current
        noack = pol.save_document(s, author, code="POL-INT", title="Internal standard", requires_acknowledgement=False)
        n1 = pol.start_version(s, author, noack.id, filename="int.pdf", data=b"%PDF-1.4 internal")
        pol.submit_version(s, author, n1.id)
        pol.approve_version(s, approver, n1.id)
        ids = (v1.id, v2.id, n1.id, v1.attachment_id)

    api_login(api, "admin")
    pid = api.post("/api/people", json={"full_name": "Pat Portal", "email": "pat@example.example"}).json()["id"]
    token = api.post(f"/api/people/{pid}/invite").json()["path"].split("#token=")[1]
    emp = TestClient(api.app)
    emp.headers["X-CSRF-Token"] = emp.post("/api/public/invite", json={"password": PASSWORD}, headers={"X-Invite-Token": token}).json()["csrf_token"]

    r = emp.get(f"/api/portal/policies/{ids[0]}/document")
    assert r.status_code == 200 and r.content == pdf and r.headers["content-disposition"].startswith("attachment") and r.headers["x-content-type-options"] == "nosniff"
    assert emp.get(f"/api/portal/policies/{ids[1]}/document").status_code == 404   # draft version
    assert emp.get(f"/api/portal/policies/{ids[2]}/document").status_code == 404   # no acknowledgement required
    assert emp.get("/api/portal/policies/999999/document").status_code == 404
    assert emp.get(f"/api/attachments/{ids[3]}").status_code == 403                # the general route stays closed
