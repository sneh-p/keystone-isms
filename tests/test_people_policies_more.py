"""Training assignment (A.6.3) and policy acknowledgement audiences: who must do what, minor versions, the matrix."""

from datetime import timedelta
from io import BytesIO

import pytest
from openpyxl import load_workbook

from keystone.core.services import today
from keystone.people import service as ppl
from keystone.people.models import Person
from keystone.policies import service as pol

from .conftest import api_login


def _person(session, user, department, kind="employee", start=None):
    p = Person(full_name=user.display_name, email=f"{user.username}@example.org", department=department, employment_type=kind, status="active", user_id=user.id,
               start_date=start or today() - timedelta(days=60), offboarding={})
    session.add(p)
    session.flush()
    return p


def test_training_assignment_and_due_dates(session, users):
    fin, eng = users["risk_owner"], users["control_owner"]
    _person(session, fin, "Finance")
    _person(session, eng, "Engineering", "contractor")
    key = ppl.modules(session)[0]["key"]
    assert key in [m["key"] for m in ppl.modules_for(session, eng)]
    ppl.set_assignment(session, users["isms_manager"], key, audience={"departments": ["finance"], "employment_types": []}, due_days=14)
    assert key in [m["key"] for m in ppl.modules_for(session, fin)] and key not in [m["key"] for m in ppl.modules_for(session, eng)]
    with pytest.raises(ValueError, match="employee or contractor"):
        ppl.set_assignment(session, users["isms_manager"], key, audience={"employment_types": ["intern"]}, due_days=14)
    mine = next(m for m in ppl.my_training(session, fin) if m["key"] == key)
    assert mine["due"] == today() + timedelta(days=14)  # started 60 days ago, assigned today: due 14 days after assignment
    assert ppl.training_overdue(session, today() + timedelta(days=20)).get(ppl.module(session, key)["title"]) == 1
    headers, rows = ppl.training_matrix(session, users["viewer"])
    eng_row = next(r for r in rows if r[0] == eng.display_name)
    assert eng_row[headers.index(ppl.module(session, key)["title"])] == "not assigned"


def test_policy_audience_and_minor_versions(session, users):
    mgr, approver = users["isms_manager"], users["admin"]
    fin, eng = users["risk_owner"], users["control_owner"]
    _person(session, fin, "Finance")
    _person(session, eng, "Engineering")
    d = pol.save_document(session, mgr, code="POL-EXP", title="Expenses", requires_acknowledgement=True, ack_audience={"departments": ["Finance"]})
    v1 = pol.start_version(session, mgr, d.id, body="# Expenses\\nReceipts are required.")
    pol.submit_version(session, mgr, v1.id)
    pol.approve_version(session, approver, v1.id)
    assert [v.id for v in pol.pending_for(session, fin)] == [v1.id] and pol.pending_for(session, eng) == []
    assert pol.ack_status(session, d).total == 1
    pol.acknowledge(session, fin, v1.id, signed_name=fin.display_name)
    v2 = pol.start_version(session, mgr, d.id, body="# Expenses\\nReceipts are required (typo fixed).", major=False)
    pol.submit_version(session, mgr, v2.id)
    pol.approve_version(session, approver, v2.id)
    assert pol.pending_for(session, fin) == []  # 1.1 keeps the 1.0 acceptance
    v3 = pol.start_version(session, mgr, d.id, body="# Expenses\\nNew limits.", major=True)
    pol.submit_version(session, mgr, v3.id)
    pol.approve_version(session, approver, v3.id)
    assert [v.id for v in pol.pending_for(session, fin)] == [v3.id]  # 2.0 asks again


def test_training_routes(api, ready_users):
    api_login(api, "admin")
    data = api.get("/api/training/assignments").json()
    key = data["modules"][0]["key"]
    assert api.put(f"/api/training/assignments/{key}", json={"audience": {"departments": [], "employment_types": ["contractor"]}, "due_days": 10}).json()["due_days"] == 10
    r = api.get("/api/training/matrix.xlsx")
    assert r.status_code == 200 and load_workbook(BytesIO(r.content)).active.max_row >= 1
    api.post("/api/auth/logout")
    api.cookies.clear()
    api_login(api, ready_users["viewer"].username)
    assert api.put(f"/api/training/assignments/{key}", json={"due_days": 10}).status_code == 403
