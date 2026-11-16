"""CSV register import: rows arrive as JSON (parsed in the browser), validated through the services."""

from keystone.assets.models import Asset
from keystone.core.audit import AuditLog, verify_chain
from keystone.people.models import Person
from keystone.tprm.models import Vendor

from .conftest import api_login

ASSETS = [
    {"Name": "Booking DB", "Asset type": "Application", "Owner": "riskowner", "Confidentiality": "4", "Contains personal data": "yes", "Classification": "confidential"},
    {"Name": "Office Wi-Fi", "Asset type": "hardware", "Owner": "", "Confidentiality": "", "Contains personal data": "no", "Classification": ""},
]


def _count(db, model):
    with db.session_scope() as s:
        return s.query(model).count()


def test_preview_validates_and_saves_nothing(api, ready_users, db):
    api_login(api, "admin")
    audit_before = _count(db, AuditLog)
    r = api.post("/api/import/assets", json={"rows": ASSETS})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] == 2 and body["errors"] == 0 and [x["label"] for x in body["rows"]] == ["Booking DB", "Office Wi-Fi"]
    assert _count(db, Asset) == 0 and _count(db, AuditLog) == audit_before
    # Committing really imports, through the service (audited).
    r = api.post("/api/import/assets", json={"rows": ASSETS, "preview": False})
    assert r.status_code == 200 and r.json()["ok"] == 2
    with db.session_scope() as s:
        a = s.query(Asset).filter_by(name="Booking DB").one()
        assert a.asset_type == "application" and a.owner_id == ready_users["risk_owner"].id and a.confidentiality == 4 and a.contains_personal_data is True
        assert s.query(AuditLog).count() >= audit_before + 2
        assert verify_chain(s)[0]


def test_row_errors_are_reported_and_commit_is_all_or_nothing(api, ready_users, db):
    api_login(api, "admin")
    rows = [
        {"name": "Acme", "status": "active", "dpa_signed": "maybe", "contract_start": "2026-13-01"},
        {"name": "Acme", "status": "active", "dpa_signed": "yes", "contract_start": ""},
        {"name": "", "status": "frozen", "dpa_signed": "", "contract_start": ""},
        {"name": "Contoso", "status": "", "dpa_signed": "", "contract_start": ""},
    ]
    body = api.post("/api/import/vendors", json={"rows": rows}).json()
    errs = {x["row"]: " ".join(x["errors"]) for x in body["rows"]}
    assert "yes or no" in errs[2] and "YYYY-MM-DD" in errs[2]
    assert errs[3] == ""  # row 2 failed, so this Acme is the first valid one
    assert "name is required" in errs[4] and "frozen" in errs[4] and errs[5] == ""
    r = api.post("/api/import/vendors", json={"rows": rows, "preview": False})
    assert r.status_code == 400 and "Nothing was imported" in r.json()["detail"]
    assert _count(db, Vendor) == 0


def test_duplicate_within_file_is_caught(api, ready_users, db):
    api_login(api, "admin")
    rows = [{"name": "Acme"}, {"name": "Acme"}]
    body = api.post("/api/import/vendors", json={"rows": rows}).json()
    assert body["ok"] == 1 and "already exists" in body["rows"][1]["errors"][0]
    rows = [{"full_name": "A B", "email": "ab@example.test"}, {"full_name": "A C", "email": "AB@example.test"}]
    body = api.post("/api/import/people", json={"rows": rows}).json()
    assert body["ok"] == 1 and "already in the people directory" in body["rows"][1]["errors"][0]
    assert _count(db, Person) == 0


def test_headers_and_bounds(api, ready_users):
    api_login(api, "admin")
    body = api.post("/api/import/risks", json={"rows": [{"title": "x", "owner_id": "1", "status": "closed"}]}).json()
    assert "Unknown column 'owner_id'" in body["header_errors"] and "Unknown column 'status'" in body["header_errors"]  # no mass assignment
    body = api.post("/api/import/risks", json={"rows": [{"description": "x"}]}).json()
    assert body["header_errors"] == ["Required column 'title' is missing"]
    body = api.post("/api/import/risks", json={"rows": [{"Title": "x", "title": "y"}]}).json()
    assert "appears more than once" in body["header_errors"][0]
    assert api.post("/api/import/risks", json={"rows": []}).status_code == 422
    assert api.post("/api/import/risks", json={"rows": [{"title": "x"}] * 1001}).status_code == 422
    assert api.post("/api/import/risks", json={"rows": [{"title": "x" * 20_001}]}).status_code == 422
    assert api.post("/api/import/risks", json={"rows": [{"title": "x"}], "extra": 1}).status_code == 422
    assert api.post("/api/import/controls", json={"rows": [{"title": "x"}]}).status_code in (404, 405)
    body = api.post("/api/import/risks", json={"rows": [{"title": "x", "owner": "nobody", "inherent_likelihood": "1e9"}]}).json()
    assert "no active user" in body["rows"][0]["errors"][0] and "whole number" in body["rows"][0]["errors"][1]
    spec = api.get("/api/import/vendors").json()
    assert spec["max_rows"] == 1000 and spec["columns"][0] == {"name": "name", "kind": "text", "required": True, "choices": [], "help": ""}


def test_import_permissions(api, ready_users):
    api.cookies.clear()
    assert api.post("/api/import/assets", json={"rows": ASSETS}).status_code == 401
    api_login(api, "viewer")
    assert api.post("/api/import/assets", json={"rows": ASSETS}).status_code == 403
    assert api.get("/api/import/assets").status_code == 403
    api_login(api, "controlowner")  # can write controls, not assets or people
    assert api.post("/api/import/assets", json={"rows": ASSETS}).status_code == 403
    assert api.post("/api/import/people", json={"rows": [{"full_name": "x", "email": "x@example.test"}]}).status_code == 403
    api_login(api, "riskowner")
    assert api.post("/api/import/assets", json={"rows": ASSETS}).status_code == 200
