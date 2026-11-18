"""Batch 1 of the security expansion: declared registers (obligations, changes, policy exceptions, background checks,
confidentiality agreements, sites, visitors, physical checks), reports of suspicious activity, the leaver access
check and the exceptions register."""

from datetime import date, timedelta

from sqlalchemy import select

from keystone.core.services import today
from keystone.notifications.models import Notification

from .conftest import api_login


def _create(api, key, title, **fields):
    r = api.post(f"/api/registers/{key}", json={"title": title, "fields": fields})
    assert r.status_code == 200, r.text
    return r.json()


# ---- registers ---------------------------------------------------------------------------------------------------

def test_register_permissions_and_validation(api, ready_users):
    assert api.get("/api/registers/obligations").status_code == 401
    api_login(api, "viewer")
    assert api.get("/api/registers/obligations").status_code == 200
    assert api.post("/api/registers/obligations", json={"title": "GDPR", "fields": {"kind": "law", "requirement": "x"}}).status_code == 403
    assert api.get("/api/registers/screening").status_code == 403  # need-to-know
    assert "screening" not in [r["key"] for r in api.get("/api/registers").json()]
    api_login(api, "employee")
    assert api.get("/api/registers").status_code == 403
    api_login(api, "ismsmanager")
    assert api.get("/api/registers/nope").status_code == 404
    bad = [
        {"title": "GDPR", "fields": {"kind": "treaty", "requirement": "x"}},  # not a choice
        {"title": "GDPR", "fields": {"kind": "law"}},  # required field missing
        {"title": "GDPR", "fields": {"kind": "law", "requirement": "x", "colour": "red"}},  # unknown field
        {"title": "GDPR", "fields": {"kind": "law", "requirement": "x", "controls": [999999]}},  # unknown control
        {"title": "GDPR", "fields": {"kind": "law", "requirement": "x", "review_on": "tomorrow"}},
        {"title": " ", "fields": {"kind": "law", "requirement": "x"}},
        {"title": "GDPR", "fields": {"kind": "law", "requirement": "x" * 8001}},
    ]
    for b in bad:
        assert api.post("/api/registers/obligations", json=b).status_code in (400, 422), b
    e = _create(api, "obligations", "GDPR Article 32", kind="law", requirement="Appropriate security of processing", review_on=str(today() + timedelta(days=30)))
    assert e["ref"].startswith("LEG-") and e["status"] == "active" and e["due_on"] == str(today() + timedelta(days=30))
    cal = api.get(f"/api/calendar?start={today()}&end={today() + timedelta(days=60)}").json()
    assert any(x["kind"] == "register" and "GDPR" in x["title"] for x in cal)
    assert api.post(f"/api/comments/register_entry/{e['id']}", json={"body": "Checked with legal"}).status_code == 200


def test_change_workflow_and_segregation(api, ready_users):
    api_login(api, "controlowner")
    c = _create(api, "changes", "Upgrade the booking database", change_type="normal", risk_level="medium", description="Major version upgrade")
    mv = lambda to, note=None: api.post(f"/api/registers/changes/{c['id']}/move", json={"to": to, "note": note})
    assert mv("approved").status_code == 403  # control owners can't approve
    api_login(api, "ismsmanager")
    r = mv("approved")
    assert r.status_code == 400 and "Security review" in r.json()["detail"]
    api_login(api, "controlowner")
    api.patch(f"/api/registers/changes/{c['id']}", json={"fields": {"security_review": "No change to exposure", "rollback": "Restore the snapshot"}})
    api_login(api, "ismsmanager")
    assert mv("approved").status_code == 200
    assert mv("closed").status_code == 400  # not implemented yet
    assert mv("implemented").json()["data"]["implemented_on"] == str(today())
    r = mv("closed")
    assert r.status_code == 400 and "Outcome" in r.json()["detail"]
    api.patch(f"/api/registers/changes/{c['id']}", json={"fields": {"outcome": "Done, no issues"}})
    done = mv("closed").json()
    assert done["status"] == "closed" and [d["to"] for d in done["decisions"]] == ["approved", "implemented", "closed"]
    assert api.patch(f"/api/registers/changes/{c['id']}", json={"title": "x"}).status_code == 400  # closed records stay as they were
    assert api.delete(f"/api/registers/changes/{c['id']}").status_code == 400  # decided: stays on record

    own = _create(api, "changes", "Firewall rule for the new VPN", change_type="normal", risk_level="high", description="x", security_review="y", rollback="z")
    r = api.post(f"/api/registers/changes/{own['id']}/move", json={"to": "approved"})
    assert r.status_code == 400 and "Segregation of duties" in r.json()["detail"]
    assert api.post(f"/api/registers/changes/{own['id']}/move", json={"to": "rejected"}).status_code == 400
    assert api.delete(f"/api/registers/changes/{own['id']}").status_code == 200  # still new: can go


def test_policy_exceptions_and_the_exceptions_register(api, ready_users):
    api_login(api, "controlowner")
    too_long = {"policy": "POL-003 Access Control", "scope": "Kiosk PCs", "justification": "Vendor software", "expires_on": str(today() + timedelta(days=400))}
    assert api.post("/api/registers/policy-exceptions", json={"title": "Kiosk auto-login", "fields": too_long}).status_code == 400
    e = _create(api, "policy-exceptions", "Kiosk auto-login", **{**too_long, "expires_on": str(today() + timedelta(days=90))})
    assert api.post(f"/api/registers/policy-exceptions/{e['id']}/move", json={"to": "approved"}).status_code == 403  # needs risk.accept
    api_login(api, "admin")
    r = api.post(f"/api/registers/policy-exceptions/{e['id']}/move", json={"to": "approved"})
    assert r.status_code == 400 and "Compensating" in r.json()["detail"]
    api.patch(f"/api/registers/policy-exceptions/{e['id']}", json={"fields": {"compensating": "Kiosks on their own network"}})
    assert api.post(f"/api/registers/policy-exceptions/{e['id']}/move", json={"to": "approved"}).status_code == 200
    rows = api.get("/api/exceptions").json()
    pex = next(x for x in rows if x["type"] == "policy")
    assert pex["approved_by"] == "admin" and pex["state"] == "active" and pex["until"] == str(today() + timedelta(days=90))
    api_login(api, "viewer")
    assert api.get("/api/exceptions").status_code == 200
    api.post("/api/auth/logout")
    assert api.get("/api/exceptions").status_code == 401


def test_need_to_know_registers(api, ready_users, db):
    from keystone.people import service as ppl

    with db.session_scope() as s:
        pid = ppl.save_person(s, ready_users["admin"], full_name="Pat Doe", email="pat@example.example").id
    api_login(api, "ismsmanager")
    chk = _create(api, "screening", "Right to work", person=pid, check_type="right_to_work")
    assert chk["person_id"] == pid and chk["status"] == "pending"
    assert api.post(f"/api/registers/screening/{chk['id']}/move", json={"to": "concerns"}).status_code == 400  # needs a note
    assert api.post(f"/api/registers/screening/{chk['id']}/move", json={"to": "clear"}).json()["data"]["completed_on"] == str(today())
    assert api.get(f"/api/comments/register_entry/{chk['id']}").status_code == 404  # no comments on need-to-know records
    nda = _create(api, "confidentiality", "Employment contract", person=pid, agreement="employment_contract", signed_on=str(today()))
    assert nda["status"] == "signed"
    assert api.post("/api/registers/screening", json={"title": "x", "fields": {"person": 999999, "check_type": "identity"}}).status_code == 400
    api_login(api, "viewer")
    assert api.get(f"/api/comments/register_entry/{chk['id']}").status_code == 404
    assert api.get(f"/api/history/register_entry/{chk['id']}").status_code == 404
    assert api.post(f"/api/registers/screening/{chk['id']}/move", json={"to": "concerns", "note": "x"}).status_code == 403
    cal = api.get(f"/api/calendar?start={today()}&end={today() + timedelta(days=60)}").json()
    assert not any("Right to work" in x["title"] for x in cal)


def test_sites_visitors_and_physical_checks(api, ready_users):
    api_login(api, "riskowner")
    site = _create(api, "sites", "Head office server room", kind="server_room", zone="restricted")
    assert api.post("/api/registers/visitors", json={"title": "A. Visitor", "fields": {"site": 999999, "host": ready_users["risk_owner"].id, "arrived_on": str(today())}}).status_code == 400
    v = _create(api, "visitors", "A. Visitor", organisation="Fabrikam", site=site["id"], host=ready_users["risk_owner"].id, arrived_on=str(today()))
    assert api.post(f"/api/registers/visitors/{v['id']}/move", json={"to": "left"}).json()["data"]["left_on"] == str(today())
    last = date(2026, 1, 31)
    chk = _create(api, "physical-checks", "CCTV at head office", equipment="cctv", site=site["id"], every_months=1, last_done_on=last.isoformat())
    assert chk["due_on"] == "2026-02-28"  # a month after the last check, end of month kept in range
    ok = api.post(f"/api/registers/physical-checks/{chk['id']}/move", json={"to": "ok"}).json()
    assert ok["data"]["last_done_on"] == str(today()) and ok["due_on"] > str(today())
    api_login(api, "viewer")
    assert api.get("/api/registers/visitors").status_code == 403  # visitors' details: need-to-know
    assert api.get("/api/registers/sites").status_code == 200


# ---- reports of suspicious activity ------------------------------------------------------------------------------

def test_reporting_and_triage(api, ready_users, db):
    api_login(api, "employee")
    r = api.post("/api/portal/reports", json={"kind": "phishing", "description": "Invoice email with a link to sign in", "sender": "billing@fabrikam-pay.example",
                                               "subject": "Overdue invoice", "clicked": True})
    assert r.status_code == 200, r.text
    rid = r.json()["id"]
    assert api.post("/api/portal/reports", json={"kind": "nonsense", "description": "x"}).status_code == 400
    assert api.post("/api/portal/reports", json={"kind": "phishing", "description": "x", "reporter_id": 1}).status_code == 422
    assert [x["id"] for x in api.get("/api/portal/reports").json()["reports"]] == [rid]
    assert api.get("/api/security-reports").status_code == 403
    with db.session_scope() as s:
        notes = list(s.scalars(select(Notification).where(Notification.kind == "report")))
        assert notes and all("clicked" in n.title for n in notes)
    api_login(api, "viewer")  # someone else's report isn't theirs to see
    assert api.get("/api/portal/reports").json()["reports"] == []
    assert api.get("/api/security-reports").status_code == 403
    api_login(api, "controlowner")
    listed = api.get("/api/security-reports").json()["reports"]
    assert listed[0]["reporter"] == "Employee" and listed[0]["clicked"] is True
    out = api.post(f"/api/security-reports/{rid}/incident", json={"severity": "high"}).json()
    assert out["ref"].startswith("INC")
    assert api.post(f"/api/security-reports/{rid}/close", json={"outcome": "not_a_threat", "reply": "x"}).status_code == 400  # already triaged
    inc = api.get(f"/api/incidents/{out['incident_id']}").json()
    assert inc["category"] == "phishing" and "billing@fabrikam-pay.example" in inc["description"]
    api_login(api, "employee")
    mine = api.get("/api/portal/reports").json()["reports"][0]
    assert mine["status"] == "incident" and mine["reply"] and "incident_id" not in mine  # the incident stays with the team
    r2 = api.post("/api/portal/reports", json={"kind": "physical", "description": "Door to the server room propped open"}).json()["id"]
    api_login(api, "controlowner")
    assert api.post(f"/api/security-reports/{r2}/close", json={"outcome": "not_a_threat"}).status_code == 422  # a reply is required
    assert api.post(f"/api/security-reports/{r2}/close", json={"outcome": "not_a_threat", "reply": "Closed and the alarm checked. Thank you."}).status_code == 200


# ---- leaver access check -----------------------------------------------------------------------------------------

def test_leaver_access_check(api, ready_users, db):
    from keystone.asm.models import AsmIdentity
    from keystone.people import service as ppl

    admin = ready_users["admin"]
    with db.session_scope() as s:
        p = ppl.save_person(s, admin, full_name="Leaving Person", email="leaver@example.example", end_date=today() - timedelta(days=3))
        ppl.link_user(s, admin, p.id, ready_users["viewer"].id)
        s.add(AsmIdentity(source="entra", upn="leaver@example.example", display_name="Leaving Person", properties={"account_enabled": True}))
        s.add(AsmIdentity(source="entra", upn="svc-backup@example.example", display_name="Backup", properties={"account_enabled": True}))
        s.add(AsmIdentity(source="entra", upn="disabled@example.example", display_name="Old", properties={"account_enabled": False}))
    api_login(api, "viewer")
    assert api.get("/api/access-check").status_code == 403
    api_login(api, "ismsmanager")
    f = api.get("/api/access-check").json()["findings"]
    leavers = [x for x in f if x["kind"] == "leaver"]
    assert {x["source"] for x in leavers} == {"Keystone", "entra"} and all(x["severity"] == "high" for x in leavers)
    orphan = next(x for x in f if x["account"] == "svc-backup@example.example")
    assert orphan["kind"] == "orphan" and not any(x["account"] == "disabled@example.example" for x in f)
    assert api.post("/api/access-check/exemptions", json={"account": orphan["key"], "note": "Backup service account"}).status_code == 200
    assert api.post("/api/access-check/exemptions", json={"account": orphan["key"], "note": "again"}).status_code == 400
    assert not any(x["account"] == "svc-backup@example.example" for x in api.get("/api/access-check").json()["findings"])

