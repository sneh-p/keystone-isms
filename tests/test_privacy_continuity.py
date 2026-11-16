"""Privacy (RoPA, DPIA, data subject requests, breach log) and business continuity (BIA, plans, tests)."""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from sqlalchemy import select

from keystone.continuity import service as bc
from keystone.core.audit import AuditLog
from keystone.core.rbac import PermissionDenied
from keystone.core.services import add_months
from keystone.privacy import service as pv
from keystone.privacy.models import DataSubjectRequest

from .conftest import api_login


def test_add_months_clamps_to_month_end():
    assert add_months(date(2026, 1, 31), 1) == date(2026, 2, 28)
    assert add_months(date(2028, 1, 31), 1) == date(2028, 2, 29)
    assert add_months(date(2026, 11, 16), 3) == date(2027, 2, 16)


def test_processing_records_are_validated(users, db):
    mgr = users["isms_manager"]
    with db.session_scope(mgr) as s:
        a = pv.save_activity(s, mgr, name="Guest bookings", purpose="Take and manage hotel bookings", lawful_basis="contract", data_subjects="Guests",
                             vendor_ids=[1], transfers="", transfer_safeguard="none")
        assert a.next_review_date and a.ref.startswith("ROPA-")
        aid = a.id
    for bad, msg in (({"lawful_basis": "legitimate_interests"}, "legitimate interest"), ({"special_category": True}, "Article 9"),
                     ({"transfers": "USA"}, "safeguard"), ({"lawful_basis": "because"}, "lists")):
        with pytest.raises(ValueError, match=msg), db.session_scope(mgr) as s:  # rolled back, as the API does
            pv.save_activity(s, mgr, aid, **bad)
    with db.session_scope() as s, pytest.raises(PermissionDenied):
        pv.save_activity(s, users["risk_owner"], name="x", purpose="y")


def test_dpia_needs_content_and_an_independent_decision(users, session):
    mgr, admin = users["isms_manager"], users["admin"]
    d = pv.save_dpia(session, mgr, title="CCTV in hotel lobbies")
    with pytest.raises(ValueError, match="necessity"):
        pv.submit_dpia(session, mgr, d.id)
    pv.save_dpia(session, mgr, d.id, necessity="Theft prevention; no less intrusive option", outcome="proceed_with_measures",
                 risks=[{"risk": "Staff monitored", "likelihood": 2, "severity": 2, "measures": "No cameras in staff areas", "residual": 1}])
    pv.submit_dpia(session, mgr, d.id)
    with pytest.raises(ValueError, match="Segregation of duties"):
        pv.decide_dpia(session, mgr, d.id, True, "ok")
    with pytest.raises(PermissionDenied):
        pv.decide_dpia(session, users["control_owner"], d.id, True, "ok")
    pv.decide_dpia(session, admin, d.id, True, "Measures are adequate")
    assert d.status == "approved" and d.decided_by_id == admin.id
    with pytest.raises(ValueError, match="decided DPIA"):
        pv.save_dpia(session, mgr, d.id, title="changed")
    with pytest.raises(ValueError):
        pv.save_dpia(session, mgr, title="x", risks=[{"risk": "r", "residual": 7}])


def test_requests_deadlines_identity_and_redaction(users, db):
    mgr = users["isms_manager"]
    with db.session_scope(mgr) as s:
        r = pv.save_request(s, mgr, request_type="access", received_on=date(2026, 1, 31), requester_name="Jo Guest", requester_contact="jo@guest.example")
        assert r.due_date == date(2026, 2, 28)
        with pytest.raises(ValueError, match="identity"):
            pv.move_request(s, mgr, r.id, "in_progress")
        pv.save_request(s, mgr, r.id, identity_verified=True)
        pv.extend_request(s, mgr, r.id, "Large volume of records across three systems")
        assert r.due_date == date(2026, 4, 30)
        with pytest.raises(ValueError, match="only once"):
            pv.extend_request(s, mgr, r.id, "again")
        with pytest.raises(ValueError, match="Outcome"):
            pv.move_request(s, mgr, r.id, "completed")
        pv.move_request(s, mgr, r.id, "completed", "Copy of data sent by secure link")
        rid = r.id
    with db.session_scope() as s:  # the audit log never holds the requester's details
        assert not any("Jo Guest" in str(a.changes) or "jo@guest" in str(a.changes) for a in s.scalars(select(AuditLog)))
        r = s.get(DataSubjectRequest, rid)
        r.closed_on = date.today() - timedelta(days=400)
    with db.session_scope() as s:
        assert pv.redact_closed_requests(s) == 1
        r = s.get(DataSubjectRequest, rid)
        assert r.requester_name is None and r.requester_contact is None and r.redacted_at and r.outcome
        assert pv.redact_closed_requests(s) == 0
    with db.session_scope() as s:
        with pytest.raises(PermissionDenied):  # need to know
            pv.requests(s, users["auditor"])
        with pytest.raises(ValueError, match="future"):
            pv.save_request(s, mgr, request_type="access", received_on=date.today() + timedelta(days=2))


def test_breach_log_and_assessment(users, session):
    from keystone.core.db import utcnow
    from keystone.incidents import service as inc

    mgr = users["isms_manager"]
    i = inc.report_incident(session, mgr, title="Booking export emailed to wrong address", severity="high", personal_data_involved=True, notification_required=True)
    other = inc.report_incident(session, mgr, title="Printer jam", severity="low", personal_data_involved=False)
    att = pv.attention(session)
    assert [x.id for x in att["breaches_unassessed"]] == [i.id]
    with pytest.raises(ValueError, match="normally isn't notifiable"):
        pv.assess_breach(session, mgr, i.id, risk_level="no_risk")
    session.rollback()
    i = session.merge(i)
    b = pv.assess_breach(session, mgr, i.id, risk_level="risk", subjects_affected=120, data_categories="Names, booking dates", rationale="Notified")
    log = {x["incident"].id: x for x in pv.breaches(session, mgr)}
    assert i.id in log and other.id not in log and log[i.id]["assessment"].id == b.id
    i.detected_at = utcnow() - timedelta(hours=80)
    assert {x["incident"].id: x for x in pv.breaches(session, mgr)}[i.id]["late"] is True  # 72 h passed, not notified
    assert pv.attention(session)["breaches_unassessed"] == []


def test_business_impact_plans_and_tests(users, db, content):
    from keystone.controls.models import Evidence
    from keystone.improvement.models import Nonconformity

    ro = users["risk_owner"]
    with db.session_scope(ro) as s:
        p = bc.save_process(s, ro, name="Online bookings", criticality="critical", mtpd_hours=24, rto_hours=8, rpo_hours=1, impact={"financial": 5, "reputational": 4})
        pid = p.id
    with pytest.raises(ValueError, match="RTO can't be longer"), db.session_scope(ro) as s:
        bc.save_process(s, ro, pid, rto_hours=48)
    with db.session_scope(ro) as s:
        assert [x.id for x in bc.attention(s)["processes_without_plan"]] == [pid]
        plan = bc.save_plan(s, ro, title="Booking platform recovery", process_ids=[pid], owner_id=ro.id)
        assert bc.attention(s)["processes_without_plan"] == [] and plan in bc.attention(s)["plans_test_due"]  # never tested
        tid = bc.plan_test(s, ro, plan_id=plan.id, title="Restore from backup", test_type="backup_restore").id
        plan_id = plan.id
    with pytest.raises(ValueError, match="can't be recorded as passed"), db.session_scope(ro) as s:
        bc.complete_test(s, ro, tid, performed_on=date.today(), outcome="passed", results=[{"process_id": pid, "recovered_hours": 12, "data_loss_hours": 0.5}])
    with db.session_scope(ro) as s:
        done = bc.complete_test(s, ro, tid, performed_on=date.today(), outcome="passed_with_issues", findings="Restore took 12 h; runbook out of date",
                                results=[{"process_id": pid, "recovered_hours": 12, "data_loss_hours": 0.5}], raise_nc=True)
        assert done.results[0]["met_rto"] is False and done.results[0]["met_rpo"] is True
        nc = s.get(Nonconformity, done.nonconformity_id)
        assert nc.severity == "minor" and "Restore from backup" in nc.title
        assert s.scalars(select(Evidence).where(Evidence.title.like(f"Continuity test {done.ref}%"))).all()
        assert plan_id not in [x.id for x in bc.attention(s)["plans_test_due"]]  # next due in 12 months
    with db.session_scope() as s, pytest.raises(PermissionDenied):
        bc.save_plan(s, users["viewer"], title="x")


def test_privacy_and_continuity_api(api, ready_users, db):
    assert api.get("/api/privacy/activities").status_code == 401
    api_login(api, ready_users["auditor"].username)
    assert api.get("/api/privacy/activities").status_code == 200
    assert api.get("/api/privacy/requests").status_code == 403  # personal data: privacy.write only
    assert api.post("/api/continuity/processes", json={"name": "x"}).status_code == 403
    api.post("/api/auth/logout")
    api_login(api, ready_users["isms_manager"].username)
    r = api.post("/api/privacy/requests", json={"request_type": "erasure", "received_on": "2026-11-01", "requester_name": "A Person"})
    assert r.status_code == 200 and r.json()["due_date"] == "2026-12-01"
    assert api.post("/api/privacy/requests", json={"request_type": "erasure", "received_on": "2026-11-01", "status": "completed"}).status_code == 422
    assert api.post("/api/continuity/processes", json={"name": "Payroll", "rto_hours": -1}).status_code == 422
    r = api.post("/api/continuity/processes", json={"name": "Payroll", "criticality": "high", "rto_hours": 48, "mtpd_hours": 72})
    pid = r.json()["id"]
    plan = api.post("/api/continuity/plans", json={"title": "Payroll continuity", "process_ids": [pid]}).json()
    assert api.get("/api/continuity/plans").json()[0]["test_due_on"] == date.today().isoformat()
    t = api.post("/api/continuity/tests", json={"plan_id": plan["id"], "title": "Tabletop"}).json()
    r = api.post(f"/api/continuity/tests/{t['id']}/complete", json={"performed_on": date.today().isoformat(), "outcome": "passed", "results": [{"process_id": pid, "recovered_hours": 24}]})
    assert r.status_code == 200 and r.json()["results"][0]["met_rto"] is True
