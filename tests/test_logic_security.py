"""Business-logic security review (round 6): workflows can't be short-circuited, and approvals keep their meaning.

Each test reproduces a way round a rule that the API allowed before the fix.
"""

from datetime import date, timedelta

import pytest

from keystone.core.db import utcnow
from keystone.improvement import service as imp
from keystone.incidents import service as inc
from keystone.risk import service as risk
from keystone.tprm import service as tprm

from .conftest import api_login


# ---- risk acceptance -------------------------------------------------------------------------------------------------

def _risk(session, actor, **kw):
    return risk.save_risk(session, actor, **{"title": "Booking data leaked by a supplier", "category": "third_party", "inherent_likelihood": 2, "inherent_impact": 2, **kw})


def test_acceptance_lapses_when_the_risk_rises_above_what_was_accepted(users, session):
    """Accepting a Low risk for years and then raising it to Critical must not leave a Critical risk accepted."""
    r = _risk(session, users["risk_owner"])
    acc = risk.accept_risk(session, users["admin"], r.id, "Low impact", expires_on=date.today() + timedelta(days=3 * 365))
    assert r.status == "accepted"
    risk.save_risk(session, users["risk_owner"], r.id, inherent_likelihood=5, inherent_impact=5)
    assert acc.revoked_at is not None and risk.active_acceptance(r) is None and r.status == "assessed"


def test_acceptance_stays_when_the_risk_falls(users, session):
    r = _risk(session, users["risk_owner"], inherent_likelihood=3, inherent_impact=3)
    acc = risk.accept_risk(session, users["admin"], r.id, "Medium, tolerable")
    risk.save_risk(session, users["risk_owner"], r.id, inherent_likelihood=1)
    assert acc.revoked_at is None and r.status == "accepted"


def test_whoever_accepted_a_risk_cannot_take_it_over_while_accepted(users, session):
    """Segregation of duties round trip: hand the risk to someone else, accept it, take it back."""
    mgr = users["isms_manager"]
    r = _risk(session, mgr, owner_id=mgr.id)
    risk.save_risk(session, mgr, r.id, owner_id=users["risk_owner"].id)
    risk.accept_risk(session, mgr, r.id, "Accepted while someone else owned it")
    with pytest.raises(ValueError, match="Segregation of duties"):
        risk.save_risk(session, mgr, r.id, owner_id=mgr.id)
    risk.save_risk(session, mgr, r.id, owner_id=users["admin2"].id)  # anyone else may take it over


# ---- incidents -------------------------------------------------------------------------------------------------------

def _incident(session, actor, **kw):
    return inc.report_incident(session, actor, **{"title": "Guest list emailed to the wrong recipient", "category": "data_breach", "severity": "high", **kw})


def test_a_contained_incident_cannot_be_closed_as_a_false_positive(users, session):
    """Closing as "false positive" skipped the root cause, lessons learned and regulator notification checks."""
    u = users["control_owner"]
    i = _incident(session, u, personal_data_involved=True, notification_required=True, detected_at=utcnow() - timedelta(hours=80))
    for st in ("triage", "contained", "eradicated", "recovered"):
        inc.move(session, u, i.id, st)
    with pytest.raises(ValueError, match="(?i)false positive|duplicate"):
        inc.move(session, u, i.id, "closed", "false_positive")
    with pytest.raises(ValueError, match="notification|root cause"):
        inc.move(session, u, i.id, "closed")


def test_a_reopened_real_incident_cannot_be_closed_as_a_duplicate(users, session):
    u = users["control_owner"]
    i = _incident(session, u)
    inc.move(session, u, i.id, "triage")
    inc.move(session, u, i.id, "contained")
    inc.move(session, u, i.id, "eradicated")
    inc.move(session, u, i.id, "recovered")
    inc.update_incident(session, u, i.id, root_cause="Autocomplete picked the wrong address", lessons_learned="Turn off autocomplete for guest lists")
    inc.move(session, u, i.id, "closed")
    inc.move(session, u, i.id, "triage")  # reopened
    with pytest.raises(ValueError, match="(?i)false positive|duplicate"):
        inc.move(session, u, i.id, "closed", "duplicate")


def test_triage_can_still_close_false_positives(users, session):
    u = users["control_owner"]
    i = _incident(session, u)
    inc.move(session, u, i.id, "triage")
    inc.move(session, u, i.id, "closed", "false_positive")
    assert i.status == "closed" and i.resolution == "false_positive"


# ---- corrective actions ----------------------------------------------------------------------------------------------

def test_whoever_completed_a_corrective_action_cannot_verify_it(users, session):
    """The owner check alone let a manager complete someone else's (or an unowned) action and verify it themselves."""
    mgr = users["isms_manager"]
    for owner_id in (users["control_owner"].id, None):
        nc = imp.raise_nc(session, mgr, title="Leavers keep access", root_cause="No HR feed")
        a = imp.add_action(session, mgr, nc.id, "Automate the leaver feed", owner_id=owner_id)
        imp.plan(session, mgr, nc.id)
        imp.complete_action(session, mgr, a.id, "Done")
        assert a.completed_by_id == mgr.id
        with pytest.raises(ValueError, match="Segregation of duties"):
            imp.verify_action(session, mgr, a.id, True, "Looks fine")
        imp.verify_action(session, users["admin"], a.id, True, "No leavers with access in 4 weeks")


# ---- vendors ---------------------------------------------------------------------------------------------------------

def test_an_active_vendor_cannot_skip_offboarding_via_prospective(users, session):
    mgr = users["isms_manager"]
    v = tprm.save_vendor(session, mgr, name="Fabrikam Backup", status="active")
    with pytest.raises(ValueError, match="(?i)prospective"):
        tprm.save_vendor(session, mgr, v.id, status="prospective")
    session.expire(v)  # the API rolls a refused request back
    with pytest.raises(ValueError, match="offboarding checklist"):
        tprm.save_vendor(session, mgr, v.id, status="terminated")


# ---- audit evidence requests -----------------------------------------------------------------------------------------

def test_whoever_answered_an_evidence_request_cannot_accept_it(users, session):
    from keystone.audits import service as audits

    mgr, auditor = users["isms_manager"], users["auditor"]
    a = audits.save_audit(session, mgr, title="Internal audit: access control", audit_type="internal", planned_start=date.today(), lead_auditor_id=auditor.id)
    r = audits.add_request(session, auditor, a.id, title="Leaver access report", description="Last quarter")
    with pytest.raises(ValueError, match="(?i)provided"):
        audits.set_request_status(session, auditor, r.id, "accepted")  # nothing was provided yet
    audits.respond_request(session, mgr, r.id, body="Attached the quarterly report")
    assert r.provided_by_id == mgr.id
    with pytest.raises(ValueError, match="Segregation of duties"):
        audits.set_request_status(session, mgr, r.id, "accepted")
    audits.set_request_status(session, auditor, r.id, "accepted")
    assert r.status == "accepted"


# ---- Trust Center ----------------------------------------------------------------------------------------------------

def test_trust_center_access_is_bounded(api, ready_users):
    api_login(api, "admin")
    for days in (0, -1, 366, 10**9):
        assert api.post("/api/trust-center/requests/1/approve", json={"days": days}).status_code == 422
