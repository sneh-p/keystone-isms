"""Phase 9: internal audits, findings -> nonconformities, coverage, management review."""

from datetime import date, timedelta

import pytest

from keystone.audits import review as mr
from keystone.audits import service as aud
from keystone.core.rbac import PermissionDenied
from keystone.frameworks.service import control_by_code


def _audit(session, users, content=None, **kw):
    ctl = [control_by_code(session, c).id for c in ("KC-ORG-18", "KC-TEC-05")]
    return aud.save_audit(session, users["isms_manager"], control_ids=ctl, **{"title": "Access control audit", "lead_auditor_id": users["auditor"].id, "planned_start": date.today(), **kw})


def test_audit_lifecycle_and_findings_raise_ncs(content, session, users):
    a = _audit(session, users)
    with pytest.raises(ValueError, match="in progress"):
        aud.add_finding(session, users["auditor"], a.id, finding_type="minor_nc", title="x")
    aud.advance(session, users["isms_manager"], a.id)
    f1 = aud.add_finding(session, users["auditor"], a.id, finding_type="minor_nc", title="Leaver access not removed", evidence="3 of 20 sampled leavers still active", common_control_id=control_by_code(session, "KC-ORG-18").id)
    f2 = aud.add_finding(session, users["auditor"], a.id, finding_type="observation", title="Review evidence scattered")
    assert f1.nonconformity_id and f2.nonconformity_id is None
    from keystone.improvement.models import Nonconformity
    nc = session.get(Nonconformity, f1.nonconformity_id)
    assert nc.source == "internal_audit" and nc.severity == "minor" and "3 of 20" in nc.description and nc.created_by_id == users["auditor"].id
    with pytest.raises(PermissionDenied):
        aud.add_finding(session, users["viewer"], a.id, finding_type="observation", title="x")
    aud.advance(session, users["isms_manager"], a.id)
    with pytest.raises(ValueError, match="summary"):
        aud.advance(session, users["isms_manager"], a.id)
    aud.save_audit(session, users["isms_manager"], a.id, summary="Sampled 20 leavers", conclusion="Partially effective")
    aud.advance(session, users["isms_manager"], a.id)
    assert a.status == "closed" and a.closed_at
    with pytest.raises(ValueError, match="Closed"):
        aud.save_audit(session, users["isms_manager"], a.id, title="x")


def test_auditor_objectivity(content, session, users):
    c = control_by_code(session, "KC-TEC-05")
    c.owner_id = users["auditor"].id
    a = _audit(session, users)
    assert aud.independence_conflicts(a) == ["KC-TEC-05"]
    with pytest.raises(ValueError, match="Objectivity"):
        aud.advance(session, users["isms_manager"], a.id)
    aud.save_audit(session, users["isms_manager"], a.id, lead_auditor_id=users["admin2"].id)
    aud.advance(session, users["isms_manager"], a.id)


def test_needs_lead_auditor(content, session, users):
    a = _audit(session, users, lead_auditor_id=None)
    with pytest.raises(ValueError, match="lead auditor"):
        aud.advance(session, users["isms_manager"], a.id)


def test_control_coverage(content, session, users):
    before = aud.control_coverage(session)
    assert before["audited"] == 0 and before["applicable"] == 128  # 107 + 11 privacy + 10 AI governance controls
    a = _audit(session, users)
    assert aud.control_coverage(session)["audited"] == 0  # planned audits don't count
    aud.advance(session, users["isms_manager"], a.id)
    cov = aud.control_coverage(session)
    assert cov["audited"] == 2 and "KC-ORG-18" not in cov["not_audited"]


def test_management_review_inputs_and_finalise(content, session, users):
    from keystone.org import service as org
    from keystone.risk import service as risk

    mgr = users["isms_manager"]
    org.save_org(session, users["admin"], name="Org", internal_issues="Small team")
    risk.save_risk(session, mgr, title="Big risk", inherent_likelihood=5, inherent_impact=5)
    a = _audit(session, users)
    aud.advance(session, mgr, a.id)
    aud.add_finding(session, users["auditor"], a.id, finding_type="major_nc", title="No MFA for admins")
    aud.advance(session, mgr, a.id)
    aud.save_audit(session, mgr, a.id, summary="s", conclusion="c")
    aud.advance(session, mgr, a.id)

    r = mr.create_review(session, mgr, title="Q4 management review", held_on=date.today(), attendees="CEO, CISO")
    i = r.inputs
    assert i["b_issues"]["internal"] == "Small team"
    assert i["d1_nonconformities"]["open_major"] == 1
    assert i["d3_audits"]["findings"] == {"major_nc": 1}
    assert i["f_risk"]["by_level"] == {"Critical": 1} and i["f_risk"]["above_appetite_untreated"] == ["RSK-0001 Big risk"]
    from keystone.frameworks.models import Framework

    enabled = {f.code for f in session.query(Framework).filter(Framework.enabled.is_(True))}
    assert set(i["d2_monitoring"]["framework_implemented_pct"]) == enabled and "ISO27001_2022" in enabled
    assert r.period_start == date.today() - timedelta(days=365)

    item = mr.raise_improvement(session, mgr, r.id, "Fund phishing-resistant MFA")
    assert item.source == "management_review"
    with pytest.raises(ValueError, match="Decisions"):
        mr.finalize(session, mgr, r.id)
    mr.update_review(session, mgr, r.id, decisions="Approve MFA budget", actions="CISO to deliver by Q2")
    mr.finalize(session, mgr, r.id)
    frozen = dict(r.inputs)
    with pytest.raises(ValueError, match="cannot be changed"):
        mr.update_review(session, mgr, r.id, decisions="x")
    with pytest.raises(ValueError, match="keep the inputs"):
        mr.refresh_inputs(session, mgr, r.id)
    assert r.inputs == frozen

    r2 = mr.create_review(session, mgr, title="Next review", held_on=date.today() + timedelta(days=90))
    assert r2.period_start == date.today()
    assert r2.inputs["a_previous_actions"]["previous_actions"] == "CISO to deliver by Q2"
    assert "Fund phishing-resistant MFA" in r2.inputs["a_previous_actions"]["open_items_from_reviews"][0]


def test_review_permissions(content, session, users):
    with pytest.raises(PermissionDenied):
        mr.create_review(session, users["risk_owner"], title="x", held_on=date.today())
