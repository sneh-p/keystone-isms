"""Phase 5: vendors, tiering, questionnaires, FAIR vendor assessments."""

from datetime import date, timedelta

import pytest

from keystone.core.rbac import PermissionDenied
from keystone.tprm import service as tprm


@pytest.mark.parametrize(
    "args,tier",
    [
        (("restricted", "high", "tenant_wide", True), 1),
        (("confidential", "medium", "delegated", False), 2),
        (("internal", "low", "sso", False), 4),
        (("internal", "medium", "none", False), 3),
        (("none", "low", "none", False), 4),
    ],
)
def test_compute_tier(args, tier):
    assert tprm.compute_tier(*args) == tier


def _vendor(session, actor, **kw):
    base = dict(name="Fabrikam Backup", website="https://fabrikambackup.example", status="active", data_sensitivity="restricted", operational_criticality="high", access_level="tenant_wide", processes_personal_data=True)
    return tprm.save_vendor(session, actor, **{**base, **kw})


def test_vendor_save_tier_and_review(users, session):
    v = _vendor(session, users["isms_manager"])
    assert v.tier == 1 and v.next_review_date == date.today() + timedelta(days=180)
    tprm.save_vendor(session, users["isms_manager"], v.id, tier_override=3, tier_override_reason="Only test data")
    assert v.tier == 3 and v.computed_tier == 1


@pytest.mark.parametrize(
    "bad,msg",
    [
        ({"tier_override": 2}, "Explain"),
        ({"tier_override": 7, "tier_override_reason": "x"}, "1-4"),
        ({"access_level": "god"}, "access_level"),
        ({"website": "javascript:alert(1)"}, "Website"),
        ({"contract_start": date(2026, 1, 1), "contract_end": date(2025, 1, 1)}, "before"),
    ],
)
def test_vendor_validation(users, session, bad, msg):
    with pytest.raises(ValueError, match=msg):
        _vendor(session, users["admin"], **bad)


@pytest.mark.parametrize("value,ok", [("fabrikam.example", "https://fabrikam.example"), ("http://a.b.example/x", "http://a.b.example/x"), ("javascript:alert(1)", None), ("https://user:pw@evil.example", None), ("not a host", None), ("ftp://x.example", None)])
def test_normalise_website(value, ok):
    if ok:
        assert tprm.normalise_website(value) == ok
    else:
        with pytest.raises(ValueError):
            tprm.normalise_website(value)


def test_vendor_unique_and_permission(users, session):
    _vendor(session, users["admin"])
    with pytest.raises(ValueError, match="already exists"):
        _vendor(session, users["admin"])
    with pytest.raises(PermissionDenied):
        _vendor(session, users["risk_owner"], name="Other")


def test_vendor_attention(users, session):
    v = _vendor(session, users["admin"], contract_end=date.today() + timedelta(days=30), dpa_signed=False)
    att = tprm.vendor_attention(session)
    assert v in att["contract_ending"] and v in att["needs_assessment"] and v in att["no_dpa"]
    v.next_review_date = date.today() - timedelta(days=1)
    assert v in tprm.vendor_attention(session)["review_overdue"]
    tprm.mark_vendor_reviewed(session, users["admin"], v.id)
    assert v not in tprm.vendor_attention(session)["review_overdue"]


# ---- questionnaires -------------------------------------------------------------------------

def test_default_template_loads_once(users, session):
    t1 = tprm.load_default_templates(session, users["admin"])
    t2 = tprm.load_default_templates(session, users["admin"])
    assert len(t1) == 1 and t1[0].id == t2[0].id and len(t1[0].questions) >= 20


def test_template_validation(users, session):
    with pytest.raises(ValueError, match="unique"):
        tprm.save_template(session, users["admin"], name="T", version="1", questions=[{"id": "a", "type": "yn", "text": "x"}, {"id": "a", "type": "yn", "text": "y"}])
    with pytest.raises(ValueError, match="type"):
        tprm.save_template(session, users["admin"], name="T", version="1", questions=[{"id": "a", "type": "essay", "text": "x"}])


QS = [
    {"id": "a", "type": "yn", "text": "A?", "weight": 3, "required": True, "control": "KC-TEC-05"},
    {"id": "b", "type": "ynp", "text": "B?", "weight": 1},
    {"id": "c", "type": "ynp", "text": "C?", "weight": 2},
    {"id": "d", "type": "text", "text": "Other?", "weight": 0},
]


def test_scoring_and_findings():
    score, findings = tprm.score_responses(QS, {"a": {"answer": "yes"}, "b": {"answer": "partial"}, "c": {"answer": "na"}})
    assert score == pytest.approx(100 * 3.5 / 4, abs=0.1)
    assert [f["id"] for f in findings] == ["b"]
    assert tprm.score_responses(QS, {})[0] is None
    _, f2 = tprm.score_responses(QS, {"a": {"answer": "no"}, "b": {"answer": "no"}})
    assert [f["id"] for f in f2] == ["a", "b"]  # heaviest first


def test_questionnaire_flow(users, session):
    mgr = users["isms_manager"]
    v = _vendor(session, mgr)
    t = tprm.save_template(session, mgr, name="T", version="1", questions=QS)
    q = tprm.send_questionnaire(session, mgr, v.id, t.id, due_date=date.today() - timedelta(days=1))
    assert v in tprm.vendor_attention(session)["questionnaire_overdue"]
    with pytest.raises(ValueError, match="Unknown question"):
        tprm.record_responses(session, mgr, q.id, {"zz": {"answer": "yes"}})
    with pytest.raises(ValueError, match="answer must be"):
        tprm.record_responses(session, mgr, q.id, {"a": {"answer": "partial"}})
    tprm.record_responses(session, mgr, q.id, {"b": {"answer": "yes"}})
    with pytest.raises(ValueError, match="Required"):
        tprm.record_responses(session, mgr, q.id, {}, complete=True)
    tprm.record_responses(session, mgr, q.id, {"a": {"answer": "yes", "comment": " MFA everywhere "}}, complete=True)
    assert q.status == "received" and q.score == 100.0 and q.responses["a"]["comment"] == "MFA everywhere"
    tprm.review_questionnaire(session, mgr, q.id, "Looks fine")
    with pytest.raises(ValueError, match="locked"):
        tprm.record_responses(session, mgr, q.id, {"b": {"answer": "no"}})


# ---- FAIR vendor assessments ---------------------------------------------------------------------

RANGES = dict(tef=[0.2, 1, 3], tcap=[0.4, 0.6, 0.9], control_strength=[0.5, 0.7, 0.9], plm=[50_000, 200_000, 1_000_000])


def test_assessment_flow_and_sod(users, session):
    mgr, admin = users["isms_manager"], users["admin"]
    v = _vendor(session, mgr)
    a = tprm.save_assessment(session, mgr, v.id, title="Annual assessment", integration_depth="Tenant-wide application access", **RANGES)
    assert a.tef == {"min": 0.2, "ml": 1.0, "max": 3.0}
    with pytest.raises(ValueError, match="Run the FAIR"):
        tprm.submit_assessment(session, mgr, a.id)
    res = tprm.run_assessment(session, mgr, a.id, iterations=2000, seed=1)
    assert a.result["ale_mean"] == res.ale_mean
    tprm.submit_assessment(session, mgr, a.id)
    with pytest.raises(ValueError, match="Segregation"):
        tprm.approve_assessment(session, mgr, a.id, "ok")
    with pytest.raises(PermissionDenied):
        tprm.approve_assessment(session, users["risk_owner"], a.id, "ok")
    tprm.approve_assessment(session, admin, a.id, "Acceptable with backup immutability")
    assert a.status == "approved" and tprm.latest_approved_assessment(session, v.id) is a
    assert v not in tprm.vendor_attention(session)["needs_assessment"]
    with pytest.raises(ValueError, match="locked"):
        tprm.save_assessment(session, mgr, v.id, a.id, title="edit")


def test_assessment_needs_inputs(users, session):
    v = _vendor(session, users["admin"])
    a = tprm.save_assessment(session, users["admin"], v.id, title="x", tef=[1, 2, 3])
    with pytest.raises(ValueError, match="needed"):
        tprm.run_assessment(session, users["admin"], a.id)
    with pytest.raises(ValueError, match="min <= most likely"):
        tprm.save_assessment(session, users["admin"], v.id, a.id, plm=[3, 2, 1])
