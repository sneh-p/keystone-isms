"""Phase 3: assets, qualitative risk scoring, lifecycle, acceptance, FAIR engine."""

from datetime import date, timedelta

import numpy as np
import pytest
from sqlalchemy import select

from keystone.assets import service as assets
from keystone.core.audit import AuditLog
from keystone.core.rbac import PermissionDenied
from keystone.risk import fair
from keystone.risk import service as risk
from keystone.risk.models import Risk


# ---- assets --------------------------------------------------------------------------

def test_asset_crud_and_criticality(users, session):
    a = assets.save_asset(session, users["risk_owner"], name="Customer DB", asset_type="information", classification="restricted", confidentiality=5, integrity=4, availability=3, contains_personal_data=True)
    assert a.criticality == 5 and a.ref == "AST-0001"
    assets.save_asset(session, users["risk_owner"], a.id, status="retired")
    assert assets.list_assets(session) == []
    assert len(assets.list_assets(session, include_retired=True)) == 1


@pytest.mark.parametrize("bad", [{"asset_type": "spaceship"}, {"classification": "secret"}, {"confidentiality": 6}, {"name": " "}])
def test_asset_validation(users, session, bad):
    with pytest.raises(ValueError):
        assets.save_asset(session, users["admin"], **{"name": "X", **bad})


def test_asset_requires_permission(users, session):
    with pytest.raises(PermissionDenied):
        assets.save_asset(session, users["viewer"], name="X")


# ---- matrix ------------------------------------------------------------------------------

@pytest.mark.parametrize("lk,im,level", [(1, 1, "Low"), (1, 4, "Low"), (5, 1, "Medium"), (3, 3, "Medium"), (2, 5, "High"), (4, 4, "High"), (4, 5, "Critical"), (5, 5, "Critical"), (None, 3, None)])
def test_matrix_levels(lk, im, level):
    assert risk.load_matrix().level(lk, im) == level


def test_appetite():
    m = risk.load_matrix()
    assert not m.above_appetite("Medium") and m.above_appetite("High") and not m.above_appetite(None)


# ---- lifecycle --------------------------------------------------------------------------

def _risk(session, actor, **kw):
    base = dict(title="Ransomware on file servers", category="technology", inherent_likelihood=4, inherent_impact=5, owner_id=None)
    base.update(kw)
    return risk.save_risk(session, actor, **base)


def test_create_assess_and_review_date(users, session):
    r = _risk(session, users["risk_owner"])
    assert r.status == "assessed" and risk.inherent_level(r) == "Critical"
    assert r.review_date == date.today() + timedelta(days=90)
    assert r.ref == "RSK-0001"


def test_risk_links_assets_and_controls(users, session, content):
    from keystone.frameworks.service import control_by_code
    a = assets.save_asset(session, users["admin"], name="File server", asset_type="hardware")
    c = control_by_code(session, "KC-TEC-13")
    r = _risk(session, users["admin"], asset_ids=[a.id], control_ids=[c.id])
    assert [x.name for x in r.assets] == ["File server"] and r.controls[0].code == "KC-TEC-13"


def test_validation(users, session):
    with pytest.raises(ValueError, match="both residual"):
        _risk(session, users["admin"], residual_likelihood=2)
    with pytest.raises(ValueError):
        _risk(session, users["admin"], category="cosmic")


def test_status_rules(users, session):
    owner = users["risk_owner"]
    r = _risk(session, owner)
    with pytest.raises(ValueError, match="treatment option"):
        risk.set_status(session, owner, r.id, "treatment")
    risk.save_risk(session, owner, r.id, treatment_option="mitigate")
    risk.set_status(session, owner, r.id, "treatment")
    with pytest.raises(ValueError, match="residual"):
        risk.set_status(session, owner, r.id, "monitoring")
    with pytest.raises(ValueError, match="acceptance"):
        risk.set_status(session, owner, r.id, "accepted")
    a = risk.save_action(session, owner, r.id, title="Immutable backups", due_date=date.today() - timedelta(days=1))
    assert r in risk.needs_attention([r])["actions_overdue"]
    with pytest.raises(ValueError, match="still open"):
        risk.set_status(session, owner, r.id, "closed")
    risk.save_action(session, owner, r.id, a.id, status="done")
    assert a.completed_at is not None
    risk.save_risk(session, owner, r.id, residual_likelihood=2, residual_impact=4)
    risk.set_status(session, owner, r.id, "monitoring")
    assert risk.current_level(r) == "Medium"
    risk.set_status(session, owner, r.id, "closed")


# ---- acceptance --------------------------------------------------------------------------

def test_acceptance_segregation_of_duties(users, session):
    mgr = users["isms_manager"]
    r = _risk(session, mgr, owner_id=mgr.id)
    with pytest.raises(ValueError, match="Segregation of duties"):
        risk.accept_risk(session, mgr, r.id, "Business decision")
    with pytest.raises(PermissionDenied):
        risk.accept_risk(session, users["risk_owner"], r.id, "x")
    acc = risk.accept_risk(session, users["admin"], r.id, "Compensating controls in place")
    assert r.status == "accepted" and acc.level_at_acceptance == "Critical"
    assert risk.active_acceptance(r) is acc


def test_above_appetite_acceptance_time_limited(users, session):
    r = _risk(session, users["risk_owner"])
    with pytest.raises(ValueError, match="at most 365"):
        risk.accept_risk(session, users["admin"], r.id, "x", expires_on=date.today() + timedelta(days=400))
    with pytest.raises(ValueError, match="future"):
        risk.accept_risk(session, users["admin"], r.id, "x", expires_on=date.today())


def test_expired_acceptance_flagged_and_reaccept_revokes_previous(users, session):
    r = _risk(session, users["risk_owner"])
    first = risk.accept_risk(session, users["admin"], r.id, "Q1", expires_on=date.today() + timedelta(days=10))
    assert risk.needs_attention([r], on=date.today() + timedelta(days=11))["acceptance_expired"] == [r]
    second = risk.accept_risk(session, users["admin"], r.id, "Q2")
    assert first.revoked_at is not None and risk.active_acceptance(r) is second
    risk.revoke_acceptance(session, users["admin"], second.id)
    assert r.status == "assessed" and risk.active_acceptance(r) is None


def test_needs_attention(users, session):
    r = _risk(session, users["risk_owner"], review_date=date.today() - timedelta(days=1))
    att = risk.needs_attention([r])
    assert r in att["review_overdue"] and r in att["above_appetite_untreated"]
    risk.mark_reviewed(session, users["risk_owner"], r.id)
    assert r not in risk.needs_attention([r])["review_overdue"]


def test_heat_map():
    rs = [Risk(title="a", inherent_likelihood=4, inherent_impact=5, residual_likelihood=2, residual_impact=3), Risk(title="b", inherent_likelihood=4, inherent_impact=5)]
    grid = risk.heat_map(rs)
    assert grid[4][3] == 2 and sum(map(sum, grid)) == 2
    assert risk.heat_map(rs, "residual")[2][1] == 1


def test_risk_changes_audited(users, db):
    with db.session_scope() as s:
        r = _risk(s, users["risk_owner"])
        rid = r.id
    with db.session_scope() as s:
        risk.save_risk(s, users["risk_owner"], rid, inherent_impact=3)
    with db.session_scope() as s:
        rows = s.scalars(select(AuditLog).where(AuditLog.entity_type == "Risk")).all()
        assert [x.action for x in rows] == ["create", "update"]
        assert rows[1].changes["inherent_impact"] == [5, 3] and rows[1].actor_name == "riskowner"


# ---- FAIR ----------------------------------------------------------------------------------

BASE = {"tef": [0.5, 2, 6], "tcap": [0.4, 0.6, 0.9], "cs": [0.5, 0.7, 0.9], "plm": [20_000, 80_000, 400_000]}


def test_pert_bounds_and_mode():
    rng = np.random.default_rng(1)
    s = fair.pert(rng, fair.Range(10, 20, 60), 50_000)
    assert s.min() >= 10 and s.max() <= 60
    assert abs(float(np.mean(s)) - (10 + 4 * 20 + 60) / 6) < 0.5  # PERT mean
    assert (fair.pert(rng, fair.Range(5, 5, 5), 10) == 5).all()


def test_simulation_is_seeded_and_ordered():
    inp = fair.FairInputs.from_dict(BASE)
    a, b = fair.simulate(inp, 20_000, seed=42), fair.simulate(inp, 20_000, seed=42)
    assert a == b
    assert a.ale_p10 <= a.ale_p50 <= a.ale_p90 <= a.ale_p95
    assert 0 < a.vulnerability < 1 and a.ale_mean > 0
    probs = [p for _, p in a.exceedance]
    assert probs == sorted(probs, reverse=True)


def test_stronger_controls_reduce_loss():
    weak = fair.simulate(fair.FairInputs.from_dict({**BASE, "cs": [0.1, 0.2, 0.3]}), 20_000, seed=7)
    strong = fair.simulate(fair.FairInputs.from_dict({**BASE, "cs": [0.8, 0.9, 0.95]}), 20_000, seed=7)
    assert strong.vulnerability < weak.vulnerability and strong.ale_mean < weak.ale_mean


def test_direct_vulnerability_and_secondary_loss():
    base = {"tef": [1, 1, 1], "vuln": [1, 1, 1], "plm": [100, 100, 100]}
    r = fair.simulate(fair.FairInputs.from_dict(base), 50_000, seed=3)
    assert abs(r.ale_mean - 100) < 3  # Poisson(1) * 100
    r2 = fair.simulate(fair.FairInputs.from_dict({**base, "slef": [1, 1, 1], "slm": [50, 50, 50]}), 50_000, seed=3)
    assert abs(r2.ale_mean - 150) < 4


@pytest.mark.parametrize(
    "bad,msg",
    [
        ({"tef": [3, 2, 1]}, "min <= most likely"),
        ({"cs": [0.5, 0.7, 1.5]}, "probability"),
        ({"tcap": None, "cs": None}, "either a vulnerability"),
        ({"slef": [0.1, 0.2, 0.3]}, "both SLEF and SLM"),
    ],
)
def test_fair_validation(bad, msg):
    with pytest.raises(ValueError, match=msg):
        fair.FairInputs.from_dict({**BASE, **bad})


def test_run_fair_stores_result(users, session):
    r = _risk(session, users["risk_owner"])
    res = risk.run_fair(session, users["risk_owner"], r.id, BASE, iterations=5000, seed=1)
    assert r.fair_result["ale_mean"] == res.ale_mean and r.fair_inputs["tef"] == {"min": 0.5, "ml": 2.0, "max": 6.0}


def test_acceptances_collection_has_no_duplicates(users, session):
    r = _risk(session, users["risk_owner"])
    risk.accept_risk(session, users["admin"], r.id, "a")
    risk.accept_risk(session, users["admin"], r.id, "b")
    assert len(r.acceptances) == 2 and len({a.id for a in r.acceptances}) == 2
