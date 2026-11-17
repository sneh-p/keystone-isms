"""Per-record history: anyone who can read a record sees its changes; employees can't; unknown kinds are refused."""

from __future__ import annotations

from keystone.policies import service as pol
from keystone.risk import service as risk

from .conftest import api_login


def test_record_history(api, ready_users, db):
    mgr = ready_users["isms_manager"]
    with db.session_scope(mgr) as s:
        r = risk.save_risk(s, mgr, title="Laptop theft", category="people", owner_id=mgr.id)
        risk.save_risk(s, mgr, r.id, title="Laptop theft while travelling", inherent_likelihood=3, inherent_impact=4)
        d = pol.save_document(s, mgr, code="POL-H", title="History policy")
        pol.start_version(s, mgr, d.id, body="Text")
        rid, did = r.id, d.id
    api_login(api, ready_users["viewer"].username)
    h = api.get(f"/api/history/risk/{rid}").json()
    assert [x["action"] for x in h][-1] == "create" and h[0]["action"] == "update"
    assert h[0]["changes"]["title"] == ["Laptop theft", "Laptop theft while travelling"] and h[0]["actor"] == mgr.username
    assert {x["entity_type"] for x in api.get(f"/api/history/policy/{did}").json()} == {"PolicyDocument", "PolicyVersion"}
    assert api.get("/api/history/user/1").status_code == 404  # need-to-know records aren't history targets
    assert api.get("/api/history/risk/99999").status_code == 404
    api.post("/api/auth/logout")
    api_login(api, ready_users["employee"].username)
    assert api.get(f"/api/history/risk/{rid}").status_code == 403
