"""Controls and evidence depth: evidence for several controls, accept/reject with segregation of duties, control tests
with tester independence, custom mappings and custom controls."""

from datetime import timedelta

import pytest

from keystone.controls import service as ctl
from keystone.core.rbac import PermissionDenied
from keystone.core.services import today
from keystone.frameworks.models import Requirement
from keystone.frameworks.service import control_by_code

from .conftest import api_login


def test_shared_evidence_and_decisions(content, session, users):
    co = users["control_owner"]
    a, b = control_by_code(session, "KC-TEC-05"), control_by_code(session, "KC-TEC-02")
    for c in (a, b):
        c.status = "implemented"
    session.flush()
    assert b.id in {c.id for c in ctl.control_attention(session)["implemented_without_evidence"]}
    ev = ctl.add_evidence(session, co, a.id, title="MFA policy export", kind="note", description="Conditional access export", also_control_ids=[b.id])
    assert ev.control_ids == [a.id, b.id]
    assert ev.id in [e.id for e in ctl.evidence_for(session, b.id)]
    assert b.id not in {c.id for c in ctl.control_attention(session)["implemented_without_evidence"]}  # shared evidence counts
    with pytest.raises(ValueError, match="Segregation of duties"):
        ctl.decide_evidence(session, co, ev.id, "accepted")
    with pytest.raises(ValueError, match="Say why"):
        ctl.decide_evidence(session, users["risk_owner"], ev.id, "rejected")
    ctl.decide_evidence(session, users["risk_owner"], ev.id, "rejected", "Export is from the test tenant")
    assert ctl.evidence_state(ev) == "rejected"
    assert b.id in {c.id for c in ctl.control_attention(session)["implemented_without_evidence"]}  # rejected doesn't count


def test_control_tests(content, session, users):
    c = control_by_code(session, "KC-ORG-18")
    c.owner_id = users["isms_manager"].id
    session.flush()
    with pytest.raises(PermissionDenied):
        ctl.record_test(session, users["control_owner"], c.id, test_type="operating", method="inspection", tested_on=today(), result="effective")
    with pytest.raises(ValueError, match="Independence"):
        ctl.record_test(session, users["isms_manager"], c.id, test_type="operating", method="inspection", tested_on=today(), result="effective")
    with pytest.raises(ValueError, match="Describe what didn't work"):
        ctl.record_test(session, users["auditor"], c.id, test_type="operating", method="inspection", tested_on=today(), result="ineffective")
    with pytest.raises(ValueError, match="future"):
        ctl.record_test(session, users["auditor"], c.id, test_type="design", method="inquiry", tested_on=today() + timedelta(days=1), result="effective")
    t = ctl.record_test(session, users["auditor"], c.id, test_type="operating", method="reperformance", tested_on=today(), result="ineffective",
                        sample="10 of 40 leavers", findings="3 accounts still active after 5 days", raise_nc=True)
    assert t.nonconformity_id and ctl.last_tests(session)[c.id].id == t.id


def test_mappings_and_custom_controls(api, ready_users, db, content):
    api_login(api, "admin")
    c = api.post("/api/controls", json={"title": "Customer data export approval", "domain": "Data"}).json()
    assert c["code"] == "KC-CUS-01"
    assert api.post("/api/controls", json={"title": "Second"}).json()["code"] == "KC-CUS-02"
    with db.session_scope() as s:
        req = s.query(Requirement).filter(Requirement.ref == "A.5.12").first()
        rid = req.id
    m = api.post(f"/api/controls/{c['id']}/mappings", json={"requirement_id": rid}).json()
    detail = api.get(f"/api/controls/{c['id']}").json()
    assert [x["ref"] for x in detail["mappings"]] == ["A.5.12"] and detail["mappings"][0]["source"] == "user"
    builtin = api.get(f"/api/controls/{api.get('/api/controls').json()[0]['id']}").json()["mappings"][0]
    assert api.delete(f"/api/control-mappings/{builtin['id']}").status_code == 400  # Keystone's own mappings stay
    assert api.delete(f"/api/control-mappings/{m['id']}").status_code == 200
    api.post("/api/auth/logout")
    api.cookies.clear()
    api_login(api, ready_users["control_owner"].username)
    assert api.post("/api/controls", json={"title": "x"}).status_code == 403
