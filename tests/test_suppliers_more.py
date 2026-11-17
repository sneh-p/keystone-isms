"""Supplier depth (A.5.19-5.22): questionnaire template editing and versioning, and vendor offboarding."""

import pytest

from keystone.reporting.routing import routed_items
from keystone.tprm import service as tprm

Q = [{"id": "q1", "section": "Access", "text": "Is MFA enforced?", "type": "ynp", "weight": 3, "control": "KC-TEC-05", "required": True}]


def test_template_editing_and_versions(session, users):
    vw = users["isms_manager"]
    t = tprm.save_template(session, vw, name="Cloud suppliers", version="1.0", questions=tprm.clean_questions(Q))
    tprm.update_template(session, vw, t.id, questions=Q + [{"id": "q2", "text": "Pen test yearly?", "type": "yn", "weight": 1}])
    assert [q["id"] for q in t.questions] == ["q1", "q2"] and t.questions[1]["section"] == "General"
    for bad, msg in (([{"id": "x y", "text": "a", "type": "yn"}], "letters, digits"), ([{"id": "a", "text": "a", "type": "yn", "weight": 50}], "between 0 and 10"),
                     ([{"id": "a", "text": "a", "type": "yn", "control": "DROP TABLE"}], "control code"), ([{"id": "a", "text": "a", "type": "yn", "evil": 1}], "only")):
        with pytest.raises(ValueError, match=msg):
            tprm.clean_questions(bad)
    v = tprm.save_vendor(session, vw, name="Acme Hosting", status="active")
    tprm.send_questionnaire(session, vw, v.id, t.id)
    with pytest.raises(ValueError, match="new version"):
        tprm.update_template(session, vw, t.id, questions=Q)
    t2 = tprm.new_template_version(session, vw, t.id, "1.1")
    assert t2.version == "1.1" and not t.active and t2.active and [x.id for x in tprm.templates(session)] == [t2.id]
    with pytest.raises(ValueError, match="already exists"):
        tprm.new_template_version(session, vw, t2.id, "1.1")


def test_vendor_offboarding(session, users):
    vw = users["isms_manager"]
    v = tprm.save_vendor(session, vw, name="Old CRM", status="active", owner_id=vw.id)
    with pytest.raises(ValueError, match="offboarding checklist"):
        tprm.save_vendor(session, vw, v.id, status="terminated")
    with pytest.raises(ValueError, match="offboarding first"):
        tprm.tick_vendor_offboarding(session, vw, v.id, "access_removed", True)
    tprm.save_vendor(session, vw, v.id, status="offboarding")
    assert any("Finish offboarding Old CRM" in i["what"] for i in routed_items(session)[vw.id])
    for item in tprm.OFFBOARDING_ITEMS:
        tprm.tick_vendor_offboarding(session, vw, v.id, item, True)
    tprm.save_vendor(session, vw, v.id, status="terminated")
    assert v.status == "terminated" and v.offboarding["data_returned_or_deleted"]["by"]
