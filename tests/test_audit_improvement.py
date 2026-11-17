"""Audits and improvement depth: the audit programme, editable findings, root-cause method and recurrence."""

from datetime import timedelta

import pytest

from keystone.audits import service as aud
from keystone.core.services import today
from keystone.frameworks.service import control_by_code
from keystone.improvement import service as imp


def test_programme_and_findings(content, session, users):
    lead = users["auditor"]
    a, b = control_by_code(session, "KC-TEC-05"), control_by_code(session, "KC-TEC-02")
    done = aud.save_audit(session, users["isms_manager"], title="2026 internal audit", lead_auditor_id=lead.id, planned_start=today() - timedelta(days=30), control_ids=[a.id])
    aud.save_audit(session, users["isms_manager"], title="2027 internal audit", lead_auditor_id=lead.id, planned_start=today() + timedelta(days=200), control_ids=[b.id])
    aud.advance(session, users["isms_manager"], done.id)  # planned -> in progress
    p = aud.programme(session)
    rows = {r["code"]: r for r in p["controls"]}
    assert rows["KC-TEC-05"]["last_audit"]["title"] == "2026 internal audit" and not rows["KC-TEC-05"]["gap"]
    assert rows["KC-TEC-02"]["next_audit"]["title"] == "2027 internal audit" and rows["KC-TEC-02"]["last_audited"] is None
    assert p["gaps"] == len(rows) - 2 and p["covered"] == 1
    f = aud.add_finding(session, lead, done.id, finding_type="observation", title="Typo in tittle")
    aud.update_finding(session, lead, f.id, title="MFA exceptions not reviewed")
    assert f.title == "MFA exceptions not reviewed"
    with pytest.raises(ValueError, match="Only the title"):
        aud.update_finding(session, lead, f.id, finding_type="major_nc")


def test_recurrence_and_root_cause_method(content, session, users):
    c = control_by_code(session, "KC-ORG-18")
    first = imp.raise_nc(session, users["isms_manager"], title="Leaver accounts not disabled on time", description="x", source="internal_audit", common_control_id=c.id)
    unrelated = imp.raise_nc(session, users["isms_manager"], title="Fire drill missed", description="x", source="self_identified")
    again = imp.raise_nc(session, users["isms_manager"], title="Accounts of leavers still active", description="y", source="monitoring", common_control_id=c.id,
                         root_cause_method="five_whys")
    assert [n.id for n in imp.similar(session, again)] == [first.id]
    assert unrelated.id not in [n.id for n in imp.similar(session, again)]
    with pytest.raises(ValueError, match="root_cause_method"):
        imp.update_nc(session, users["isms_manager"], again.id, root_cause_method="guess")
