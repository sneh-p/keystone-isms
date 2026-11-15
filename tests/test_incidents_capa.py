"""Phase 8: incidents, nonconformities, corrective actions."""

from datetime import timedelta

import pytest

from keystone.core.db import utcnow
from keystone.core.rbac import PermissionDenied
from keystone.improvement import service as imp
from keystone.incidents import service as inc


def _inc(session, actor, **kw):
    return inc.report_incident(session, actor, **{"title": "Phishing led to mailbox compromise", "category": "account_compromise", "severity": "high", **kw})


def test_report_and_timeline(users, session):
    i = _inc(session, users["control_owner"], detected_at=utcnow() - timedelta(hours=2))
    assert i.status == "new" and i.ref == "INC-0001"
    assert [e.kind for e in i.events] == ["system"]
    inc.add_note(session, users["control_owner"], i.id, "Reset password, revoked sessions")
    inc.update_incident(session, users["control_owner"], i.id, severity="critical")
    assert [e.kind for e in i.events] == ["system", "note", "system"] and "high → critical" in i.events[-1].entry
    assert len({e.id for e in i.events}) == len(i.events)  # no duplicates in the loaded collection
    with pytest.raises(PermissionDenied):
        _inc(session, users["viewer"])
    with pytest.raises(ValueError, match="future"):
        _inc(session, users["admin"], detected_at=utcnow() + timedelta(days=1))


def test_lifecycle_requires_lessons(users, session):
    u = users["control_owner"]
    i = _inc(session, u)
    with pytest.raises(ValueError, match="Cannot move"):
        inc.move(session, u, i.id, "recovered")
    for st in ("triage", "contained", "eradicated", "recovered"):
        inc.move(session, u, i.id, st)
    assert i.contained_at is not None
    with pytest.raises(ValueError, match="root cause and lessons"):
        inc.move(session, u, i.id, "closed")
    inc.update_incident(session, u, i.id, root_cause="No phishing-resistant MFA", lessons_learned="Roll out FIDO2 for staff")
    inc.move(session, u, i.id, "closed")
    assert i.resolution == "resolved" and i.closed_at
    inc.move(session, u, i.id, "triage")  # reopen
    assert i.closed_at is None and i.resolution is None


def test_false_positive_close(users, session):
    u = users["control_owner"]
    i = _inc(session, u)
    inc.move(session, u, i.id, "triage")
    with pytest.raises(ValueError, match="resolution"):
        inc.move(session, u, i.id, "closed")
    with pytest.raises(ValueError, match="must be contained"):
        inc.move(session, u, i.id, "closed", "resolved")
    inc.move(session, u, i.id, "closed", "false_positive")
    assert i.status == "closed"


def test_personal_data_notification(users, session):
    u = users["control_owner"]
    i = _inc(session, u, personal_data_involved=True, notification_required=True, detected_at=utcnow() - timedelta(hours=80), category="data_breach")
    assert inc.notification_deadline(i) == i.detected_at + timedelta(hours=72)
    att = inc.incident_attention(session)
    assert i in att["notification_due"] and i in att["notification_overdue"] and i in att["containment_overdue"]
    for st in ("triage", "contained", "eradicated", "recovered"):
        inc.move(session, u, i.id, st)
    inc.update_incident(session, u, i.id, root_cause="x", lessons_learned="y")
    with pytest.raises(ValueError, match="notification"):
        inc.move(session, u, i.id, "closed")
    inc.record_notification(session, u, i.id, note="Reported via the regulator portal")
    inc.move(session, u, i.id, "closed")
    assert inc.incident_attention(session)["notification_due"] == []


def test_no_deadline_without_personal_data(users, session):
    i = _inc(session, users["admin"], personal_data_involved=False)
    assert inc.notification_deadline(i) is None
    j = _inc(session, users["admin"], personal_data_involved=True, notification_required=False)
    assert inc.notification_deadline(j) is None


# ---- nonconformities --------------------------------------------------------------------

def test_nc_full_cycle_with_effectiveness_check(users, session):
    owner, verifier = users["control_owner"], users["isms_manager"]
    nc = imp.raise_nc(session, owner, title="Leaver accounts not disabled within 24h", source="internal_audit", severity="minor")
    with pytest.raises(ValueError, match="root cause"):
        imp.plan(session, owner, nc.id)
    imp.update_nc(session, owner, nc.id, root_cause="HR does not notify IT")
    with pytest.raises(ValueError, match="corrective action"):
        imp.plan(session, owner, nc.id)
    a1 = imp.add_action(session, owner, nc.id, "Automate leaver feed from HR", owner_id=owner.id)
    imp.plan(session, owner, nc.id)
    with pytest.raises(ValueError, match="verification"):
        imp.close(session, verifier, nc.id)
    imp.complete_action(session, owner, a1.id, "Feed live since 1 Nov")
    assert nc.status == "verification"
    with pytest.raises(PermissionDenied):
        imp.verify_action(session, owner, a1.id, True, "ok")
    imp.verify_action(session, verifier, a1.id, False, "Two leavers last week still enabled")
    assert nc.status == "open" and a1.status == "ineffective"
    a2 = imp.add_action(session, owner, nc.id, "Daily reconciliation report", owner_id=owner.id)
    imp.plan(session, owner, nc.id)
    imp.complete_action(session, owner, a2.id, "Report running")
    imp.verify_action(session, verifier, a2.id, True, "No exceptions in 4 weeks")
    imp.close(session, verifier, nc.id)
    assert nc.status == "closed" and nc.closed_by_id == verifier.id
    with pytest.raises(ValueError, match="(?i)closed"):
        imp.update_nc(session, owner, nc.id, title="x")


def test_owner_cannot_verify_own_action(users, session):
    mgr = users["isms_manager"]
    nc = imp.raise_nc(session, mgr, title="x", root_cause="y")
    a = imp.add_action(session, mgr, nc.id, "do it", owner_id=mgr.id)
    imp.plan(session, mgr, nc.id)
    imp.complete_action(session, mgr, a.id, "done")
    with pytest.raises(ValueError, match="Segregation"):
        imp.verify_action(session, mgr, a.id, True, "fine")


def test_auditor_can_raise_but_not_edit(users, session):
    nc = imp.raise_nc(session, users["auditor"], title="Finding", source="internal_audit")
    assert nc.created_by_id == users["auditor"].id
    with pytest.raises(PermissionDenied):
        imp.update_nc(session, users["auditor"], nc.id, title="y")
    with pytest.raises(PermissionDenied):
        imp.raise_nc(session, users["viewer"], title="x")


def test_nc_attention(users, session):
    from datetime import date
    mgr = users["isms_manager"]
    nc = imp.raise_nc(session, mgr, title="x", due_date=date.today() - timedelta(days=1))
    a = imp.add_action(session, mgr, nc.id, "a", due_date=date.today() - timedelta(days=2))
    att = imp.nc_attention(session)
    assert nc in att["overdue"] and a in att["actions_overdue"]
