"""Calendar sources added in round 4: privacy, improvement, objectives and configuration dates."""

from datetime import date, timedelta

from keystone.core.db import utcnow
from keystone.core.services import today
from keystone.improvement import service as improvement
from keystone.privacy import service as privacy
from keystone.reporting.calendar import events


def test_new_event_kinds(session, users):
    from keystone.configcheck.models import ConfigTarget

    admin = users["admin"]
    privacy.save_request(session, admin, request_type="access", received_on=today(), requester_name="Fictional Person")
    nc = improvement.raise_nc(session, admin, title="Missed review", source="internal_audit", description="x", due_date=today() + timedelta(days=5))
    improvement.add_action(session, admin, nc.id, "Run the review", owner_id=admin.id, due_date=today() + timedelta(days=3))
    fw = ConfigTarget(kind="firewall", platform="fortigate", name="FGT-1", facts={}, created_at=utcnow(), facts_at=utcnow() - timedelta(days=80))
    session.add(fw)
    session.flush()
    got = events(session, admin, today(), today() + timedelta(days=40))
    kinds = {e["kind"] for e in got}
    assert {"dsr_due", "nc_due", "corrective_action", "firewall_upload"} <= kinds, kinds
    fw_event = next(e for e in got if e["kind"] == "firewall_upload")
    assert fw_event["date"] == (date.today() + timedelta(days=10)).isoformat() and fw_event["page"] == f"/configuration?target={fw.id}"
