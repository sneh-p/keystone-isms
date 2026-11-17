"""Objective measurements (6.2, 9.1), recurring access reviews (A.5.18) and the configuration tile."""

from datetime import timedelta

import pytest

from keystone.access_reviews import service as ar
from keystone.core.db import utcnow
from keystone.core.services import add_months, today
from keystone.org import service as org
from keystone.reporting import dashboard


def test_objective_measurements_and_metric_link(content, session, users):
    o = org.save_objective(session, users["admin"], title="Fewer overdue tasks", target="0", metric_key="tasks_overdue")
    with pytest.raises(ValueError, match="metric from the list"):
        org.save_objective(session, users["admin"], o.id, metric_key="made_up")
    org.record_measurement(session, users["admin"], o.id, value=7, measured_on=today() - timedelta(days=30), note="Baseline")
    dashboard.take_snapshot(session)
    dashboard.take_snapshot(session)  # idempotent per day
    ms = org.measurements(session, o.id)
    assert [m.source for m in ms] == ["manual", "metric"] and o.current_value == f"{ms[-1].value:g}"
    with pytest.raises(ValueError, match="future"):
        org.record_measurement(session, users["admin"], o.id, value=1, measured_on=today() + timedelta(days=1))


def test_recurring_access_reviews_and_export(session, users):
    mgr = users["isms_manager"]
    r = ar.start(session, mgr, "Quarterly review", ["keystone"], today() + timedelta(days=20), repeat_months=3)
    assert r.next_start_on == add_months(today(), 3)
    with pytest.raises(ValueError, match="3, 6 or 12"):
        ar.start(session, mgr, "x", ["keystone"], today() + timedelta(days=20), repeat_months=5)
    assert ar.start_due_campaigns(session, today()) == []
    started = ar.start_due_campaigns(session, r.next_start_on or today())
    assert len(started) == 1 and started[0].title.startswith("Quarterly review (") and started[0].repeat_months == 3 and r.next_start_on is None
    headers, rows = ar.export_rows(session, users["viewer"], r.id)
    assert headers[0] == "Account" and rows and rows[0][4] == "pending"


def test_dashboard_configuration_tile(session, users):
    from keystone.configcheck import service as cfg
    from keystone.configcheck.models import ConfigTarget

    cfg.create_baseline(session, users["admin"], name="Linux", platform="linux", recommended=False)
    b = cfg.baselines(session)[0]
    cfg.save_rule(session, users["admin"], baseline_id=b.id, key="firewall_active")
    t = ConfigTarget(kind="agent", platform="linux", name="h1", facts={"firewall_active": False}, facts_at=utcnow(), created_at=utcnow())
    session.add(t)
    session.flush()
    cfg.evaluate_target(session, t)
    ov = dashboard.overview(session)
    assert ov["configuration"]["failing"] == 1 and any("configuration baseline" in a["text"] for a in ov["attention"])
