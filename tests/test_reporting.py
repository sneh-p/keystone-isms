"""Phase 10: dashboard, personal tasks and register exports (on the demo organisation)."""

import io

import pytest
from openpyxl import load_workbook
from sqlalchemy import select

from keystone import demo
from keystone.core import auth
from keystone.core.audit import AuditLog, verify_chain
from keystone.core.rbac import PermissionDenied
from keystone.reporting import dashboard, registers


@pytest.fixture
def demo_session(db):
    with db.session_scope() as s:
        admin = auth.create_user(s, None, username="admin", display_name="Admin", password=demo.DEMO_PASSWORD)
    with db.session_scope(admin) as s:
        demo.seed(s, s.get(auth.User, admin.id))
    with db.session_scope() as s:
        yield s


def _user(s, name):
    return s.scalar(select(auth.User).where(auth.User.username == name))


def test_overview(demo_session):
    o = dashboard.overview(demo_session)
    assert o["open_risks"] == 4 and sum(o["risk_levels"].values()) == 4
    assert o["open_incidents"] == 1 and o["open_ncs"] >= 2 and o["vendors"] == 3
    texts = " ".join(a["text"] for a in o["attention"])
    assert "regulator notification" in texts and "above appetite" in texts and "without current evidence" in texts
    assert all(a["count"] > 0 for a in o["attention"])
    assert {name.split(" ")[0] for name, _ in o["coverage"]} >= {"ISO/IEC", "NIST", "SOC", "CIS"}


def test_my_tasks(demo_session):
    lena = _user(demo_session, "lena.ctl")
    tasks = [t["what"] for t in dashboard.my_tasks(demo_session, lena)]
    assert any(t.startswith("Acknowledge POL-001") for t in tasks)
    assert any("Quarterly restore test" in t for t in tasks)
    assert any(t.startswith("Corrective action: Enforce FIDO2") for t in tasks)
    admin = _user(demo_session, "admin")
    assert any(t.startswith("Approve POL-002") for t in (x["what"] for x in dashboard.my_tasks(demo_session, admin)))
    raj = _user(demo_session, "raj.risk")
    assert not any(t["what"].startswith("Acknowledge POL-001") for t in dashboard.my_tasks(demo_session, raj))  # already acknowledged


@pytest.mark.parametrize("name", list(registers.REGISTERS))
def test_register_exports(demo_session, name):
    viewer = _user(demo_session, "sam.view")
    data = registers.export(demo_session, viewer, name, "Alpine Ski House")
    ws = load_workbook(io.BytesIO(data)).active
    assert ws["A1"].value == f"Alpine Ski House: {name}" and ws.max_row > 3
    assert demo_session.scalar(select(AuditLog).where(AuditLog.action == "export").order_by(AuditLog.id.desc())).actor_name == "sam.view"


def test_audit_log_export_needs_permission(demo_session):
    with pytest.raises(PermissionDenied):
        registers.export(demo_session, _user(demo_session, "sam.view"), "Audit log")
    data = registers.export(demo_session, _user(demo_session, "omar.audit"), "Audit log")
    assert load_workbook(io.BytesIO(data)).active.max_row > 100


def test_demo_audit_chain_intact(demo_session):
    assert verify_chain(demo_session) == (True, None)


def test_next_steps_come_from_real_gaps(demo_session):
    steps = dashboard.next_steps(demo_session, limit=20)
    keys = [s["key"] for s in steps]
    assert keys and all(s["count"] > 0 and s["page"].startswith("/") for s in steps)
    assert "owners" in keys  # the demo has controls without an owner
    from keystone.frameworks.models import CommonControl
    from sqlalchemy import func

    unowned = demo_session.scalar(select(func.count()).select_from(CommonControl).where(CommonControl.owner_id.is_(None), CommonControl.status != "not_applicable"))
    assert next(s for s in steps if s["key"] == "owners")["count"] == unowned
    assert len(dashboard.next_steps(demo_session)) <= 4
    # Closing a gap removes its step.
    admin = _user(demo_session, "admin")
    for c in demo_session.scalars(select(CommonControl).where(CommonControl.owner_id.is_(None))):
        c.owner_id = admin.id
    demo_session.flush()
    assert "owners" not in [s["key"] for s in dashboard.next_steps(demo_session, limit=20)]


def test_demo_has_trend_history(demo_session):
    from keystone.reporting.models import MetricSnapshot

    days = [s.day for s in demo_session.scalars(select(MetricSnapshot).order_by(MetricSnapshot.day))]
    assert len(days) == 11 and all(d.weekday() == 6 for d in days)
    t = dashboard.trend(demo_session, dashboard.metrics(demo_session))
    assert len(t["days"]) == dashboard.TREND_POINTS


def test_audit_coverage_counts(demo_session):
    o = dashboard.overview(demo_session)
    cov = o["audit_coverage"]
    assert 0 < cov["audited"] <= cov["applicable"]
    assert o["audit_coverage_pct"] == round(100 * cov["audited"] / cov["applicable"], 1)


def test_snapshots_are_daily_and_trend_is_weekly(demo_session):
    from datetime import date, timedelta

    from keystone.reporting.models import MetricSnapshot

    today = date(2026, 11, 16)  # a Monday
    demo_session.query(MetricSnapshot).delete()  # start without the demo's fictional history
    assert demo_session.query(MetricSnapshot).count() == 0
    for d in range(0, 40):
        dashboard.take_snapshot(demo_session, today - timedelta(days=d + 1))
    dashboard.take_snapshot(demo_session, today - timedelta(days=1))  # same day again: replaced, not duplicated
    assert demo_session.scalar(select(func_count(MetricSnapshot))) == 40
    snap = demo_session.scalar(select(MetricSnapshot).where(MetricSnapshot.day == today - timedelta(days=3)))
    snap.values = {**snap.values, "open_risks": 99}
    demo_session.flush()
    current = dashboard.metrics(demo_session, today)
    t = dashboard.trend(demo_session, current, today)
    assert t["days"][-1] == today.isoformat() and t["series"]["open_risks"][-1] == current["open_risks"]
    assert len(t["days"]) == 7  # six earlier weeks with data plus today
    days = [date.fromisoformat(x) for x in t["days"][:-1]]
    assert all(d.weekday() == 6 for d in days)  # the last snapshot of each week (Sunday)
    assert 99 not in t["series"]["open_risks"]  # mid-week values are not shown
    assert set(t["series"]) == set(current) and all(len(v) == len(t["days"]) for v in t["series"].values())


def func_count(model):
    from sqlalchemy import func

    return func.count(model.id)
