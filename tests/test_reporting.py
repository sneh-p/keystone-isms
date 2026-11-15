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
