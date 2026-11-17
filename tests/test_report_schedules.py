"""Board summary PDF and scheduled report emails (recipients are Keystone users only)."""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from keystone.core.auth import User
from keystone.notifications import mailer
from keystone.notifications import service as ntf
from keystone.reporting import schedules as sch

from .conftest import api_login


@pytest.fixture
def outbox(monkeypatch, db, users):
    sent = []
    monkeypatch.setattr(mailer, "resolve", lambda host: "203.0.113.10")
    monkeypatch.setattr(mailer, "send", lambda cfg, msgs: sent.extend(msgs))
    with db.session_scope(users["admin"]) as s:
        ntf.update_smtp(s, users["admin"], host="smtp.example.com", from_address="isms@example.com", enabled=True, digest_hour_utc=7)
        for role in ("isms_manager", "viewer", "employee"):
            s.get(User, users[role].id).email = f"{role}@alpine.example"
    return sent


def test_board_pdf(api, ready_users, content):
    api_login(api, ready_users["viewer"].username)
    r = api.get("/api/reports/board.pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF") and r.headers["content-type"] == "application/pdf"


def test_schedule_sends_to_eligible_users_only(db, users, outbox, content):
    mgr = users["isms_manager"]
    with db.session_scope(mgr) as s:
        with pytest.raises(ValueError, match="Recipients must be"):
            sch.save(s, mgr, name="x", report="board_pdf", frequency="monthly", recipient_ids=[users["employee"].id], next_run_on=date.today())
    with db.session_scope(mgr) as s:
        with pytest.raises(ValueError, match="Choose a report"):
            sch.save(s, mgr, name="x", report="Audit log", frequency="monthly", recipient_ids=[mgr.id], next_run_on=date.today())
    with db.session_scope(mgr) as s:
        sc = sch.save(s, mgr, name="Monthly board pack", report="board_pdf", frequency="monthly", recipient_ids=[mgr.id, users["viewer"].id], next_run_on=date.today())
        sid = sc.id
    with db.session_scope() as s:
        s.get(User, users["viewer"].id).active = False  # left since the schedule was set up
    with db.session_scope() as s:
        assert sch.run_due(s) == 1
        sc = s.get(type(sc), sid)
        assert sc.next_run_on == sch.advance(date.today(), "monthly") and sc.last_error is None
    assert [m["To"] for m in outbox] == ["isms_manager@alpine.example"]
    att = [p for p in outbox[0].iter_attachments()]
    assert att[0].get_filename().startswith("Board_summary_") and att[0].get_content().startswith(b"%PDF")
    with db.session_scope() as s:
        assert sch.run_due(s) == 0  # not due again until next month


def test_schedule_stops_when_its_owner_cant_read(db, users, outbox, content):
    mgr = users["isms_manager"]
    with db.session_scope(mgr) as s:
        sid = sch.save(s, mgr, name="Risks", report="Risk register", frequency="weekly", recipient_ids=[mgr.id], next_run_on=date.today()).id
    with db.session_scope() as s:
        s.get(User, mgr.id).active = False
    with db.session_scope() as s:
        assert sch.run_due(s) == 0
        from keystone.reporting.models import ReportSchedule

        sc = s.get(ReportSchedule, sid)
        assert "can no longer read" in sc.last_error and sc.next_run_on == date.today() + timedelta(days=7)
    assert outbox == []


def test_schedule_api_permissions(api, ready_users):
    api_login(api, ready_users["viewer"].username)
    assert api.get("/api/report-schedules").status_code == 403
    api.post("/api/auth/logout")
    api_login(api, ready_users["isms_manager"].username)
    body = api.get("/api/report-schedules").json()
    assert "board_pdf" in body["reports"] and "Audit log" not in body["reports"]
