"""Slack, Teams and webhook notifications: URL rules, payloads, signatures, retries and secrecy of URLs."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select

from keystone.core.audit import AuditLog
from keystone.core.db import utcnow
from keystone.integrations import http
from keystone.outbound import service as ob
from keystone.outbound.models import Delivery

from .conftest import api_login

SLACK = "https://hooks.slack.com/services/T000/B000/SECRETTOKENxyz"
TEAMS = "https://prod-12.westeurope.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?api-version=2016-06-01&sig=TEAMSSECRET"
HOOK = "https://hooks.alpine.example/keystone"


@pytest.fixture
def sink(monkeypatch):
    state = {"calls": [], "status": 200}

    def handler(req: httpx.Request) -> httpx.Response:
        state["calls"].append(req)
        return httpx.Response(state["status"], text="ok")

    monkeypatch.setattr(http, "TEST_TRANSPORT", httpx.MockTransport(handler))
    return state


def test_destination_urls_are_checked_and_kept_secret(users, db):
    admin = users["admin"]
    with db.session_scope(admin) as s:
        for kind, url in (("slack", "https://evil.example/services/x"), ("slack", "http://hooks.slack.com/x"), ("teams", "https://teams.evil.example/x"),
                          ("webhook", "https://user:pw@hooks.alpine.example/x"), ("webhook", "https://hooks.alpine.example:8443/x")):
            with pytest.raises(ValueError):
                ob.save_destination(s, admin, kind=kind, name="x", url=url, events=["incident.created"])
        d, secret = ob.save_destination(s, admin, kind="slack", name="#security", url=SLACK, events=["incident.created"])
        assert secret is None and d.url_host == "hooks.slack.com" and "SECRETTOKEN" not in d.url_enc
        _, whsec = ob.save_destination(s, admin, kind="webhook", name="SIEM", url=HOOK, events=["incident.created"])
        assert whsec.startswith("whsec_")
        with pytest.raises(ValueError):
            ob.save_destination(s, admin, kind="teams", name="t", url=TEAMS, events=["everything"])
    with db.session_scope() as s:
        assert not any("SECRETTOKEN" in json.dumps(a.changes or {}) or "whsec_" in json.dumps(a.changes or {}) for a in s.scalars(select(AuditLog)))


def test_events_are_queued_and_delivered_with_the_right_shape(users, db, sink):
    from keystone.incidents import service as inc

    admin = users["admin"]
    with db.session_scope(admin) as s:
        ob.save_destination(s, admin, kind="slack", name="#sec", url=SLACK, events=["incident.created"])
        ob.save_destination(s, admin, kind="teams", name="Teams", url=TEAMS, events=["incident.created", "policy.approved"])
        _, whsec = ob.save_destination(s, admin, kind="webhook", name="SIEM", url=HOOK, events=["incident.created"])
        inc.report_incident(s, admin, title="Mia's laptop stolen from car", severity="high")
    with db.session_scope() as s:
        assert len(s.scalars(select(Delivery)).all()) == 3
        assert ob.deliver_due(s) == {"sent": 3, "failed": 0, "retry": 0}
    by_host = {c.url.host: c for c in sink["calls"]}
    slack = json.loads(by_host["hooks.slack.com"].content)
    assert "Incident INC-0001 reported" in slack["text"] and "laptop" not in slack["text"]  # no incident title in chat
    teams = json.loads(by_host["prod-12.westeurope.logic.azure.com"].content)
    assert teams["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    req = by_host["hooks.alpine.example"]
    t, v1 = (x.split("=", 1)[1] for x in req.headers["x-keystone-signature"].split(","))
    assert hmac.compare_digest(v1, hmac.new(whsec.encode(), f"{t}.".encode() + req.content, hashlib.sha256).hexdigest())
    body = json.loads(req.content)
    assert body["event"] == "incident.created" and req.headers["x-keystone-delivery"] == body["id"]


def test_failures_retry_with_backoff_and_never_store_the_url(users, db, sink):
    admin = users["admin"]
    with db.session_scope(admin) as s:
        d, _ = ob.save_destination(s, admin, kind="slack", name="#sec", url=SLACK, events=["system.alert"])
        ob.emit(s, "system.alert", title="Backup failed")
    sink["status"] = 404
    with db.session_scope() as s:
        assert ob.deliver_due(s)["retry"] == 1
        dl = s.scalars(select(Delivery)).one()
        assert dl.status == "pending" and dl.next_attempt_at > utcnow() + timedelta(seconds=50)
        assert "SECRETTOKEN" not in (dl.last_error or "") and "404" in dl.last_error
        for _ in range(5):
            dl.next_attempt_at = utcnow() - timedelta(seconds=1)
            ob.deliver_due(s)
        assert dl.status == "failed" and dl.attempts == 6
    with db.session_scope() as s:  # a disabled destination's queue is cancelled
        ob.save_destination(s, admin, d.id, enabled=False)
        ob.emit(s, "system.alert", title="x")  # nothing queued: disabled
        assert len(s.scalars(select(Delivery)).all()) == 1


def test_outbound_api(api, ready_users, db, sink):
    api_login(api, ready_users["isms_manager"].username)
    r = api.post("/api/outbound/destinations", json={"kind": "webhook", "name": "SIEM", "url": HOOK, "events": ["incident.created"]})
    assert r.status_code == 200 and r.json()["signing_secret"].startswith("whsec_") and "url" not in r.json()
    did = r.json()["id"]
    listed = api.get("/api/outbound/destinations").json()
    assert "whsec_" not in json.dumps(listed) and listed["destinations"][0]["url_host"] == "hooks.alpine.example"
    assert api.post(f"/api/outbound/destinations/{did}/test").json()["status"] == "sent"
    api.post("/api/auth/logout")
    api_login(api, ready_users["viewer"].username)
    assert api.get("/api/outbound/destinations").status_code == 403
