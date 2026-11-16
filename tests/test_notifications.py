"""Inbox, daily digest and SMTP settings."""

import socket
import socketserver
import threading
from datetime import date, datetime

import pytest
from sqlalchemy import select

from keystone import demo
from keystone.core import auth
from keystone.core.audit import AuditLog
from keystone.notifications import mailer, service as ntf
from keystone.notifications.models import Notification

from .conftest import api_login

RELAY_VALUE = "S3cret-relay-pw"  # a made-up SMTP relay password for the write-only checks


@pytest.fixture
def demo_db(db):
    with db.session_scope() as s:
        admin = auth.create_user(s, None, username="admin", display_name="Admin", password=demo.DEMO_PASSWORD, email="admin@example.test")
    with db.session_scope(admin) as s:
        demo.seed(s, s.get(auth.User, admin.id))
    return db


def _user(s, name):
    return s.scalar(select(auth.User).where(auth.User.username == name))


def test_refresh_dedupes_and_resolves(demo_db):
    with demo_db.session_scope() as s:
        mia = _user(s, "mia.isms")
        added = ntf.refresh(s, mia)
        assert added > 0 and ntf.refresh(s, mia) == 0  # same items are not added twice
        items = ntf.inbox(s, mia)
        assert all(n.page.startswith("/") for n in items)
        assert all(n.due is None or (n.due - date.today()).days <= ntf.NOTIFY_WITHIN_DAYS for n in items)
        # An item that no longer needs action is resolved, not deleted.
        first = items[0]
        orig = ntf.items_for
        ntf.items_for = lambda session, user, on=None, routed=None: [i for i in orig(session, user, on, routed) if i["key"] != first.key]
        try:
            ntf.refresh(s, mia)
        finally:
            ntf.items_for = orig
        assert s.get(Notification, first.id).resolved_at is not None
        assert first.id not in [n.id for n in ntf.inbox(s, mia)]


def test_inbox_is_per_user_api(api, demo_db):
    with demo_db.session_scope() as s:
        ntf.refresh_all(s)
        other = s.scalar(select(Notification).join(auth.User, auth.User.id == Notification.user_id).where(auth.User.username == "mia.isms")).id
    api.cookies.clear()
    assert api.get("/api/portal/notifications").status_code == 401
    api_login(api, "raj.risk", demo.DEMO_PASSWORD)
    body = api.get("/api/portal/notifications").json()
    assert body["unread"] == len(body["items"]) and other not in [i["id"] for i in body["items"]]
    assert api.post("/api/portal/notifications/read", json={"ids": [other]}).status_code == 404  # someone else's item
    if body["items"]:
        assert api.post("/api/portal/notifications/read", json={"ids": [body["items"][0]["id"]]}).json() == {"updated": 1}
    assert api.post("/api/portal/notifications/read", json={}).status_code == 200
    assert api.get("/api/portal/notifications").json()["unread"] == 0
    assert api.put("/api/portal/notifications/prefs", json={"email_digest": False}).json() == {"email_digest": False}
    assert api.put("/api/portal/notifications/prefs", json={"email_digest": False, "user_id": 1}).status_code == 422
    # SMTP settings are for administrators only.
    assert api.get("/api/settings/email").status_code == 403
    assert api.put("/api/settings/email", json={"enabled": False}).status_code == 403


def test_smtp_settings_password_is_write_only_and_bound_to_host(api, demo_db, monkeypatch):
    monkeypatch.setattr(mailer, "resolve", lambda host: "203.0.113.10")
    api_login(api, "admin", demo.DEMO_PASSWORD)
    r = api.put("/api/settings/email", json={"host": "smtp.example.com", "port": 587, "security": "starttls", "username": "keystone", "password": RELAY_VALUE, "from_address": "isms@example.com", "enabled": True})
    assert r.status_code == 200, r.text
    assert r.json()["password_set"] is True and RELAY_VALUE not in r.text and "password_enc" not in r.text
    assert RELAY_VALUE not in api.get("/api/settings/email").text
    with demo_db.session_scope() as s:
        assert all(RELAY_VALUE not in (a.changes and str(a.changes) or "") for a in s.scalars(select(AuditLog)))
    # Changing the host without re-entering the password drops it (SC-SSRF-003).
    r = api.put("/api/settings/email", json={"host": "mail.attacker.example"})
    assert r.json()["password_set"] is False
    for bad in ({"port": 22}, {"security": "none"}, {"host": "10.0.0.5"}, {"host": "https://smtp.example.com"}, {"from_name": "x\r\nBcc: victim@example.com"}, {"from_address": "nope"}, {"digest_hour_utc": 24}):
        assert api.put("/api/settings/email", json=bad).status_code == 400, bad


def test_private_relay_needs_operator_allowlist(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 0))])
    monkeypatch.delenv("KEYSTONE_SMTP_PRIVATE_HOSTS", raising=False)
    with pytest.raises(ValueError, match="KEYSTONE_SMTP_PRIVATE_HOSTS"):
        mailer.resolve("relay.corp.example")
    monkeypatch.setenv("KEYSTONE_SMTP_PRIVATE_HOSTS", "relay.corp.example")
    assert mailer.resolve("relay.corp.example") == "10.1.2.3"
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))])
    with pytest.raises(ValueError, match="loopback"):
        mailer.resolve("relay.corp.example")


class _NoTls(socketserver.BaseRequestHandler):
    def handle(self):
        f = self.request.makefile("rwb")
        f.write(b"220 fake ESMTP\r\n"); f.flush()
        while line := f.readline():
            if line.upper().startswith((b"EHLO", b"HELO")):
                f.write(b"250-fake\r\n250 AUTH PLAIN\r\n")
            elif line.upper().startswith(b"QUIT"):
                f.write(b"221 bye\r\n"); f.flush()
                return
            else:
                f.write(b"250 ok\r\n")
            f.flush()


def test_no_plaintext_fallback(monkeypatch):
    srv = socketserver.TCPServer(("127.0.0.1", 0), _NoTls)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setattr(mailer, "resolve", lambda host: "127.0.0.1")
        monkeypatch.setattr(mailer, "ALLOWED_PORTS", (port,))
        with pytest.raises(ValueError, match="STARTTLS"):
            mailer.connect("smtp.example.com", port, "starttls")
    finally:
        srv.shutdown()


def test_headers_cannot_be_injected():
    with pytest.raises(ValueError):
        mailer.build("a@example.com", "Keystone", "b@example.com", "Hi\r\nBcc: c@example.com", "body").as_string()


def test_daily_digest(demo_db, monkeypatch):
    sent = []
    monkeypatch.setattr(mailer, "send", lambda cfg, msgs: sent.extend(msgs))
    monkeypatch.setattr(mailer, "resolve", lambda host: "203.0.113.10")
    with demo_db.session_scope() as s:
        admin = _user(s, "admin")
        ntf.update_smtp(s, admin, host="smtp.example.com", from_address="isms@example.com", enabled=True, digest_hour_utc=7)
        ntf.refresh_all(s)
        sam = _user(s, "sam.view")
        ntf.set_prefs(s, _user(s, "raj.risk"), False)  # opted out
        assert ntf.send_digests(s, datetime(2026, 11, 16, 6, 0)) == 0  # before the digest hour
        n = ntf.send_digests(s, datetime(2026, 11, 16, 7, 5))
        assert n == len(sent) > 0
        to = {m["To"] for m in sent}
        assert "raj.risk@alpineskihouse.example" not in to
        assert all(m["Subject"].startswith("Keystone: ") and "\n" not in m["Subject"] for m in sent)
        assert ntf.send_digests(s, datetime(2026, 11, 16, 9, 0)) == 0  # once a day
        assert sam is not None


def test_employees_have_an_inbox(api, ready_users):
    api_login(api, "employee")
    r = api.get("/api/portal/notifications")
    assert r.status_code == 200 and r.json()["unread"] == 0
    assert api.get("/api/settings/email").status_code == 403
