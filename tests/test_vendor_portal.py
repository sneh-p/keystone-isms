"""Vendor self-service portal: links, public access, uploads with virus scanning."""

import os
import socket
import struct
import tempfile
import threading

import pytest
from sqlalchemy import select

from keystone import demo
from keystone.core import auth
from keystone.core.attachments import Attachment
from keystone.core.audit import AuditLog
from keystone.tprm.models import VendorPortalLink, VendorQuestionnaire
from keystone.trust import service as trust

from .conftest import api_login

PDF = b"%PDF-1.4 vendor SOC 2 report"
H = "X-Vendor-Token"


class FakeClamd:
    """Speaks enough of clamd's INSTREAM protocol: 'EICAR' in the stream means infected."""

    def __init__(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "clamd.sock")
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(self.path)
        self.srv.listen(8)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            with c:
                f = c.makefile("rb")
                cmd = b""
                while not cmd.endswith(b"\0"):
                    cmd += f.read(1)
                if cmd == b"zPING\0":
                    c.sendall(b"PONG\0")
                    continue
                data = b""
                while (n := struct.unpack(">I", f.read(4))[0]):
                    data += f.read(n)
                c.sendall(b"stream: Eicar-Test-Signature FOUND\0" if b"EICAR" in data else b"stream: OK\0")

    def close(self):
        self.srv.close()


@pytest.fixture
def clamd(monkeypatch):
    fake = FakeClamd()
    monkeypatch.setenv("KEYSTONE_CLAMD_SOCKET", fake.path)
    monkeypatch.delenv("KEYSTONE_CLAMD_TCP", raising=False)
    yield fake
    fake.close()


@pytest.fixture
def demo_api(api, db):
    with db.session_scope() as s:
        admin = auth.create_user(s, None, username="admin", display_name="Admin", password=demo.DEMO_PASSWORD)
    with db.session_scope(admin) as s:
        demo.seed(s, s.get(auth.User, admin.id))
    trust._hits.clear()
    return api


def _sent_questionnaire(db) -> int:
    with db.session_scope() as s:
        return s.scalar(select(VendorQuestionnaire.id).where(VendorQuestionnaire.status == "sent"))


def _link(api, qid, **kw) -> str:
    r = api.post(f"/api/questionnaires/{qid}/portal-link", json=kw)
    assert r.status_code == 200, r.text
    assert r.json()["path"].startswith("/vendor-portal#token=")
    return r.json()["path"].split("#token=")[1]


def test_link_lifecycle_and_isolation(demo_api, db):
    api = demo_api
    qid = _sent_questionnaire(db)
    api_login(api, "sam.view", demo.DEMO_PASSWORD)
    assert api.post(f"/api/questionnaires/{qid}/portal-link", json={}).status_code == 403
    api_login(api, "mia.isms", demo.DEMO_PASSWORD)
    token = _link(api, qid, contact_name="Ana Vendor", contact_email="ana@northwind.example")
    with db.session_scope() as s:
        link = s.scalar(select(VendorPortalLink))
        assert link.expires_at is None  # default: never expires
        assert token not in link.token_hash and all(token not in (a.summary + str(a.changes or "")) for a in s.scalars(select(AuditLog)))
    public = api.__class__(api.app)  # no session cookie: a vendor's browser
    v = public.get("/api/public/vendor-portal", headers={H: token})
    assert v.status_code == 200
    body = v.json()
    assert body["editable"] and body["vendor"] and body["questions"]
    assert all(set(q) == {"id", "section", "text", "type", "required"} for q in body["questions"])  # no weights or control mappings
    assert "weight" not in v.text and "KC-" not in v.text and "mia" not in v.text.lower()
    for bad in ({}, {H: "nope"}, {H: "x" * 300}):
        r = public.get("/api/public/vendor-portal", headers=bad)
        assert r.status_code == 404 and "not valid" in r.json()["detail"]
    assert public.get(f"/api/public/vendor-portal?token={token}").status_code == 404  # never via the URL
    # A new link replaces the old one; revoking and expiring both close access.
    token2 = _link(api, qid)
    assert public.get("/api/public/vendor-portal", headers={H: token}).status_code == 404
    assert public.get("/api/public/vendor-portal", headers={H: token2}).status_code == 200
    lid = api.get(f"/api/questionnaires/{qid}/portal").json()["links"][0]["id"]
    assert api.patch(f"/api/portal-links/{lid}", json={"expires_at": "2000-01-01T00:00:00Z"}).status_code == 400
    with db.session_scope() as s:
        from datetime import datetime, timedelta

        s.get(VendorPortalLink, lid).expires_at = datetime.now() - timedelta(minutes=1)
    assert public.get("/api/public/vendor-portal", headers={H: token2}).status_code == 404
    assert api.patch(f"/api/portal-links/{lid}", json={"expires_at": None}).status_code == 200
    assert public.get("/api/public/vendor-portal", headers={H: token2}).status_code == 200
    assert api.post(f"/api/portal-links/{lid}/revoke").status_code == 200
    assert public.get("/api/public/vendor-portal", headers={H: token2}).status_code == 404


def test_answers_submit_and_lock(demo_api, db):
    api = demo_api
    qid = _sent_questionnaire(db)
    api_login(api, "mia.isms", demo.DEMO_PASSWORD)
    token = _link(api, qid)
    public = api.__class__(api.app)
    view = public.get("/api/public/vendor-portal", headers={H: token}).json()
    q0 = view["questions"][0]
    assert public.put("/api/public/vendor-portal", headers={H: token}, json={"responses": {q0["id"]: {"answer": "maybe-ish"}}}).status_code == 400
    assert public.put("/api/public/vendor-portal", headers={H: token}, json={"responses": {"zz": {"answer": "yes"}}}).status_code == 400
    assert public.put("/api/public/vendor-portal", headers={H: token}, json={"responses": {q0["id"]: {"answer": "yes", "comment": "x" * 10_001}}}).status_code == 400
    r = public.put("/api/public/vendor-portal", headers={H: token}, json={"responses": {q0["id"]: {"answer": "yes", "comment": "Policy v3"}}})
    assert r.status_code == 200 and r.json()["responses"][q0["id"]]["answer"] == "yes"
    r = public.put("/api/public/vendor-portal", headers={H: token}, json={"responses": {}, "submit": True})
    assert r.status_code == 400 and "Required" in r.json()["detail"]
    answers = {q["id"]: {"answer": (view["answer_options"][q["type"]] or ["Text answer"])[0]} for q in view["questions"]}
    r = public.put("/api/public/vendor-portal", headers={H: token}, json={"responses": answers, "submit": True})
    assert r.status_code == 200 and r.json()["editable"] is False
    assert public.put("/api/public/vendor-portal", headers={H: token}, json={"responses": answers}).status_code == 400
    with db.session_scope() as s:
        assert s.get(VendorQuestionnaire, qid).status == "received"
        assert s.scalars(select(AuditLog).where(AuditLog.summary.like("Submitted by the vendor%"))).first() is not None
        # The vendor's owner is told it came back.
        from keystone.notifications import service as ntf

        vq = s.get(VendorQuestionnaire, qid)
        from keystone.tprm.models import Vendor

        owner = s.get(auth.User, s.get(Vendor, vq.vendor_id).owner_id)
        assert any("returned by" in i["title"] for i in ntf.items_for(s, owner))


def test_uploads_are_checked_and_scanned(demo_api, db, clamd):
    api = demo_api
    qid = _sent_questionnaire(db)
    api_login(api, "mia.isms", demo.DEMO_PASSWORD)
    token = _link(api, qid)
    public = api.__class__(api.app)

    def up(name, data):
        return public.post("/api/public/vendor-portal/files", headers={H: token}, files={"file": (name, data, "application/octet-stream")})

    r = up("soc2.pdf", PDF)
    assert r.status_code == 200 and r.json()["files"][0]["filename"] == "soc2.pdf"
    fid = r.json()["files"][0]["id"]
    assert len(fid) == 32 and not fid.isdigit()
    assert up("page.html", b"<script>alert(1)</script>").status_code == 400
    assert up("image.svg", b"<svg onload=alert(1)>").status_code == 400
    assert up("fake.pdf", b"MZ\x90\x00 not a pdf").status_code == 400
    assert up("big.pdf", b"%PDF" + b"0" * (10 * 1024 * 1024)).status_code == 400
    assert up("bomb.xlsx", b"PK\x03\x04garbage").status_code == 400  # archive checks
    r = up("eicar.pdf", b"%PDF-1.4 EICAR test")
    assert r.status_code == 400 and "virus scanner" in r.json()["detail"]
    with db.session_scope() as s:
        assert s.scalars(select(AuditLog).where(AuditLog.action == "upload_blocked")).first() is not None
        assert s.scalar(select(Attachment).where(Attachment.filename == "eicar.pdf")) is None
    # Staff see the file and can open it; the vendor can download their own copy.
    files = api.get(f"/api/questionnaires/{qid}/portal").json()["files"]
    assert [f["filename"] for f in files] == ["soc2.pdf"]
    assert api.get(f"/api/attachments/{files[0]['id']}").content == PDF
    assert public.get(f"/api/public/vendor-portal/files/{fid}", headers={H: token}).content == PDF
    assert public.get("/api/public/vendor-portal/files/0" * 1, headers={H: token}).status_code in (404, 405)
    assert public.delete(f"/api/public/vendor-portal/files/{fid}", headers={H: token}).json()["files"] == []


def test_scanner_down_fails_closed(demo_api, db, monkeypatch):
    api = demo_api
    monkeypatch.setenv("KEYSTONE_CLAMD_SOCKET", "/nonexistent/clamd.sock")
    qid = _sent_questionnaire(db)
    api_login(api, "mia.isms", demo.DEMO_PASSWORD)
    token = _link(api, qid)
    public = api.__class__(api.app)
    r = public.post("/api/public/vendor-portal/files", headers={H: token}, files={"file": ("soc2.pdf", PDF, "application/pdf")})
    assert r.status_code == 503 and "virus scanning is unavailable" in r.json()["detail"]
    with db.session_scope() as s:
        assert s.scalar(select(Attachment).where(Attachment.filename == "soc2.pdf")) is None
    assert api.get(f"/api/questionnaires/{qid}/portal").json()["scanner_ok"] is False


def test_file_limit_and_rate_limit(demo_api, db, clamd, monkeypatch):
    api = demo_api
    qid = _sent_questionnaire(db)
    api_login(api, "mia.isms", demo.DEMO_PASSWORD)
    token = _link(api, qid)
    public = api.__class__(api.app)
    from keystone.tprm import portal

    monkeypatch.setattr(portal, "MAX_FILES", 2)
    for i in range(2):
        assert public.post("/api/public/vendor-portal/files", headers={H: token}, files={"file": (f"r{i}.pdf", PDF + bytes([i]), "application/pdf")}).status_code == 200
    r = public.post("/api/public/vendor-portal/files", headers={H: token}, files={"file": ("r3.pdf", PDF + b"3", "application/pdf")})
    assert r.status_code == 400 and "At most 2" in r.json()["detail"]
    trust._hits.clear()
    orig = trust.rate_limit
    monkeypatch.setattr(portal, "rate_limit", lambda key, limit=5, window=3600: orig(key, limit=min(limit, 3), window=window))
    codes = [public.get("/api/public/vendor-portal", headers={H: token}).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and 429 in codes
