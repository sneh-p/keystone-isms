"""Batch 3 of the security expansion: phishing simulations, look-alike domains, supplier breach news, on-call
alerting and DMARC reports. No test touches the network: the downloads are replaced by fixed data."""

import gzip
import io
import re
import zipfile
from datetime import timedelta

import pytest
from sqlalchemy import select

from keystone.core.db import utcnow
from keystone.core.services import today
from keystone.notifications.models import Notification

from .conftest import api_login


# ---- phishing simulations -------------------------------------------------------------------------------------------

@pytest.fixture
def email_on(db, monkeypatch, users):
    from keystone.notifications import mailer
    from keystone.notifications.models import SmtpSettings

    monkeypatch.setenv("KEYSTONE_PUBLIC_URL", "https://isms.example.example")
    sent: list = []
    monkeypatch.setattr(mailer, "send", lambda cfg, msgs: sent.extend(msgs))
    with db.session_scope() as s:
        row = s.scalar(select(SmtpSettings)) or SmtpSettings()
        row.enabled, row.host, row.from_address, row.from_name = True, "smtp.example.example", "isms@example.example", "Security"
        s.add(row)
    return sent

def test_phishing_simulation(api, ready_users, db, email_on):
    from keystone.core import auth
    from keystone.phishing import service as ph
    from keystone.phishing.models import PhishingTarget

    with db.session_scope() as s:
        for u in s.scalars(select(auth.User)):
            u.email = f"{u.username}@example.example"
    api_login(api, "viewer")
    assert api.get("/api/phishing").status_code == 403
    api_login(api, "ismsmanager")
    assert api.post("/api/phishing", json={"name": "Q4", "template": "nope"}).status_code == 400
    c = api.post("/api/phishing", json={"name": "Q4 practice", "template": "password-expiry"}).json()
    r = api.post(f"/api/phishing/{c['id']}/launch")
    assert r.status_code == 400 and "Segregation of duties" in r.json()["detail"]
    api_login(api, "admin")
    assert api.post(f"/api/phishing/{c['id']}/launch").json()["status"] == "running"
    with db.session_scope() as s:
        assert ph.send_batch(s) >= 5
        assert all(t.token_hash and len(t.token_hash) == 64 for t in s.scalars(select(PhishingTarget)) if t.sent_at)  # only hashes kept
    msg = next(m for m in email_on if m["To"] == "employee@example.example")
    assert msg["Subject"] == "Action needed: your password expires today" and "isms@example.example" in msg["From"]
    token = re.search(r"/phish#t=([\w-]+)", msg.get_content()).group(1)

    api.post("/api/auth/logout")
    public = api.__class__(api.app)
    assert public.post("/api/public/phish", json={"token": "x" * 20}).status_code == 404
    landing = public.post("/api/public/phish", json={"token": token}).json()
    assert landing["red_flags"] and "password" not in str(landing.keys())  # it explains; it never asks for anything
    public.post("/api/public/phish", json={"token": token})

    api_login(api, "riskowner")  # reports the practice email from the portal: counts as caught
    api.post("/api/portal/reports", json={"kind": "phishing", "description": "Password expiry email with a strange link"})
    api_login(api, "admin")
    res = next(x for x in api.get("/api/phishing").json()["campaigns"] if x["id"] == c["id"])["results"]
    assert res["clicked"] == 1 and res["reported"] == 1 and res["click_rate"] > 0
    emp = next(p for p in res["people"] if p["name"] == "Employee")
    assert emp["clicked_at"] and not emp["reported_at"]
    assert api.post(f"/api/phishing/{c['id']}/complete").json()["status"] == "completed"
    with db.session_scope() as s:
        assert ph.latest_click_rate(s) == res["click_rate"]


def test_phishing_needs_email_and_a_public_address(api, ready_users):
    api_login(api, "ismsmanager")
    c = api.post("/api/phishing", json={"name": "Q1", "template": "invoice"}).json()
    api_login(api, "admin")
    r = api.post(f"/api/phishing/{c['id']}/launch")
    assert r.status_code == 400 and "email" in r.json()["detail"].lower()


# ---- look-alike domains ---------------------------------------------------------------------------------------------

def test_lookalike_matching():
    from keystone.threatintel.service import registrable, why_lookalike

    assert registrable("login.alpineskihouse.co.uk") == "alpineskihouse.co.uk" and registrable("a.b.example.com") == "example.com"
    assert why_lookalike("alpineskihouse-login.com", "alpineskihouse") == "Contains 'alpineskihouse'"
    assert why_lookalike("a1pineskihouse.com", "alpineskihouse") == "Same name with swapped look-alike characters"
    assert why_lookalike("alpineskihuose.com", "alpineskihouse") == "One or two typing mistakes away"
    assert why_lookalike("alpineskihouse.net", "alpineskihouse") == "Same name, different ending"
    assert why_lookalike("example.com", "alpineskihouse") is None


def test_lookalike_scan_and_decisions(api, ready_users, db):
    from keystone.asm.models import ExternalDomain
    from keystone.threatintel import service as ti

    with db.session_scope() as s:
        s.add(ExternalDomain(name="alpineskihouse.example", verification_token="x", verified_at=utcnow()))
        s.flush()
        found = {"alpineskihouse.example", "alpineskihouse-login.com", "a1pineskihouse.com", "weather.example", "alpineskihuose.com"}
        assert ti.scan_lookalikes(s, fetch=lambda pattern: found) == 3
        assert ti.scan_lookalikes(s, fetch=lambda pattern: found) == 0  # seen before: not new again
        assert s.scalars(select(Notification).where(Notification.title.like("%look-alike%"))).first() is not None
    api_login(api, "viewer")
    rows = api.get("/api/lookalikes").json()["lookalikes"]
    assert {r["name"] for r in rows} == {"alpineskihouse-login.com", "a1pineskihouse.com", "alpineskihuose.com"}
    assert api.post(f"/api/lookalikes/{rows[0]['id']}/decide", json={"status": "threat", "note": "x"}).status_code == 403
    api_login(api, "admin")
    assert api.post(f"/api/lookalikes/{rows[0]['id']}/decide", json={"status": "threat"}).status_code == 400  # say what is done
    assert api.post(f"/api/lookalikes/{rows[0]['id']}/decide", json={"status": "threat", "note": "Takedown requested from the registrar"}).json()["status"] == "threat"


# ---- supplier breach news -------------------------------------------------------------------------------------------

def test_supplier_breach_news(api, ready_users, db):
    from keystone.threatintel import service as ti
    from keystone.tprm import service as tprm

    with db.session_scope() as s:
        v = tprm.save_vendor(s, ready_users["admin"], name="Fabrikam Backup", website="https://www.fabrikam.example", owner_id=ready_users["control_owner"].id)
        feed = [{"Name": "Fabrikam", "Title": "Fabrikam", "Domain": "fabrikam.example", "BreachDate": "2026-10-01", "AddedDate": str(today()) + "T10:00:00Z",
                 "PwnCount": 120000, "DataClasses": ["Email addresses", "Passwords"]},
                {"Name": "Other", "Title": "Other", "Domain": "other.example", "AddedDate": str(today())}]
        assert ti.scan_breaches(s, fetch=lambda: feed) == 1
        assert ti.scan_breaches(s, fetch=lambda: feed) == 0
        owner_note = s.scalars(select(Notification).where(Notification.user_id == ready_users["control_owner"].id, Notification.title.like("Breach reported%"))).first()
        assert owner_note is not None and v.id
    api_login(api, "viewer")
    b = api.get("/api/vendor-breaches").json()["breaches"][0]
    assert b["vendor"] == "Fabrikam Backup" and b["data_classes"] == ["Email addresses", "Passwords"]
    assert api.post(f"/api/vendor-breaches/{b['id']}/decide", json={"status": "assessing", "note": "x"}).status_code == 403
    api_login(api, "controlowner")
    assert api.post(f"/api/vendor-breaches/{b['id']}/decide", json={"status": "assessing", "note": "x"}).status_code == 403  # vendor.write
    api_login(api, "ismsmanager")
    assert api.post(f"/api/vendor-breaches/{b['id']}/decide", json={"status": "assessing", "note": "Asked the vendor for details"}).json()["status"] == "assessing"


# ---- on-call ----------------------------------------------------------------------------------------------------------

def test_on_call_paging_and_escalation(api, ready_users, db):
    from keystone.incidents import service as inc
    from keystone.oncall import service as oc
    from keystone.oncall.models import Page

    mgr, ctl = ready_users["isms_manager"], ready_users["control_owner"]
    api_login(api, "viewer")
    assert api.post("/api/oncall", json={"name": "x", "member_ids": [mgr.id], "start_on": str(today()), "rotation_days": 7, "escalate_after_minutes": 15}).status_code == 403
    api_login(api, "ismsmanager")
    bad = {"name": "Security", "member_ids": [ready_users["viewer"].id], "start_on": str(today()), "rotation_days": 7, "escalate_after_minutes": 15}
    assert api.post("/api/oncall", json=bad).status_code == 400  # members must be able to handle incidents
    rota = api.post("/api/oncall", json={**bad, "member_ids": [ctl.id, mgr.id]}).json()
    assert api.get("/api/oncall").json()["rotas"][0]["on_call"] == ctl.id
    with db.session_scope() as s:
        i = inc.report_incident(s, ready_users["admin"], title="Ransomware on file server", category="ransomware", severity="critical")
        page = s.scalar(select(Page).where(Page.source == f"incident:{i.id}"))
        assert page.user_id == ctl.id and page.level == 0
        page.created_at = utcnow() - timedelta(minutes=20)
        assert oc.escalate(s) == 1
        nxt = s.scalar(select(Page).where(Page.source == f"incident:{i.id}", Page.level == 1))
        assert nxt.user_id == mgr.id
        first = page.id
    assert api.post(f"/api/oncall/pages/{first}/ack").status_code == 404  # only the person paged acknowledges
    r = api.post(f"/api/oncall/pages/{nxt.id}/ack")
    assert r.status_code == 200
    with db.session_scope() as s:
        assert all(p.acked_at for p in s.scalars(select(Page).where(Page.source == f"incident:{i.id}")))  # one ack stops the call
        assert oc.escalate(s, utcnow() + timedelta(hours=2)) == 0
    assert rota["id"]


# ---- DMARC reports -------------------------------------------------------------------------------------------------

def _report(report_id: str, records: list[tuple[str, int, str, str, str]]) -> bytes:
    rows = "".join(f"<record><row><source_ip>{ip}</source_ip><count>{n}</count><policy_evaluated><disposition>{disp}</disposition><dkim>{dkim}</dkim>"
                   f"<spf>{spf}</spf></policy_evaluated></row><identifiers><header_from>alpineskihouse.example</header_from></identifiers></record>"
                   for ip, n, disp, dkim, spf in records)
    return (f"<?xml version='1.0'?><feedback><report_metadata><org_name>mail.example</org_name><report_id>{report_id}</report_id>"
            f"<date_range><begin>{int(utcnow().timestamp()) - 86400}</begin><end>{int(utcnow().timestamp())}</end></date_range></report_metadata>"
            f"<policy_published><domain>alpineskihouse.example</domain><p>quarantine</p></policy_published>{rows}</feedback>").encode()


def test_dmarc_reports(api, ready_users):
    good = _report("r1", [("198.51.100.10", 900, "none", "pass", "pass"), ("203.0.113.66", 40, "quarantine", "fail", "fail")])
    api_login(api, "viewer")
    assert api.post("/api/dmarc", files={"file": ("r1.xml", good, "text/xml")}).status_code == 403
    api_login(api, "admin")
    assert api.post("/api/dmarc", files={"file": ("r1.xml", good, "text/xml")}).json() == {"added": 1, "already_had": 0}
    assert api.post("/api/dmarc", files={"file": ("r1.xml", good, "text/xml")}).json()["already_had"] == 1
    assert api.post("/api/dmarc", files={"file": ("r2.xml.gz", gzip.compress(_report("r2", [("198.51.100.10", 10, "none", "pass", "fail")])), "application/gzip")}).json()["added"] == 1
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        z.writestr("r3.xml", _report("r3", [("192.0.2.5", 5, "reject", "fail", "fail")]))
    assert api.post("/api/dmarc", files={"file": ("r3.zip", zbuf.getvalue(), "application/zip")}).json()["added"] == 1
    many = io.BytesIO()
    with zipfile.ZipFile(many, "w") as z:
        for n in range(6):
            z.writestr(f"r{n}.xml", b"<feedback/>")
    assert api.post("/api/dmarc", files={"file": ("many.zip", many.getvalue(), "application/zip")}).status_code == 400
    xxe = b'<?xml version="1.0"?><!DOCTYPE feedback [<!ENTITY x SYSTEM "file:///etc/passwd">]><feedback>&x;</feedback>'
    assert api.post("/api/dmarc", files={"file": ("x.xml", xxe, "text/xml")}).status_code == 400  # DTDs refused
    assert api.post("/api/dmarc", files={"file": ("x.pdf", b"%PDF-1.4", "application/pdf")}).status_code == 400
    s = api.get("/api/dmarc").json()
    assert s["messages"] == 955 and s["passed"] == 910 and s["sources"][0]["passed"] < s["sources"][0]["messages"]  # failing sources first

