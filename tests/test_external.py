"""External attack surface: ownership verification, passive discovery, DNS/email checks, host checks, API."""

from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select

from keystone.asm import external as ext
from keystone.asm.models import ExternalDomain, ExternalHost
from keystone.integrations import http
from keystone.integrations.providers.base import Outcome

from .conftest import api_login

DOMAIN = "alpine.example"


class Zone:
    """A fake DNS: {(name, type): [values]}, plus names that don't exist."""

    def __init__(self):
        self.records: dict[tuple[str, str], list[str]] = {}
        self.nx: set[str] = set()

    def txt(self, name):
        return list(self.records.get((name, "TXT"), []))

    def recs(self, name, rtype):
        return list(self.records.get((name, rtype), []))

    def nxdomain(self, name):
        return name in self.nx


@pytest.fixture
def zone(monkeypatch):
    z = Zone()
    monkeypatch.setattr(ext, "dns_txt", z.txt)
    monkeypatch.setattr(ext, "dns_records", z.recs)
    monkeypatch.setattr(ext, "dns_nxdomain", z.nxdomain)
    return z


@pytest.fixture
def crtsh(monkeypatch):
    state = {"rows": [{"name_value": f"vpn.{DOMAIN}\n*.{DOMAIN}"}, {"name_value": f"old.{DOMAIN}"}, {"name_value": "evil.example\nalpine.example.evil.example"}], "status": 200, "calls": []}

    def handler(req: httpx.Request) -> httpx.Response:
        state["calls"].append(str(req.url))
        assert req.url.host == "crt.sh"
        return httpx.Response(state["status"], json=state["rows"])

    monkeypatch.setattr(http, "TEST_TRANSPORT", httpx.MockTransport(handler))
    return state


def _domain(session, users, zone, verified=True) -> ExternalDomain:
    d = ext.add_domain(session, users["admin"], f"https://{DOMAIN.upper()}/")
    if verified:
        zone.records[(f"_keystone-verification.{DOMAIN}", "TXT")] = [d.verification_token]
        ext.verify(session, users["admin"], d.id)
    return d


def test_domains_must_be_verified_before_anything_is_looked_up(users, session, zone, crtsh):
    d = _domain(session, users, zone, verified=False)
    assert d.name == DOMAIN and d.verification_token.startswith("keystone-site-verification=")
    with pytest.raises(ext.NotVerified):
        ext.verify(session, users["admin"], d.id)
    with pytest.raises(ext.NotVerified):
        ext.scan(session, users["admin"], d.id, probe=lambda h: ({}, []))
    assert crtsh["calls"] == []  # nothing was enumerated for an unverified domain
    zone.records[(DOMAIN, "TXT")] = ["v=spf1 -all", d.verification_token]  # the apex works too
    assert ext.verify(session, users["admin"], d.id).verified_at is not None
    with pytest.raises(ValueError):
        ext.add_domain(session, users["admin"], DOMAIN)
    for bad in ("localhost", "10.0.0.1", "exa mple.com", "a.b"):
        with pytest.raises(ValueError):
            ext.add_domain(session, users["admin"], bad)


def test_scan_discovers_only_hosts_under_the_domain(users, session, zone, crtsh):
    d = _domain(session, users, zone)
    probed = []

    def probe(h):
        probed.append(h)
        return ({"web": "https"}, [ext._issue("hsts_missing", "low", "x")] if h == f"vpn.{DOMAIN}" else [])

    out = ext.scan(session, users["admin"], d.id, probe=probe)
    assert sorted(probed) == sorted([DOMAIN, f"www.{DOMAIN}", f"vpn.{DOMAIN}", f"old.{DOMAIN}"])  # not evil.example
    assert out["hosts"] == 4
    hosts = {h.host: h for h in session.scalars(select(ExternalHost))}
    assert hosts[f"vpn.{DOMAIN}"].worst == "low" and hosts[f"vpn.{DOMAIN}"].source == "ct"
    # A host certificate logs don't show can be added, but only under the domain
    ext.add_host(session, users["admin"], d.id, f"intranet.{DOMAIN}")
    with pytest.raises(ValueError, match="isn't part of"):
        ext.add_host(session, users["admin"], d.id, "intranet.other.example")
    crtsh["rows"] = []
    ext.scan(session, users["admin"], d.id, probe=probe)
    assert f"intranet.{DOMAIN}" in probed and not hosts[f"old.{DOMAIN}"].current


def test_scan_stops_when_the_verification_record_is_removed(users, session, zone, crtsh):
    d = _domain(session, users, zone)
    zone.records.clear()
    with pytest.raises(ext.NotVerified):
        ext.scan(session, users["admin"], d.id, probe=lambda h: ({}, []))
    assert d.verified_at is None and "no longer checked" in d.scan_error
    assert crtsh["calls"] == []


def test_email_checks(zone):
    zone.records[(DOMAIN, "TXT")] = ["v=spf1 include:spf.protection.outlook.com +all"]
    _facts, issues = ext.email_checks(DOMAIN)
    assert {i["code"] for i in issues} == {"spf_pass_all", "dmarc_missing", "caa_missing"}
    zone.records[(DOMAIN, "TXT")] = ["v=spf1 include:spf.protection.outlook.com -all"]
    zone.records[(f"_dmarc.{DOMAIN}", "TXT")] = ["v=DMARC1; p=none; rua=mailto:d@alpine.example"]
    zone.records[(DOMAIN, "CAA")] = ['0 issue "letsencrypt.org"']
    facts, issues = ext.email_checks(DOMAIN)
    assert [i["code"] for i in issues] == ["dmarc_monitor_only"] and facts["dmarc_policy"] == "none"
    zone.records[(f"_dmarc.{DOMAIN}", "TXT")] = ["v=DMARC1; p=reject"]
    assert ext.email_checks(DOMAIN)[1] == []
    zone.records[(DOMAIN, "TXT")] = ["v=spf1 a", "v=spf1 mx"]
    assert [i["code"] for i in ext.email_checks(DOMAIN)[1]] == ["spf_multiple"]


def test_host_checks_takeover_internal_and_web(zone, monkeypatch):
    zone.records[("shop.alpine.example", "CNAME")] = ["alpine-shop.azurewebsites.net"]
    zone.nx.add("alpine-shop.azurewebsites.net")
    facts, issues = ext.check_host("shop.alpine.example")
    assert [i["code"] for i in issues] == ["dangling_cname"] and issues[0]["severity"] == "high"

    zone.records[("intranet.alpine.example", "A")] = ["10.1.2.3"]
    assert [i["code"] for i in ext.check_host("intranet.alpine.example")[1]] == ["internal_address"]

    called = []
    monkeypatch.setattr(ext, "_probe_web", lambda h: (called.append(h) or ({"web": "https"}, [])))
    zone.records[("www.alpine.example", "A")] = ["93.184.216.34"]
    assert ext.check_host("www.alpine.example") == ({"cname": None, "addresses": ["93.184.216.34"], "web": "https"}, [])
    assert called == ["www.alpine.example"]  # private and dangling names were never probed
    assert ext.check_host("gone.alpine.example")[0]["web"] == "no address"


def test_web_outcomes_become_issues(monkeypatch):
    from keystone.integrations.providers import website

    def fake_run(self, config, secrets, session=None):
        return [Outcome("https_redirect", "fail", "HTTP returned 200"), Outcome("security_headers", "fail", "Missing", {"missing": ["strict-transport-security"]}),
                Outcome("tls_version", "fail", "Negotiated TLSv1.0", {"version": "TLSv1.0"}), Outcome("certificate", "fail", "Expires in 3 days", {"expires": "2026-11-19"})]

    monkeypatch.setattr(website.WebsiteProvider, "run", fake_run)
    facts, issues = ext._probe_web("old.alpine.example")
    assert {i["code"] for i in issues} == {"no_https_redirect", "hsts_missing", "tls_old", "cert_expiring"}
    assert facts["tls_version"] == "TLSv1.0" and facts["cert_expires"] == "2026-11-19"

    def bad_cert(self, config, secrets, session=None):
        return [Outcome("tls_version", "error", "TLS connection failed: SSLCertVerificationError")]

    monkeypatch.setattr(website.WebsiteProvider, "run", bad_cert)
    assert [i["code"] for i in ext._probe_web("x.alpine.example")[1]] == ["cert_invalid"]


def test_new_high_issues_notify_managers(users, session, zone, crtsh):
    from keystone.notifications.models import Notification

    d = _domain(session, users, zone)
    ext.scan(session, users["admin"], d.id, probe=lambda h: ({}, [ext._issue("dangling_cname", "high", "x")] if h.startswith("vpn.") else []))
    notes = session.scalars(select(Notification).where(Notification.kind == "asm")).all()
    assert {n.user_id for n in notes} == {users["isms_manager"].id}
    n_before = len(notes)
    ext.scan(session, users["admin"], d.id, probe=lambda h: ({}, [ext._issue("dangling_cname", "high", "x")] if h.startswith("vpn.") else []))
    assert len(session.scalars(select(Notification).where(Notification.kind == "asm")).all()) == n_before  # same issue: no repeat


def test_external_api(api, ready_users, db, zone, crtsh, monkeypatch):
    monkeypatch.setattr(ext, "check_host", lambda h: ({"web": "https"}, []))
    assert api.get("/api/asm/external").status_code == 401
    api_login(api, ready_users["viewer"].username)
    assert api.post("/api/asm/external/domains", json={"name": DOMAIN}).status_code == 403
    api.post("/api/auth/logout")
    api_login(api, "admin")
    r = api.post("/api/asm/external/domains", json={"name": DOMAIN})
    did = r.json()["id"]
    assert api.post(f"/api/asm/external/domains/{did}/scan").status_code == 409
    assert api.post(f"/api/asm/external/domains/{did}/verify").status_code == 409
    token = api.get("/api/asm/external").json()["domains"][0]["verification"]["value"]
    zone.records[(f"_keystone-verification.{DOMAIN}", "TXT")] = [token]
    assert api.post(f"/api/asm/external/domains/{did}/verify").status_code == 200
    assert api.post(f"/api/asm/external/domains/{did}/scan").json()["hosts"] == 4
    api.post("/api/auth/logout")
    api_login(api, ready_users["viewer"].username)
    body = api.get("/api/asm/external").json()
    assert body["domains"][0]["verified"] and body["domains"][0]["verification"] is None  # viewers don't see the token
    assert {h["host"] for h in body["hosts"]} >= {DOMAIN, f"vpn.{DOMAIN}"}
    api.post("/api/auth/logout")
    api_login(api, "admin")
    assert api.post(f"/api/asm/external/domains/{did}/hosts", json={"host": "intranet.other.example"}).status_code == 400
    assert api.delete(f"/api/asm/external/domains/{did}").status_code == 200
    with db.session_scope() as s:
        assert s.scalars(select(ExternalHost)).all() == []  # hosts go with the domain
