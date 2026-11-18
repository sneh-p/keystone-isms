"""Batch 2 of the security expansion: the security alert inbox (inbound with per-source tokens), pentests and their
findings, application security, certificates and keys, backup jobs, indicators and maturity assessments."""

from datetime import date, timedelta

from keystone.core.services import today

from .conftest import api_login


def _create(api, key, title, **fields):
    r = api.post(f"/api/registers/{key}", json={"title": title, "fields": fields})
    assert r.status_code == 200, r.text
    return r.json()


# ---- alert inbox ----------------------------------------------------------------------------------------------------

def test_alert_inbox(api, ready_users, db):
    from keystone.assets import service as assets

    with db.session_scope() as s:
        laptop = assets.save_asset(s, ready_users["admin"], name="LAPTOP-7", asset_type="hardware", owner_id=ready_users["control_owner"].id).id
    api_login(api, "controlowner")
    assert api.post("/api/alert-sources", json={"name": "EDR", "kind": "edr"}).status_code == 403  # integration.manage
    api_login(api, "admin")
    src = api.post("/api/alert-sources", json={"name": "Contoso EDR", "kind": "edr"}).json()
    token = src["token"]
    assert token.startswith("kalt_") and "token" not in api.get("/api/alert-sources").json()["sources"][0]
    api.post("/api/auth/logout")
    inbound = api.__class__(api.app)  # no session cookie, no CSRF token: tools authenticate with their source token only
    alert = {"title": "Credential theft tool detected", "severity": "high", "category": "malware", "host": "laptop-7", "external_id": "edr-123",
             "link": "https://edr.example/alerts/123"}
    assert inbound.post("/api/inbound/alerts", json=alert).status_code == 401
    assert inbound.post("/api/inbound/alerts", json=alert, headers={"Authorization": "Bearer kalt_wrong"}).status_code == 401
    h = {"Authorization": f"Bearer {token}"}
    r = inbound.post("/api/inbound/alerts", json=alert, headers=h)
    assert r.status_code == 200 and r.json()["new"] is True
    again = inbound.post("/api/inbound/alerts", json={**alert, "severity": "critical"}, headers=h).json()
    assert again["new"] is False and again["count"] == 2  # a repeat is counted, not stored again
    for bad in ({**alert, "severity": "urgent"}, {**alert, "link": "http://edr.example/1"}, {**alert, "link": "javascript:alert(1)"}, {**alert, "extra": 1}, {"severity": "low"}):
        assert inbound.post("/api/inbound/alerts", json=bad, headers=h).status_code == 422, bad
    assert inbound.post("/api/inbound/alerts", content=b"{" + b" " * 70000 + b"}", headers={**h, "content-type": "application/json"}).status_code == 413
    no_id = {"title": "Impossible travel", "severity": "medium", "category": "account_compromise", "account": "raj@example.example"}
    assert inbound.post("/api/inbound/alerts", json=no_id, headers=h).json()["new"] is True
    assert inbound.post("/api/inbound/alerts", json=no_id, headers=h).json()["count"] == 2  # same title, host and account within a day

    api_login(api, "viewer")
    assert api.get("/api/alerts").status_code == 403
    api_login(api, "controlowner")
    rows = {a["title"]: a for a in api.get("/api/alerts").json()["alerts"]}
    theft = rows["Credential theft tool detected"]
    assert theft["severity"] == "critical" and theft["asset_id"] == laptop and theft["owner"] == "Control Owner" and theft["source"] == "Contoso EDR"
    out = api.post(f"/api/alerts/{theft['id']}/incident", json={}).json()
    inc = api.get(f"/api/incidents/{out['incident_id']}").json()
    assert inc["severity"] == "critical" and inc["category"] == "malware" and "https://edr.example/alerts/123" in inc["description"]
    assert api.post(f"/api/alerts/{theft['id']}/close", json={"reason": "benign", "note": "x"}).status_code == 400  # handled already
    travel = rows["Impossible travel"]
    assert api.post(f"/api/alerts/{travel['id']}/close", json={"reason": "benign"}).status_code == 422
    assert api.post(f"/api/alerts/{travel['id']}/close", json={"reason": "benign", "note": "VPN exit node"}).json()["status"] == "closed"

    api_login(api, "admin")
    api.put(f"/api/alert-sources/{src['id']}/enabled", json={"enabled": False})
    assert inbound.post("/api/inbound/alerts", json=alert, headers=h).status_code == 401  # a disabled source is refused
    api.put(f"/api/alert-sources/{src['id']}/enabled", json={"enabled": True})
    new_token = api.post(f"/api/alert-sources/{src['id']}/token").json()["token"]
    assert inbound.post("/api/inbound/alerts", json=alert, headers=h).status_code == 401  # the old token stops working
    assert inbound.post("/api/inbound/alerts", json=alert, headers={"Authorization": f"Bearer {new_token}"}).status_code == 200


# ---- pentests and findings -------------------------------------------------------------------------------------------

def test_pentest_findings_and_independent_retest(api, ready_users):
    api_login(api, "riskowner")
    pen = _create(api, "pentests", "External pentest 2026", kind="pentest", provider="Fabrikam Security", scope="Booking platform")
    f = _create(api, "findings", "SQL injection in search", test=pen["id"], severity="critical", description="The search box is injectable.")
    assert f["due_on"] == str(today() + timedelta(days=15))  # fix-by from severity
    mv = lambda to, note=None: api.post(f"/api/registers/findings/{f['id']}/move", json={"to": to, "note": note})
    assert mv("fixed", "Parameterised queries").status_code == 200
    api_login(api, "admin")  # retest by someone else
    api.post("/api/auth/logout")
    api_login(api, "riskowner")
    assert mv("verified").status_code == 403  # retests need audit.findings
    api_login(api, "auditor")
    r = mv("verified")
    assert r.status_code == 200 and r.json()["status"] == "verified"
    f2 = None
    api_login(api, "admin")
    f2 = _create(api, "findings", "Verbose errors", test=pen["id"], severity="low", description="Stack traces shown.")
    api.post(f"/api/registers/findings/{f2['id']}/move", json={"to": "fixed", "note": "Errors hidden"})
    r = api.post(f"/api/registers/findings/{f2['id']}/move", json={"to": "verified"})
    assert r.status_code == 400 and "Segregation of duties" in r.json()["detail"]  # the fixer can't verify
    api_login(api, "auditor")
    assert api.post(f"/api/registers/findings/{f2['id']}/move", json={"to": "reopen"}).status_code == 400  # a failed retest needs a note
    assert api.post(f"/api/registers/findings/{f2['id']}/move", json={"to": "reopen", "note": "Still shown on /api"}).json()["status"] == "open"


def test_application_security_registers(api, ready_users):
    api_login(api, "controlowner")
    app = _create(api, "applications", "Booking platform", criticality="critical", data="restricted", personal_data=True)
    tm = _create(api, "threat-models", "Booking platform STRIDE", application=app["id"], method="stride", scope="Web app and API", threats="Account takeover")
    rel = _create(api, "release-signoffs", "Booking 4.2", application=app["id"], version="4.2", changes="New payment page")
    assert api.post(f"/api/registers/threat-models/{tm['id']}/move", json={"to": "approved"}).status_code == 403  # needs task.approve
    api_login(api, "ismsmanager")
    r = api.post(f"/api/registers/threat-models/{tm['id']}/move", json={"to": "approved"})
    assert r.status_code == 400 and "Mitigations" in r.json()["detail"]
    api.patch(f"/api/registers/threat-models/{tm['id']}", json={"fields": {"mitigations": "MFA, rate limits"}})
    assert api.post(f"/api/registers/threat-models/{tm['id']}/move", json={"to": "approved"}).status_code == 200
    r = api.post(f"/api/registers/release-signoffs/{rel['id']}/move", json={"to": "approved"})
    assert r.status_code == 400 and "Security testing done" in r.json()["detail"]
    api.patch(f"/api/registers/release-signoffs/{rel['id']}", json={"fields": {"tests": "SAST, dependency scan, DAST"}})
    assert api.post(f"/api/registers/release-signoffs/{rel['id']}/move", json={"to": "approved"}).json()["status"] == "approved"


def test_certificates_keys_and_backups(api, ready_users, db):
    from keystone.asm.models import ExternalDomain, ExternalHost
    from keystone.registers.service import sync_public_certificates

    api_login(api, "riskowner")
    key = _create(api, "crypto", "Backup encryption key", kind="encryption_key", location="Backup vault", rotate_every_months=12,
                  last_rotated_on=str(date(2026, 1, 15)))
    assert key["due_on"] == "2027-01-15"
    cert = _create(api, "crypto", "Booking site certificate", kind="tls_certificate", location="booking.example", expires_on=str(today() + timedelta(days=20)),
                   rotate_every_months=12, last_rotated_on=str(today() - timedelta(days=345)))
    rotated = api.post(f"/api/registers/crypto/{cert['id']}/move", json={"to": "rotated"}).json()
    assert rotated["data"]["expires_on"] == str(today() + timedelta(days=20))  # a rotation doesn't erase the expiry
    with db.session_scope() as s:
        d = ExternalDomain(name="example.example", verification_token="x")
        s.add(d)
        s.flush()
        s.add(ExternalHost(domain_id=d.id, host="www.example.example", facts={"cert_expires": str(today() + timedelta(days=10))}))
        s.flush()
        assert sync_public_certificates(s) == 1 and sync_public_certificates(s) == 0
    auto = next(e for e in api.get("/api/registers/crypto").json()["entries"] if e["data"].get("location") == "www.example.example")
    assert auto["due_on"] == str(today() + timedelta(days=10)) and auto["data"]["source"] == "Internet-facing check"

    job = _create(api, "backups", "Booking database nightly", tool="Veeam", frequency="daily", restore_test_every_months=6,
                  last_restore_test_on=str(today() - timedelta(days=200)))
    assert job["due_on"] < str(today())  # restore test overdue
    failing = api.post(f"/api/registers/backups/{job['id']}/move", json={"to": "failure", "note": "Repository full"}).json()
    assert failing["status"] == "failing"
    assert api.post(f"/api/registers/backups/{job['id']}/move", json={"to": "restore_test", "note": "x"}).status_code == 400  # not while failing
    ok = api.post(f"/api/registers/backups/{job['id']}/move", json={"to": "success"}).json()
    assert ok["status"] == "ok" and ok["data"]["last_success_on"] == str(today())
    tested = api.post(f"/api/registers/backups/{job['id']}/move", json={"to": "restore_test", "note": "Restored to staging in 40 minutes"}).json()
    assert tested["data"]["last_restore_test_on"] == str(today()) and tested["due_on"] > str(today())


# ---- indicators and maturity -----------------------------------------------------------------------------------------

def test_indicators(api, ready_users, db):
    from keystone.indicators import service as kri
    from keystone.notifications.models import Notification

    api_login(api, "viewer")
    assert api.post("/api/indicators/recommended").status_code == 403
    api_login(api, "ismsmanager")
    r = api.post("/api/indicators/recommended")
    assert r.status_code == 200, r.text
    assert r.json()["added"] == len(kri.RECOMMENDED)
    data = api.get("/api/indicators").json()
    mfa = next(i for i in data["indicators"] if i["metric_key"] == "mfa_coverage_pct")
    assert mfa["last_state"] == "green" and mfa["last_measured_on"] == str(today())
    bad = {"name": "x", "metric_key": "nope", "amber": 1, "red": 2}
    assert api.post("/api/indicators", json=bad).status_code == 400
    assert api.post("/api/indicators", json={"name": "x", "amber": 5, "red": 2}).status_code == 400  # red better than amber
    manual = api.post("/api/indicators", json={"name": "Phishing simulation click rate", "unit": "%", "amber": 5, "red": 10, "owner_id": ready_users["control_owner"].id}).json()
    r = api.post(f"/api/indicators/{manual['id']}/values", json={"value": 12, "note": "October campaign"}).json()
    assert r["last_state"] == "red"
    with db.session_scope() as s:
        n = s.query(Notification).filter(Notification.user_id == ready_users["control_owner"].id, Notification.title.like("Indicator red%")).count()
        assert n == 1
    assert api.post(f"/api/indicators/{mfa['id']}/values", json={"value": 50}).status_code == 400  # measured by Keystone
    assert api.post(f"/api/indicators/{manual['id']}/values", json={"value": 1, "measured_on": str(today() + timedelta(days=1))}).status_code == 400


def test_maturity(api, ready_users):
    api_login(api, "viewer")
    data = api.get("/api/maturity").json()
    refs = [c["ref"] for f in data["categories"] for c in f["categories"]]
    assert len(data["categories"]) == 6 and "GV.OC" in refs and len(refs) >= 20
    assert api.post("/api/maturity", json={"title": "2026"}).status_code == 403
    api_login(api, "ismsmanager")
    a = api.post("/api/maturity", json={"title": "2026 self-assessment", "scores": {"GV.OC": {"current": 2, "target": 3}}}).json()
    for bad in ({"GV.OC": {"current": 5}}, {"XX.YY": {"current": 1}}, {"GV.OC": {"current": 1, "colour": "red"}}):
        assert api.patch(f"/api/maturity/{a['id']}", json={"scores": bad}).status_code == 400, bad
    r = api.post(f"/api/maturity/{a['id']}/final")
    assert r.status_code == 400 and "Score every category" in r.json()["detail"]
    api.patch(f"/api/maturity/{a['id']}", json={"scores": {ref: {"current": 2, "target": 3} for ref in refs}})
    assert api.post(f"/api/maturity/{a['id']}/final").json()["status"] == "final"
    assert api.patch(f"/api/maturity/{a['id']}", json={"title": "x"}).status_code == 400
    nxt = api.post(f"/api/maturity/{a['id']}/copy", json={"title": "2027 self-assessment"}).json()
    assert nxt["status"] == "draft" and nxt["scores"]["GV.OC"]["current"] == 2
    fn = next(x for x in api.get("/api/maturity").json()["assessments"] if x["id"] == a["id"])["functions"]
    assert all(f["current"] == 2 and f["target"] == 3 for f in fn)
