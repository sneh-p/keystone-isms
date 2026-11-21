"""Batch C of the integrations and agents work: cloud posture checks, Okta, Google Workspace, alerts pulled from
endpoint security tools, check-ins from backup and CI tools, firewall configurations read over the firewall's API, and
the extra trusted CA for connectors."""

import base64
import json
import ssl
from datetime import date
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from keystone.alerts.models import Alert, AlertSource
from keystone.asm.vocabulary import Inventory, SettingObs
from keystone.configcheck.models import ConfigTarget
from keystone.integrations import http
from keystone.integrations import service as integ
from keystone.integrations.providers.asm_cloud import AwsSecurityHubProvider, DefenderForCloudProvider, GoogleSccProvider
from keystone.integrations.providers.asm_edr import CrowdStrikeProvider
from keystone.integrations.providers.firewall_api import FortiGateApiProvider, PanOsApiProvider
from keystone.integrations.providers.google_workspace import GoogleWorkspaceProvider
from keystone.integrations.providers.okta import OktaProvider
from keystone.registers import service as reg
from keystone.registers.models import RegisterEntry
from tests.conftest import api_login
from tests.test_asm_connectors import TOKEN, mock

FIX = Path(__file__).parent / "fixtures" / "configcheck"


@pytest.fixture
def transport(monkeypatch):
    def use(routes, calls=None):
        monkeypatch.setattr(http, "TEST_TRANSPORT", mock(routes, calls))
    return use


# ---- cloud posture checks ---------------------------------------------------------------------------------------------

def _inv(settings, severities, complete=True, **facts):
    inv = Inventory(settings=settings, complete={"settings"} if complete else set())
    inv.facts.update(severity=severities, **facts)
    return inv


def test_posture_checks():
    bad = SettingObs("aws:S3.1", "S3.1 Block public access", compliant=False)
    ok = SettingObs("aws:IAM.1", "IAM.1 Policies", compliant=True)
    r = AwsSecurityHubProvider().assess(_inv([bad, ok], {"aws:S3.1": "critical", "aws:IAM.1": "high"}))
    assert r[0].result == "fail" and r[0].details["failing"] == ["S3.1 Block public access"]
    assert AwsSecurityHubProvider().assess(_inv([bad], {"aws:S3.1": "medium"}))[0].result == "pass"
    assert AwsSecurityHubProvider().assess(_inv([bad], {}, complete=False))[0].result == "unknown"
    plans = {"sub-1": {"VirtualMachines": "Standard", "StorageAccounts": "Free", "SqlServers": "Standard"}}
    r = {o.key: o for o in DefenderForCloudProvider().assess(_inv([], {}, plans=plans))}
    assert r["no_severe_findings"].result == "pass" and r["defender_plans"].result == "fail" and "StorageAccounts" in r["defender_plans"].summary
    assert {o.key: o.result for o in DefenderForCloudProvider().assess(_inv([], {}))}["defender_plans"] == "unknown"
    scc = [SettingObs("scc:PUBLIC_BUCKET_ACL", "Public bucket acl", compliant=False, detail="2 resource(s) affected"),
           SettingObs("scc:OPEN_SSH_PORT", "Open ssh port", compliant=False, detail="1 resource(s) affected")]
    r = {o.key: o.result for o in GoogleSccProvider().assess(_inv(scc, {"scc:PUBLIC_BUCKET_ACL": "high", "scc:OPEN_SSH_PORT": "high"}))}
    assert r == {"no_severe_findings": "fail", "no_public_data": "fail", "no_open_admin_ports": "fail", "mfa_enforced": "pass"}


# ---- Okta -------------------------------------------------------------------------------------------------------------

def test_okta(transport):
    h = "acme.okta.com"
    long_ago, recent = "2026-01-01T00:00:00.000Z", "2026-11-20T00:00:00.000Z"
    calls: list = []
    page2 = f"https://{h}/api/v1/users?after=u2&limit=200"

    def users(req: httpx.Request):
        if "after=u2" in str(req.url):
            return httpx.Response(200, json=[{"id": "u3", "profile": {"login": "cy@corp.example"}, "lastLogin": long_ago}])
        return httpx.Response(200, json=[{"id": "u1", "profile": {"login": "ada@corp.example"}, "lastLogin": recent},
                                         {"id": "u2", "profile": {"login": "bob@corp.example"}, "lastLogin": recent}], headers={"link": f'<{page2}>; rel="next"'})
    transport({
        ("GET", f"{h}/api/v1/users"): users,
        ("GET", f"{h}/api/v1/users/u1/factors"): [{"factorType": "webauthn", "status": "ACTIVE"}],
        ("GET", f"{h}/api/v1/users/u2/factors"): [{"factorType": "sms", "status": "PENDING_ACTIVATION"}],
        ("GET", f"{h}/api/v1/users/u3/factors"): [{"factorType": "push", "status": "ACTIVE"}],
        ("GET", f"{h}/api/v1/iam/assignees/users"): [{"id": "u1", "profile": {"login": "ada@corp.example"}}],
        ("GET", f"{h}/api/v1/users/u1/roles"): [{"type": "SUPER_ADMIN"}],
        ("GET", f"{h}/api/v1/policies"): [{"name": "Default", "status": "ACTIVE", "settings": {"password": {"complexity": {"minLength": 8}}}},
                                           {"name": "Old", "status": "INACTIVE", "settings": {"password": {"complexity": {"minLength": 4}}}}],
    }, calls)
    r = {o.key: o for o in OktaProvider().run({"domain": f"https://{h}"}, {"token": "t"})}
    assert r["inactive_users"].result == "fail" and r["inactive_users"].details["inactive"] == ["cy@corp.example"]
    assert r["mfa_enrolled"].result == "fail" and r["mfa_enrolled"].details["without_mfa"] == ["bob@corp.example"]
    assert r["few_super_admins"].result == "pass" and r["password_length"].result == "fail" and "Default (8)" in r["password_length"].summary
    assert all(c[0] == "GET" for c in calls)
    with pytest.raises(http.ConnectorError):
        OktaProvider().run({"domain": "https://evil.example"}, {"token": "t"})


# ---- Google Workspace ----------------------------------------------------------------------------------------------------

def _service_account():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return json.dumps({"type": "service_account", "client_email": "keystone@proj.iam.gserviceaccount.com", "private_key": pem, "token_uri": "https://evil.example/token"})


def test_google_workspace(transport):
    seen = {}

    def token(req: httpx.Request):
        body = dict(x.split("=", 1) for x in req.content.decode().split("&"))
        claims = json.loads(base64.urlsafe_b64decode(body["assertion"].split(".")[1] + "=="))
        seen.update(claims)
        return httpx.Response(200, json=TOKEN)
    transport({
        ("POST", "oauth2.googleapis.com/token"): token,
        ("GET", "admin.googleapis.com/admin/directory/v1/users"): {"users": [
            {"primaryEmail": "ada@corp.example", "isEnrolledIn2Sv": True, "isEnforcedIn2Sv": True, "isAdmin": True, "lastLoginTime": "2026-11-19T10:00:00.000Z"},
            {"primaryEmail": "bob@corp.example", "isEnrolledIn2Sv": False, "isEnforcedIn2Sv": False, "isAdmin": False, "lastLoginTime": "1970-01-01T00:00:00.000Z",
             "creationTime": "2025-01-01T00:00:00.000Z"},
            {"primaryEmail": "old@corp.example", "isEnrolledIn2Sv": False, "suspended": True}]},
        ("GET", "cloudidentity.googleapis.com/v1/policies"): {"policies": [{"setting": {"type": "settings/drive_and_docs.external_sharing", "value": {"externalSharingMode": "ALLOWED"}}}]},
    })
    r = {o.key: o for o in GoogleWorkspaceProvider().run({"admin_email": "admin@corp.example"}, {"service_account_json": _service_account()})}
    assert seen["sub"] == "admin@corp.example" and seen["aud"] == "https://oauth2.googleapis.com/token" and "readonly" in seen["scope"]  # the file's token_uri is ignored
    assert r["two_step_enrolled"].details["not_enrolled"] == ["bob@corp.example"] and r["two_step_enforced"].result == "fail"
    assert r["few_super_admins"].result == "pass" and r["inactive_users"].details["inactive"] == ["bob@corp.example"]  # never signed in, created long ago
    assert r["external_sharing"].result == "fail"
    with pytest.raises(http.ConnectorError, match="administrator"):
        GoogleWorkspaceProvider().run({"admin_email": "not an email"}, {"service_account_json": _service_account()})


# ---- alerts pulled from endpoint security tools ---------------------------------------------------------------------------

def _falcon(transport, alerts):
    h = "api.crowdstrike.com"
    transport({
        ("POST", f"{h}/oauth2/token"): TOKEN,
        ("GET", f"{h}/devices/queries/devices/v1"): {"resources": ["d1"], "meta": {"pagination": {"total": 1}}},
        ("POST", f"{h}/devices/entities/devices/v2"): {"resources": [{"device_id": "d1", "hostname": "ASH-LT-1", "status": "normal", "platform_name": "Windows"}]},
        ("GET", f"{h}/alerts/queries/alerts/v2"): {"resources": [a["composite_id"] for a in alerts]},
        ("POST", f"{h}/alerts/entities/alerts/v2"): {"resources": alerts},
    })


ALERTS = [{"composite_id": "c1", "display_name": "Credential theft attempt", "severity_name": "Critical", "device": {"hostname": "ASH-LT-1"}, "user_name": "ada",
           "created_timestamp": "2026-11-21T08:00:00Z", "falcon_host_link": "https://falcon.crowdstrike.com/activity-v2/detections/c1"},
          {"composite_id": "c2", "display_name": "Suspicious script", "severity": 45, "device": {"hostname": "ASH-LT-1"}, "created_timestamp": "2026-11-21T09:00:00Z"}]


def test_alerts_are_pulled_once_and_only_when_turned_on(content, session, users, transport):
    _falcon(transport, ALERTS)
    i = integ.save_integration(session, users["admin"], provider_key="crowdstrike", name="Falcon", values={"cloud": "us-1", "client_id": "c", "client_secret": "s"})
    integ.run(session, users["admin"], i.id)
    assert session.scalar(select(Alert)) is None  # off by default
    integ.save_integration(session, users["admin"], i.id, values={"pull_alerts": "on"})
    integ.run(session, users["admin"], i.id)
    rows = list(session.scalars(select(Alert).order_by(Alert.id)))
    assert [(a.title, a.severity, a.host) for a in rows] == [("Credential theft attempt", "critical", "ASH-LT-1"), ("Suspicious script", "medium", "ASH-LT-1")]
    integ.run(session, users["admin"], i.id)  # the same alerts again: not counted twice
    assert [a.count for a in session.scalars(select(Alert).order_by(Alert.id))] == [1, 1]
    src = session.scalar(select(AlertSource).where(AlertSource.integration_id == i.id))
    assert src is not None and src.name == "Falcon (pulled)"
    from keystone.alerts import service as al

    with pytest.raises(ValueError, match="pulled"):
        al.rotate_token(session, users["admin"], src.id)


def test_alert_pull_failure_doesnt_fail_the_inventory(content, session, users, monkeypatch, transport):
    _falcon(transport, ALERTS)
    p = CrowdStrikeProvider()

    def broken(*a, **kw):
        raise http.ConnectorError("api.crowdstrike.com refused access to /alerts (403)")
    monkeypatch.setattr(p, "fetch_alerts", broken)
    monkeypatch.setitem(integ.PROVIDERS, "crowdstrike", p)
    i = integ.save_integration(session, users["admin"], provider_key="crowdstrike", name="Falcon", values={"cloud": "us-1", "client_id": "c", "client_secret": "s", "pull_alerts": "on"})
    res = integ.run(session, users["admin"], i.id)
    assert i.last_status == "ok" and "Alerts not read" in next(r.summary for r in res if r.check_key == "inventory")


# ---- check-ins from backup and CI tools -------------------------------------------------------------------------------------

def _source(api, name, kind):
    r = api.post("/api/alert-sources", json={"name": name, "kind": kind})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def test_backup_and_ci_checkins(api, ready_users, db):
    with db.session_scope() as s:
        admin = s.get(type(ready_users["admin"]), ready_users["admin"].id)
        job = reg.save(s, admin, "backups", title="Booking database", owner_id=admin.id, tool="Veeam", frequency="daily", restore_test_every_months=6)
        app = reg.save(s, admin, "applications", title="Booking platform", owner_id=admin.id, criticality="high", data="restricted")
        rel = reg.save(s, admin, "release-signoffs", title="Booking 4.3", application=app.id, version="4.3", changes="New login page")
        job_ref, rel_id = job.ref, rel.id
    api_login(api, "admin")
    backup_token, ci_token, edr_token = _source(api, "Veeam", "backup"), _source(api, "GitHub Actions", "ci"), _source(api, "EDR", "edr")
    api.cookies.clear()
    api.headers.pop("X-CSRF-Token", None)

    def post(token, body):
        return api.post("/api/inbound/checkin", json=body, headers={"Authorization": f"Bearer {token}"} if token else {})
    assert post(None, {"kind": "backup", "job": job_ref, "status": "success"}).status_code == 401
    assert post(edr_token, {"kind": "backup", "job": job_ref, "status": "success"}).status_code == 403
    assert post(backup_token, {"kind": "backup", "job": "No such job", "status": "success"}).status_code == 404
    assert post(backup_token, {"kind": "backup", "job": job_ref, "status": "maybe"}).status_code == 422
    r = post(backup_token, {"kind": "backup", "job": "booking database", "status": "failure", "note": "Repository full"})
    assert r.status_code == 200 and r.json() == {"entry": job_ref, "status": "failing"}
    r = post(backup_token, {"kind": "backup", "job": job_ref, "status": "success"})
    assert r.json()["status"] == "ok"
    assert post(backup_token, {"kind": "release_scan", "application": "Booking platform", "version": "4.3", "result": "pass"}).status_code == 403
    r = post(ci_token, {"kind": "release_scan", "application": "Booking platform", "version": "4.3", "tool": "semgrep", "result": "pass", "summary": "0 findings"})
    assert r.status_code == 200 and r.json()["status"] == "requested"  # never signed off by a tool
    assert post(ci_token, {"kind": "release_scan", "application": "Booking platform", "version": "9.9", "result": "pass"}).status_code == 404
    with db.session_scope() as s:
        e = s.scalar(select(RegisterEntry).where(RegisterEntry.register == "backups"))
        assert e.data["last_success_on"] == date.today().isoformat() and [d["by"] for d in e.decisions] == ["Veeam (check-in)", "Veeam (check-in)"]
        assert e.decisions[0]["note"] == "Repository full"
        assert "semgrep: PASS - 0 findings" in s.get(RegisterEntry, rel_id).data["tests"]


def test_only_backup_success_and_failure_are_system_steps(content, session, users):
    e = reg.save(session, users["admin"], "backups", title="Files", owner_id=users["admin"].id, tool="Veeam", frequency="daily", restore_test_every_months=6)
    with pytest.raises(ValueError, match="can't be recorded"):
        reg.system_move(session, e, "restore_test", "tool")
    with pytest.raises(ValueError, match="can't be recorded"):
        reg.system_move(session, e, "retired", "tool")


# ---- firewall configurations read over the API ---------------------------------------------------------------------------------

def test_panos_configuration_by_api(content, session, users, transport, monkeypatch):
    cfg_xml = (FIX / "panos.xml").read_bytes()
    calls: list = []
    transport({("GET", "pa1.example.org/api/"): lambda req: httpx.Response(200, content=b'<response status="success"><result>' + cfg_xml.split(b"?>", 1)[-1] + b"</result></response>",
                                                                            headers={"content-type": "application/xml"})}, calls)
    i = integ.save_integration(session, users["admin"], provider_key="panos_api", name="PA1", values={"server": "https://pa1.example.org", "token": "LUFRPT1"})
    dry = integ.test(session, users["admin"], integration_id=i.id)
    assert dry[0]["result"] == "pass" and "Nothing was stored" in dry[0]["summary"]
    assert session.scalar(select(ConfigTarget)) is None
    integ.run(session, users["admin"], i.id)
    integ.run(session, users["admin"], i.id)
    targets = list(session.scalars(select(ConfigTarget)))
    assert len(targets) == 1 and targets[0].source_filename == "API: pa1.example.org" and targets[0].platform == "panos" and targets[0].facts
    assert all("LUFRPT1" not in url for _, url in calls)  # the key goes in a header


def test_fortigate_falls_back_to_post_on_newer_firmware(transport):
    conf = (FIX / "fortigate-weak.conf").read_bytes()
    calls: list = []
    transport({("GET", "fw1.example.org/api/v2/monitor/system/config/backup"): httpx.Response(405),
               ("POST", "fw1.example.org/api/v2/monitor/system/config/backup"): lambda req: httpx.Response(200, content=conf)}, calls)
    out = FortiGateApiProvider().run({"server": "https://fw1.example.org"}, {"token": "t"}, None)
    assert out[0].result == "pass" and [c[0] for c in calls] == ["GET", "POST"]


def test_panos_refusal_is_an_error(transport):
    transport({("GET", "pa1.example.org/api/"): lambda req: httpx.Response(200, content=b'<response status="error"><msg>Invalid credentials.</msg></response>')})
    with pytest.raises(http.ConnectorError, match="refused"):
        PanOsApiProvider().run({"server": "https://pa1.example.org"}, {"token": "bad"}, None)


# ---- extra trusted CA -----------------------------------------------------------------------------------------------------------

def test_extra_ca_file(monkeypatch, tmp_path):
    monkeypatch.delenv("KEYSTONE_EXTRA_CA_FILE", raising=False)
    assert http.tls_verify() is True
    import certifi

    monkeypatch.setenv("KEYSTONE_EXTRA_CA_FILE", certifi.where())
    ctx = http.tls_verify()
    assert isinstance(ctx, ssl.SSLContext) and ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    (tmp_path / "bad.pem").write_text("not a certificate")
    monkeypatch.setenv("KEYSTONE_EXTRA_CA_FILE", str(tmp_path / "bad.pem"))
    with pytest.raises(http.ConnectorError, match="PEM"):
        http.tls_verify()


def test_new_inbound_route_requires_a_token(api, ready_users):
    assert api.post("/api/inbound/checkin", json={"kind": "backup", "job": "x", "status": "success"}).status_code == 401
    assert api.post("/api/inbound/checkin", json={"kind": "backup"}, headers={"Authorization": "Bearer kalt_nope"}).status_code == 401
