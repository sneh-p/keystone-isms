"""Batch B of the integrations and agents work: Microsoft 365 checks from the attack surface connector, Jamf Pro and
Kandji device lists with their fleet checks, and checks from attack surface sources filed as evidence."""

import shutil
import subprocess
from pathlib import Path

import pytest
from sqlalchemy import select

from keystone.asm.vocabulary import DeviceObs, Inventory
from keystone.controls.models import Evidence
from keystone.core.db import utcnow
from keystone.integrations import http
from keystone.integrations import service as integ
from keystone.integrations.models import CheckResult
from keystone.integrations.providers.asm_mdm import JamfProProvider, KandjiProvider, fleet_checks
from keystone.integrations.providers.asm_microsoft import MicrosoftProvider
from tests.test_asm_connectors import TID, TOKEN, mock

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def transport(monkeypatch):
    def use(routes, calls=None):
        monkeypatch.setattr(http, "TEST_TRANSPORT", mock(routes, calls))
    return use


def _tenant(transport, ca=True, scores=((62.0, 100), (70.0, 100)), audit=True):
    g, m = "graph.microsoft.com", "api.securitycenter.microsoft.com"
    routes = {
        ("POST", f"login.microsoftonline.com/{TID}/oauth2/v2.0/token"): TOKEN,
        ("GET", f"{g}/v1.0/reports/authenticationMethods/userRegistrationDetails"): {"value": [
            {"userPrincipalName": "ada@corp.example", "isMfaRegistered": True, "isAdmin": True, "methodsRegistered": ["microsoftAuthenticatorPush", "fido2"]},
            {"userPrincipalName": "bob@corp.example", "isMfaRegistered": True, "isAdmin": True, "methodsRegistered": ["microsoftAuthenticatorPush"]},
            {"userPrincipalName": "cy@corp.example", "isMfaRegistered": False, "isAdmin": False, "methodsRegistered": []},
            {"userPrincipalName": "guest_x#EXT#@corp.example", "isMfaRegistered": False, "isAdmin": False, "methodsRegistered": []}]},
        ("GET", f"{g}/v1.0/users"): {"value": [
            {"userPrincipalName": "ada@corp.example", "accountEnabled": True, "userType": "Member"},
            {"userPrincipalName": "bob@corp.example", "accountEnabled": True, "userType": "Member"},
            {"userPrincipalName": "cy@corp.example", "accountEnabled": True, "userType": "Member"},
            {"userPrincipalName": "guest_x#EXT#@corp.example", "accountEnabled": True, "userType": "Guest"}]},
        ("GET", f"{g}/v1.0/deviceManagement/managedDevices"): {"value": [
            {"id": "1", "deviceName": "ADA-LT", "operatingSystem": "Windows", "complianceState": "compliant", "isEncrypted": True, "lastSyncDateTime": "2026-11-20T10:00:00Z"},
            {"id": "2", "deviceName": "BOB-LT", "operatingSystem": "Windows", "complianceState": "noncompliant", "isEncrypted": False, "lastSyncDateTime": "2026-11-20T10:00:00Z"},
            {"id": "3", "deviceName": "BOB-PHONE", "operatingSystem": "iOS", "complianceState": "compliant", "lastSyncDateTime": "2026-11-20T10:00:00Z"}]},
        ("GET", f"{g}/v1.0/security/secureScoreControlProfiles"): {"value": [{"id": "mip_search_auditlog", "title": "Turn on audit log search", "maxScore": 1}]},
        ("GET", f"{g}/v1.0/security/secureScores"): {"value": [{"currentScore": c, "maxScore": mx, "createdDateTime": f"2026-11-{20 - i:02d}T00:00:00Z",
                                                                "controlScores": [{"controlName": "mip_search_auditlog", "score": 1 if audit else 0}]}
                                                               for i, (c, mx) in enumerate(scores)]},
        ("GET", f"{m}/api/machines"): {"value": []},
        ("GET", f"{m}/api/machines/SoftwareVulnerabilitiesByMachine"): {"value": []},
    }
    if ca:
        routes[("GET", f"{g}/v1.0/identity/conditionalAccess/policies")] = {"value": [
            {"id": "p1", "displayName": "Block legacy authentication", "state": "enabled",
             "conditions": {"clientAppTypes": ["exchangeActiveSync", "other"], "users": {"includeUsers": ["All"]}}, "grantControls": {"builtInControls": ["block"]}},
            {"id": "p2", "displayName": "Report-only test", "state": "enabledForReportingButNotEnforced", "conditions": {}, "grantControls": {}}]}
    transport(routes)
    p = MicrosoftProvider()
    return p, p.collect({"tenant_id": TID, "client_id": "cid"}, {"client_secret": "s"})


def test_microsoft_365_checks(transport):
    p, inv = _tenant(transport)
    r = {o.key: o for o in p.assess(inv)}
    assert r["mfa_all_users"].result == "fail" and r["mfa_all_users"].details["without_mfa"] == ["cy@corp.example"]  # guests aren't counted
    assert r["admins_phishing_resistant"].result == "fail" and r["admins_phishing_resistant"].details["without_phishing_resistant"] == ["bob@corp.example"]
    assert r["legacy_auth_blocked"].result == "pass" and "Block legacy authentication" in r["legacy_auth_blocked"].summary
    assert r["audit_log_search"].result == "pass"
    assert r["secure_score_trend"].result == "fail" and r["secure_score_trend"].summary.startswith("62.0% now, 70.0%")
    assert r["intune_compliant"].result == "fail" and r["intune_compliant"].details["not_compliant"] == ["BOB-LT"]
    assert r["fleet_encrypted"].result == "fail" and r["fleet_encrypted"].details["not_encrypted"] == ["BOB-LT"]  # the phone isn't a computer
    assert set(r) == {c.key for c in p.checks}


def test_microsoft_365_checks_are_unknown_without_the_data(transport):
    p, inv = _tenant(transport, ca=False, scores=((70.0, 100),), audit=True)
    r = {o.key: o.result for o in p.assess(inv)}
    assert r["legacy_auth_blocked"] == "unknown" and r["secure_score_trend"] == "unknown"
    assert any("Conditional Access skipped" in n for n in inv.notes)
    assert {o.key: o.result for o in p.assess(Inventory())}["mfa_all_users"] == "unknown"


def test_jamf_pro(transport):
    host = "acme.jamfcloud.com"
    calls: list = []
    transport({
        ("POST", f"{host}/api/oauth/token"): TOKEN,
        ("GET", f"{host}/api/v1/computers-inventory"): {"totalCount": 2, "results": [
            {"id": "1", "general": {"name": "ADA-MBP", "lastContactTime": "2026-11-20T09:00:00Z", "remoteManagement": {"managed": True}},
             "hardware": {"serialNumber": "C02ABC"}, "operatingSystem": {"version": "15.1"},
             "diskEncryption": {"bootPartitionEncryptionDetails": {"partitionFileVault2State": "ENCRYPTED"}}, "userAndLocation": {"email": "ada@corp.example"}},
            {"id": "2", "general": {"name": "OLD-MBP", "lastContactTime": "2026-08-01T09:00:00Z"}, "hardware": {"serialNumber": "C02XYZ"},
             "operatingSystem": {"version": "13.6"}, "diskEncryption": {"bootPartitionEncryptionDetails": {"partitionFileVault2State": "UNENCRYPTED"}}}]},
    }, calls)
    p = JamfProProvider()
    inv = p.collect({"server": f"https://{host}", "client_id": "cid"}, {"client_secret": "s"})
    a, b = inv.devices
    assert (a.name, a.serial, a.os_version, a.owner_email, a.props) == ("ADA-MBP", "C02ABC", "15.1", "ada@corp.example", {"disk_encrypted": True, "mdm_managed": True})
    assert b.props == {"disk_encrypted": False} and "devices" in inv.complete
    r = {o.key: o for o in p.assess(inv)}
    assert r["fleet_encrypted"].details["not_encrypted"] == ["OLD-MBP"] and r["fleet_checked_in"].details["stale"] == ["OLD-MBP"]
    assert all(c[0] == "GET" or c[1].endswith("/api/oauth/token") for c in calls)  # reads only
    with pytest.raises(http.ConnectorError):
        p.collect({"server": "http://acme.jamfcloud.com", "client_id": "cid"}, {"client_secret": "s"})


def test_kandji(transport):
    host = "acme.api.eu.kandji.io"
    transport({
        ("GET", f"{host}/api/v1/devices"): [
            {"device_id": "d1", "device_name": "ADA-MBA", "serial_number": "FVF1", "platform": "Mac", "os_version": "15.1", "last_check_in": "2026-11-20T08:00:00Z",
             "user": {"email": "ada@corp.example"}},
            {"device_id": "d2", "device_name": "ADA-IPHONE", "platform": "iPhone", "os_version": "18.1", "last_check_in": "2026-11-20T08:00:00Z"},
            {"device_id": "d3", "device_name": "GONE", "platform": "Mac", "is_removed": True}],
        ("GET", f"{host}/api/v1/devices/d1/details"): {"filevault": {"filevault_enabled": True}},
    })
    p = KandjiProvider()
    inv = p.collect({"subdomain": "acme", "region": "eu"}, {"token": "t"})
    assert [d.name for d in inv.devices] == ["ADA-MBA", "ADA-IPHONE"] and inv.devices[0].props == {"disk_encrypted": True}
    assert inv.devices[1].device_type == "mobile" and inv.devices[1].os == "iOS"
    assert {o.key: o.result for o in p.assess(inv)} == {"fleet_encrypted": "pass", "fleet_checked_in": "pass"}
    for bad in ("acme.evil.example", "a/b", "-acme"):
        with pytest.raises(http.ConnectorError, match="sub-domain"):
            p.collect({"subdomain": bad}, {"token": "t"})


def test_fleet_checks_never_pass_without_data():
    inv = Inventory(devices=[DeviceObs("x", "MAC-1", "mdm", device_type="workstation", last_seen=utcnow())], complete={"devices"})
    assert {o.key: o.result for o in fleet_checks(inv, "Tool")} == {"fleet_encrypted": "unknown", "fleet_checked_in": "pass"}
    assert {o.key: o.result for o in fleet_checks(Inventory(devices=inv.devices), "Tool")} == {"fleet_encrypted": "unknown", "fleet_checked_in": "unknown"}


def test_attack_surface_source_checks_file_evidence(content, session, users, monkeypatch, transport):
    p, _ = _tenant(transport)
    monkeypatch.setitem(integ.PROVIDERS, "microsoft365", p)
    i = integ.save_integration(session, users["admin"], provider_key="microsoft365", name="M365", values={"tenant_id": TID, "client_id": "cid", "client_secret": "s"})
    integ.run(session, users["admin"], i.id)
    results = {r.check_key: r.result for r in session.scalars(select(CheckResult).where(CheckResult.integration_id == i.id))}
    assert results["legacy_auth_blocked"] == "pass" and results["mfa_all_users"] == "fail" and results["inventory"] == "pass"
    ev = session.scalar(select(Evidence).where(Evidence.title == "Automated check: Legacy sign-in blocked by Conditional Access (M365)"))
    assert ev is not None and ev.attachment_id is not None


def test_linux_agent_reports_the_new_settings():
    sh = shutil.which("dash") or "/bin/sh"
    out = subprocess.run([sh, str(ROOT / "agents/linux/keystone-agent.sh"), "collect"], capture_output=True, text=True, timeout=120, check=True).stdout
    import json

    facts = json.loads(out)["facts"]
    assert isinstance(facts["edr_running"], bool) and isinstance(facts["edr_product"], str) and isinstance(facts["backup_agent_present"], bool)
    assert isinstance(facts["log_forwarding"], bool) and isinstance(facts["local_admin_count"], int)
