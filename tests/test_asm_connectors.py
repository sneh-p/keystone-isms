"""Attack surface connectors against recorded-style sample responses (httpx.MockTransport), plus the HTTP rules.

The samples use the field names the connectors map; they are not captured from live tenants. Live validation is done
with read-only keys through Test connection, which lists the fields a real API returns.
"""

import json
import socket
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from keystone.integrations import http
from keystone.integrations.providers.asm_edr import CrowdStrikeProvider, SentinelOneProvider, SophosProvider
from keystone.integrations.providers.asm_microsoft import MicrosoftProvider
from keystone.integrations.providers.asm_rmm import ConnectWiseAutomateProvider, DattoRmmProvider, NCentralProvider, NinjaOneProvider
from keystone.integrations.providers.asm_vuln import QualysProvider, Rapid7Provider, TenableProvider

TID = "11111111-2222-3333-4444-555555555555"


def mock(routes: dict, calls: list | None = None):
    """routes: {(METHOD, host+path): response | callable(request)}. Unknown routes return 404."""
    def handler(request: httpx.Request):
        key = (request.method, request.url.host + request.url.path)
        if calls is not None:
            calls.append((request.method, str(request.url)))
        r = routes.get(key)
        if r is None:
            return httpx.Response(404, json={"error": "not found"})
        r = r(request) if callable(r) else r
        if isinstance(r, httpx.Response):
            return r
        if isinstance(r, (bytes, str)):
            return httpx.Response(200, content=r if isinstance(r, bytes) else r.encode(), headers={"content-type": "application/xml"})
        return httpx.Response(200, json=r)
    return httpx.MockTransport(handler)


@pytest.fixture
def transport(monkeypatch):
    def use(routes, calls=None):
        monkeypatch.setattr(http, "TEST_TRANSPORT", mock(routes, calls))
    return use


TOKEN = {"access_token": "tok", "token_type": "Bearer", "expires_in": 3600}


# ---- Microsoft ------------------------------------------------------------------------------------------

def test_microsoft(transport):
    g, m = "graph.microsoft.com", "api.securitycenter.microsoft.com"
    transport({
        ("POST", f"login.microsoftonline.com/{TID}/oauth2/v2.0/token"): TOKEN,
        ("GET", f"{g}/v1.0/reports/authenticationMethods/userRegistrationDetails"): {"value": [{"userPrincipalName": "Ana@corp.example", "isMfaRegistered": False, "isAdmin": True}]},
        ("GET", f"{g}/v1.0/users"): {"value": [{"userPrincipalName": "Ana@corp.example", "displayName": "Ana", "accountEnabled": True, "userType": "Member",
                                                "signInActivity": {"lastSignInDateTime": "2026-11-10T08:00:00Z"}}]},
        ("GET", f"{g}/v1.0/deviceManagement/managedDevices"): {"value": [{"id": "md1", "deviceName": "ANA-LAPTOP", "serialNumber": "PF1234", "operatingSystem": "Windows",
                                                                          "osVersion": "10.0.22631", "complianceState": "noncompliant", "isEncrypted": False,
                                                                          "lastSyncDateTime": "2026-11-15T10:00:00Z", "userPrincipalName": "ana@corp.example", "azureADDeviceId": "AAD-1"}]},
        ("GET", f"{g}/v1.0/security/secureScoreControlProfiles"): {"value": [{"id": "MFARegistrationV2", "title": "Ensure all users can complete MFA", "maxScore": 9, "controlCategory": "Identity"}]},
        ("GET", f"{g}/v1.0/security/secureScores"): {"value": [{"controlScores": [{"controlName": "MFARegistrationV2", "score": 4.5, "controlCategory": "Identity"}]}]},
        ("GET", f"{m}/api/machines"): {"value": [{"id": "mde1", "computerDnsName": "ana-laptop.corp.example", "osPlatform": "Windows11", "healthStatus": "Active",
                                                   "onboardingStatus": "Onboarded", "aadDeviceId": "aad-1", "lastSeen": "2026-11-16T07:00:00Z"}]},
        ("GET", f"{m}/api/machines/SoftwareVulnerabilitiesByMachine"): {"value": [{"deviceId": "mde1", "cveId": "CVE-2026-1111", "softwareName": "chrome",
                                                                                     "vulnerabilitySeverityLevel": "Critical", "exploitabilityLevel": "ExploitIsVerified",
                                                                                     "firstSeenTimestamp": "2026-11-01T00:00:00Z"}]},
    })
    inv = MicrosoftProvider().collect({"tenant_id": TID, "client_id": "cid"}, {"client_secret": "s"})
    ident = inv.identities[0]
    assert ident.upn == "ana@corp.example" and ident.props["mfa_registered"] is False and ident.props["is_admin"] is True and "last_sign_in_days" in ident.props
    intune = next(d for d in inv.devices if d.category == "mdm")
    assert intune.props == {"mdm_compliant": False, "disk_encrypted": False} and intune.serial == "PF1234" and intune.owner_email == "ana@corp.example"
    mde = next(d for d in inv.devices if d.category == "edr")
    assert mde.props["edr_active"] is True and mde.aad_device_id == "aad-1"
    assert inv.vulns[0].severity == "critical" and inv.vulns[0].exploitable and inv.vulns[0].device_external_id == "mde:mde1"
    assert inv.settings[0].compliant is False and inv.settings[0].detail == "Score 4.5 of 9"
    assert {"devices", "vulns", "identities", "settings"} <= inv.complete


def test_microsoft_skips_unlicensed_parts_without_retiring(transport):
    transport({
        ("POST", f"login.microsoftonline.com/{TID}/oauth2/v2.0/token"): TOKEN,
        ("GET", "graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails"): {"value": []},
        ("GET", "graph.microsoft.com/v1.0/users"): {"value": []},
        ("GET", "graph.microsoft.com/v1.0/deviceManagement/managedDevices"): httpx.Response(403, json={"error": {"code": "Forbidden", "message": "secret-ish detail"}}),
        ("GET", "graph.microsoft.com/v1.0/security/secureScoreControlProfiles"): {"value": []},
        ("GET", "graph.microsoft.com/v1.0/security/secureScores"): {"value": []},
        ("GET", "api.securitycenter.microsoft.com/api/machines"): {"value": []},
        ("GET", "api.securitycenter.microsoft.com/api/machines/SoftwareVulnerabilitiesByMachine"): {"value": []},
    })
    inv = MicrosoftProvider().collect({"tenant_id": TID, "client_id": "cid"}, {"client_secret": "s"})
    assert any("Intune devices skipped" in n for n in inv.notes) and "devices" not in inv.complete
    assert not any("secret-ish" in n for n in inv.notes)  # response bodies never echoed
    with pytest.raises(http.ConnectorError, match="GUID"):
        MicrosoftProvider().collect({"tenant_id": "contoso.onmicrosoft.com", "client_id": "c"}, {"client_secret": "s"})


# ---- EDR ----------------------------------------------------------------------------------------------------

def test_crowdstrike(transport):
    h = "api.eu-1.crowdstrike.com"
    transport({
        ("POST", f"{h}/oauth2/token"): TOKEN,
        ("GET", f"{h}/devices/queries/devices/v1"): {"resources": ["d1", "d2"], "meta": {"pagination": {"total": 2}}},
        ("POST", f"{h}/devices/entities/devices/v2"): {"resources": [
            {"device_id": "d1", "hostname": "WS-01", "serial_number": "SN1", "platform_name": "Windows", "os_version": "Windows 11", "product_type_desc": "Workstation", "status": "normal", "last_seen": "2026-11-16T01:00:00Z"},
            {"device_id": "d2", "hostname": "SRV-01", "platform_name": "Linux", "product_type_desc": "Server", "status": "normal", "reduced_functionality_mode": "yes"}]},
    })
    inv = CrowdStrikeProvider().collect({"cloud": "eu-1", "client_id": "c"}, {"client_secret": "s"})
    by = {d.name: d for d in inv.devices}
    assert by["WS-01"].props["edr_active"] is True and by["SRV-01"].props["edr_active"] is False and by["SRV-01"].device_type == "server"
    with pytest.raises(http.ConnectorError):
        CrowdStrikeProvider().collect({"cloud": "evil", "client_id": "c"}, {"client_secret": "s"})


def test_sentinelone_paging_and_console_rule(transport):
    calls = []

    def agents(request):
        cursor = parse_qs(urlparse(str(request.url)).query).get("cursor")
        if not cursor:
            return {"data": [{"id": 1, "computerName": "MAC-01", "serialNumber": "C02X", "osName": "macOS", "machineType": "laptop", "isActive": True, "infected": False, "activeThreats": 0,
                              "firewallEnabled": True, "lastActiveDate": "2026-11-16T05:00:00Z"}], "pagination": {"nextCursor": "abc+="}}
        return {"data": [{"id": 2, "computerName": "SRV-02", "machineType": "server", "isActive": True, "infected": True, "activeThreats": 2}], "pagination": {"nextCursor": None}}

    transport({("GET", "acme.sentinelone.net/web/api/v2.1/agents"): agents}, calls)
    inv = SentinelOneProvider().collect({"console": "https://acme.sentinelone.net"}, {"token": "t"})
    by = {d.name: d for d in inv.devices}
    assert by["MAC-01"].props == {"edr_active": True, "threats_active": 0, "firewall_on": True}
    assert by["SRV-02"].props["edr_active"] is False and by["SRV-02"].props["threats_active"] == 2
    assert "cursor=abc%2B%3D" in calls[1][1]
    for bad in ("https://acme.sentinelone.net.evil.example", "https://evil.example/sentinelone.net", "http://acme.sentinelone.net", "https://acme.sentinelone.net:8443", "https://user:pw@acme.sentinelone.net"):
        with pytest.raises(http.ConnectorError):
            SentinelOneProvider().collect({"console": bad}, {"token": "t"})


def test_sophos_region_must_be_sophos(transport):
    def whoami(region):
        return {"id": "tenant-1", "idType": "tenant", "apiHosts": {"dataRegion": region}}

    routes = {("POST", "id.sophos.com/api/v2/oauth2/token"): TOKEN, ("GET", "api.central.sophos.com/whoami/v1"): whoami("https://api-eu02.central.sophos.com"),
              ("GET", "api-eu02.central.sophos.com/endpoint/v1/endpoints"): {"items": [{"id": "e1", "hostname": "LT-9", "type": "computer", "os": {"name": "Windows 11"},
                                                                                        "health": {"overall": "good", "threats": {"status": "good"}}, "tamperProtectionEnabled": True,
                                                                                        "encryption": {"volumes": [{"status": "encrypted"}]}, "lastSeenAt": "2026-11-16T00:00:00Z"}], "pages": {}}}
    transport(routes)
    d = SophosProvider().collect({"client_id": "c"}, {"client_secret": "s"}).devices[0]
    assert d.props == {"edr_active": True, "tamper_protection": True, "disk_encrypted": True, "threats_active": 0}
    routes[("GET", "api.central.sophos.com/whoami/v1")] = whoami("https://attacker.example")
    transport(routes)
    with pytest.raises(http.ConnectorError):
        SophosProvider().collect({"client_id": "c"}, {"client_secret": "s"})
    routes[("GET", "api.central.sophos.com/whoami/v1")] = {"id": "p", "idType": "partner", "apiHosts": {}}
    transport(routes)
    with pytest.raises(http.ConnectorError, match="tenant"):
        SophosProvider().collect({"client_id": "c"}, {"client_secret": "s"})


# ---- RMM --------------------------------------------------------------------------------------------------------

def test_ninjaone(transport):
    h = "eu.ninjarmm.com"
    transport({
        ("POST", f"{h}/ws/oauth/token"): TOKEN,
        ("GET", f"{h}/v2/devices-detailed"): lambda r: [{"id": 7, "systemName": "PC-7", "dnsName": "pc-7.corp", "nodeClass": "WINDOWS_WORKSTATION", "os": {"name": "Windows 11 Pro"},
                                                         "system": {"serialNumber": "SN7"}, "lastContact": 1763251200.5}] if "after=0" in str(r.url) else [],
        ("GET", f"{h}/v2/queries/os-patches"): {"results": [{"deviceId": 7, "severity": "CRITICAL"}, {"deviceId": 7, "severity": "OPTIONAL"}]},
        ("GET", f"{h}/v2/queries/antivirus-status"): {"results": [{"deviceId": 7, "definitionStatus": "OUT_OF_DATE"}]},
    })
    d = NinjaOneProvider().collect({"region": "eu", "client_id": "c"}, {"client_secret": "s"}).devices[0]
    assert d.serial == "SN7" and d.props == {"av_up_to_date": False, "patches_pending": 1} and d.last_seen is not None


def test_datto_next_page_must_stay_on_datto(transport):
    h = "merlot-api.centrastage.net"
    page2 = {"devices": [{"uid": "u2", "hostname": "PC-2", "operatingSystem": "Windows 10", "antivirus": {"antivirusStatus": "NotDetected"}}], "pageDetails": {"nextPageUrl": None}}

    def devices(request):
        if "page=1" in str(request.url):
            return page2
        return {"devices": [{"uid": "u1", "hostname": "PC-1", "operatingSystem": "Windows 11", "deviceType": {"category": "Laptop"}, "lastSeen": 1763251200000,
                             "antivirus": {"antivirusStatus": "RunningAndUpToDate"}, "patchManagement": {"patchesApprovedPending": 3}}],
                "pageDetails": {"nextPageUrl": f"https://{h}/api/v2/account/devices?max=250&page=1"}}

    routes = {("POST", f"{h}/auth/oauth/token"): TOKEN, ("GET", f"{h}/api/v2/account/devices"): devices}
    transport(routes)
    inv = DattoRmmProvider().collect({"platform": "merlot", "api_key": "k"}, {"api_secret": "s"})
    by = {d.name: d for d in inv.devices}
    assert by["PC-1"].props == {"av_up_to_date": True, "patches_pending": 3} and by["PC-2"].props == {}
    page2["pageDetails"]["nextPageUrl"] = "https://attacker.example/steal"
    routes[("GET", f"{h}/api/v2/account/devices")] = lambda r: {**devices(r), "pageDetails": {"nextPageUrl": "https://attacker.example/steal"}}
    transport(routes)
    with pytest.raises(http.ConnectorError, match="attacker.example"):
        DattoRmmProvider().collect({"platform": "merlot", "api_key": "k"}, {"api_secret": "s"})


def test_ncentral_and_automate(transport):
    transport({
        ("POST", "nc.msp.example/api/auth/authenticate"): {"tokens": {"access": {"token": "a"}, "refresh": {"token": "r"}}},
        ("GET", "nc.msp.example/api/devices"): {"data": [{"deviceId": 101, "longName": "FS-01", "deviceClass": "Server - Windows", "supportedOsLabel": "Windows Server 2019",
                                                          "lastApplianceCheckinTime": "2026-11-15T22:00:00Z"}, {"deviceId": 102, "longName": "probe", "isProbe": True}], "totalPages": 1},
        ("POST", "rmm.msp.example/cwa/api/v1/apitoken"): {"AccessToken": "a"},
        ("GET", "rmm.msp.example/cwa/api/v1/computers"): lambda r: [{"Id": 5, "ComputerName": "PC-5", "SerialNumber": "S5", "OperatingSystemName": "Microsoft Windows 11",
                                                                    "LastContact": "2026-11-16T00:00:00", "VirusDefinitionDate": "2026-10-01T00:00:00"}] if "page=1" in str(r.url) else [],
    })
    nc = NCentralProvider().collect({"server": "https://nc.msp.example"}, {"jwt": "j"})
    assert [d.name for d in nc.devices] == ["FS-01"] and nc.devices[0].device_type == "server"
    cw = ConnectWiseAutomateProvider().collect({"server": "rmm.msp.example", "client_id": "cid", "username": "u"}, {"password": "p"})
    assert cw.devices[0].props == {"av_up_to_date": False} and cw.devices[0].serial == "S5"


# ---- vulnerability management ----------------------------------------------------------------------------------------

def test_tenable_export(transport, monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    u = "0f8fad5b-d9cb-469f-a165-70867728950e"
    status = iter([{"status": "PROCESSING", "chunks_available": [1]}, {"status": "FINISHED", "chunks_available": [1]}])
    transport({
        ("POST", "cloud.tenable.com/vulns/export"): {"export_uuid": u},
        ("GET", f"cloud.tenable.com/vulns/export/{u}/status"): lambda r: next(status),
        ("GET", f"cloud.tenable.com/vulns/export/{u}/chunks/1"): [{"asset": {"uuid": "a1", "hostname": "web-01", "operating_system": ["Ubuntu 22.04"]}, "severity": "critical",
                                                                    "plugin": {"id": 1234, "name": "OpenSSL RCE", "cve": ["CVE-2026-0001"], "cvss3_base_score": 9.8, "exploit_available": True},
                                                                    "first_found": "2026-10-01T00:00:00Z", "state": "OPEN"}],
    })
    inv = TenableProvider().collect({"access_key": "a"}, {"secret_key": "s"})
    assert inv.devices[0].name == "web-01" and inv.vulns[0].severity == "critical" and inv.vulns[0].exploitable and "vulns" in inv.complete and "devices" not in inv.complete


QUALYS_XML = b"""<?xml version="1.0" encoding="UTF-8" ?>
<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST><HOST><ID>42</ID><IP>10.0.0.5</IP><DNS>db-01.corp</DNS><OS>Windows Server 2016</OS>
<DETECTION_LIST><DETECTION><QID>91234</QID><SEVERITY>5</SEVERITY><STATUS>Active</STATUS><FIRST_FOUND_DATETIME>2026-09-01T00:00:00Z</FIRST_FOUND_DATETIME></DETECTION>
<DETECTION><QID>38170</QID><SEVERITY>2</SEVERITY></DETECTION></DETECTION_LIST></HOST></HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>"""

XXE = b"""<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST><HOST><ID>&e;</ID></HOST></HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>"""


def test_qualys_xml_and_xxe(transport):
    transport({("GET", "qualysapi.qg2.apps.qualys.com/api/2.0/fo/asset/host/vm/detection/"): QUALYS_XML})
    inv = QualysProvider().collect({"api_server": "https://qualysapi.qg2.apps.qualys.com", "username": "u"}, {"password": "p"})
    assert inv.devices[0].name == "db-01.corp" and [(v.key, v.severity) for v in inv.vulns] == [("qid:91234", "critical")]
    transport({("GET", "qualysapi.qualys.com/api/2.0/fo/asset/host/vm/detection/"): XXE})
    with pytest.raises(http.ConnectorError, match="entity declarations") as e:  # defusedxml refuses them
        QualysProvider().collect({"api_server": "https://qualysapi.qualys.com", "username": "u"}, {"password": "p"})
    assert "passwd" not in str(e.value)
    with pytest.raises(http.ConnectorError):
        QualysProvider().collect({"api_server": "https://portal.qualys.com", "username": "u"}, {"password": "p"})


def test_rapid7(transport):
    transport({("POST", "eu.api.insight.rapid7.com/vm/v4/integration/assets"): {"data": [{"id": "r1", "host_name": "app-01", "os_description": "Red Hat Enterprise Linux 9",
                                                                                          "same": [{"vulnerability_id": "ssh-weak", "severity": "Severe", "first_found": "2026-10-10T00:00:00Z"}]}],
                                                                                "metadata": {}}})
    inv = Rapid7Provider().collect({"region": "eu"}, {"api_key": "k"})
    assert inv.devices[0].name == "app-01" and inv.vulns[0].severity == "high"


# ---- HTTP rules ----------------------------------------------------------------------------------------------------------

def test_self_hosted_servers_must_be_public_or_allowlisted(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.9", 443))])
    monkeypatch.delenv("KEYSTONE_INTEGRATION_PRIVATE_HOSTS", raising=False)
    with pytest.raises(http.ConnectorError, match="KEYSTONE_INTEGRATION_PRIVATE_HOSTS"):
        http._resolve("nc.corp.example")
    monkeypatch.setenv("KEYSTONE_INTEGRATION_PRIVATE_HOSTS", "nc.corp.example")
    assert http._resolve("nc.corp.example") == "10.0.0.9"
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))])
    with pytest.raises(http.ConnectorError):
        http._resolve("nc.corp.example")  # metadata service never, even when allowlisted


def test_redirects_errors_and_size(transport, monkeypatch):
    api = http.Api(http.HostPolicy(hosts=frozenset({"api.example.com"})))
    transport({("GET", "api.example.com/r"): httpx.Response(302, headers={"Location": "https://evil.example/"}),
               ("GET", "api.example.com/e"): httpx.Response(500, text="Internal error: password=hunter2"),
               ("GET", "api.example.com/a"): httpx.Response(401, text="bad token abc123")})
    with pytest.raises(http.ConnectorError, match="redirected"):
        api.request("GET", "https://api.example.com/r")
    with pytest.raises(http.ConnectorError) as e:
        api.request("GET", "https://api.example.com/e")
    assert "hunter2" not in str(e.value)
    with pytest.raises(http.ConnectorError, match="credentials"):
        api.request("GET", "https://api.example.com/a")
    with pytest.raises(http.ConnectorError):
        api.request("GET", "http://api.example.com/x")
    with pytest.raises(http.ConnectorError):
        api.request("GET", "https://other.example.com/x")
    monkeypatch.setattr(http, "MAX_BYTES", 10)
    transport({("GET", "api.example.com/big"): {"x": "y" * 100}})
    with pytest.raises(http.ConnectorError, match="too large"):
        api.request("GET", "https://api.example.com/big")


def test_credentials_are_bound_to_the_self_hosted_server(db, users):
    from keystone.integrations import service as integ

    admin = users["admin"]
    with db.session_scope(admin) as s:
        i = integ.save_integration(s, admin, provider_key="ncentral", name="N-central", values={"server": "https://nc.msp.example", "jwt": "secret-jwt"})
        with pytest.raises(ValueError, match="enter the credentials again"):
            integ.save_integration(s, admin, i.id, values={"server": "https://attacker.example"})
        integ.save_integration(s, admin, i.id, values={"server": "https://nc2.msp.example", "jwt": "new-jwt"})
        integ.save_integration(s, admin, i.id, name="Renamed")  # unchanged server keeps the stored token


def test_every_connector_has_setup_and_a_mapping_note():
    from keystone.integrations.providers.base import InventoryProvider
    from keystone.integrations.service import PROVIDERS

    inv = [p for p in PROVIDERS.values() if isinstance(p, InventoryProvider)]
    assert len(inv) == 17  # 11 attack surface sources + 3 cloud posture sources (round 3) + Jamf Pro, Kandji and Keystone's own agents (round 9)
    assert all(p.setup and p.mapping_note and (p.fields or p.needs_session) for p in inv)  # Keystone's agents need no settings
    assert json.dumps([p.describe() for p in inv])  # serialisable for the UI
