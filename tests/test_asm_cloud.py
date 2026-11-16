"""Cloud posture connectors: AWS Security Hub, Defender for Cloud, Google SCC (mocked APIs)."""

from __future__ import annotations

import json
from urllib.parse import parse_qs

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from keystone.integrations import http
from keystone.integrations.http import ConnectorError
from keystone.integrations.providers.asm_cloud import AwsSecurityHubProvider, DefenderForCloudProvider, GoogleSccProvider

SUB = "11111111-2222-3333-4444-555555555555"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _finding(cid, status, res, std="standards/aws-foundational-security-best-practices/v/1.0.0"):
    return {"Id": f"f-{cid}-{res}", "Title": f"Control {cid}", "Compliance": {"SecurityControlId": cid, "Status": status, "AssociatedStandards": [{"StandardsId": std}]},
            "Resources": [{"Id": res}]}


class FakeSecurityHub:
    def __init__(self, pages):
        self.pages, self.calls = pages, []

    def get_findings(self, **kw):
        self.calls.append(kw)
        i = int(kw.get("NextToken", "0"))
        out = {"Findings": self.pages[i]}
        if i + 1 < len(self.pages):
            out["NextToken"] = str(i + 1)
        return out


def test_security_hub_groups_findings_by_control():
    hub = FakeSecurityHub([[_finding("S3.1", "FAILED", "arn:b1"), _finding("S3.1", "PASSED", "arn:b2")], [_finding("IAM.6", "PASSED", "arn:root")]])
    p = AwsSecurityHubProvider(client_factory=lambda region: hub)
    inv = p.collect({"region": "eu-west-1"}, {})
    s = {x.key: x for x in inv.settings}
    assert s["aws:S3.1"].compliant is False and s["aws:S3.1"].detail == "1 of 2 resource(s) failing"
    assert s["aws:IAM.6"].compliant is True and s["aws:S3.1"].category == "aws-foundational-security-best-practices"
    assert inv.complete == {"settings"} and len(hub.calls) == 2
    assert hub.calls[0]["Filters"]["RecordState"][0]["Value"] == "ACTIVE"
    preview = AwsSecurityHubProvider(client_factory=lambda region: FakeSecurityHub([[_finding("S3.1", "FAILED", "x")], [_finding("X", "FAILED", "y")]])).collect({"region": "eu-west-1"}, {}, preview=True)
    assert len(preview.settings) == 1 and preview.complete == set()  # a preview never retires settings
    with pytest.raises(ConnectorError, match="region"):
        p.collect({"region": "evil.example.com/"}, {})


def test_security_hub_not_enabled_is_explained():
    from botocore.exceptions import ClientError

    class Off:
        def get_findings(self, **kw):
            raise ClientError({"Error": {"Code": "InvalidAccessException", "Message": "Account 123 is not subscribed"}}, "GetFindings")

    with pytest.raises(ConnectorError, match="isn't enabled"):
        AwsSecurityHubProvider(client_factory=lambda r: Off()).collect({"region": "eu-west-1"}, {})


@pytest.fixture
def mock_http(monkeypatch):
    routes, calls = {}, []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        for (method, prefix), fn in routes.items():
            if req.method == method and str(req.url).startswith(prefix):
                return fn(req)
        return httpx.Response(404)

    monkeypatch.setattr(http, "TEST_TRANSPORT", httpx.MockTransport(handler))
    return routes, calls


def test_defender_for_cloud(mock_http):
    routes, calls = mock_http
    routes[("POST", f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token")] = lambda r: httpx.Response(200, json={"access_token": "t"})
    page2 = f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Security/assessments?api-version=2021-06-01&$skipToken=2"

    def assessments(req):
        if "skipToken" in str(req.url):
            return httpx.Response(200, json={"value": [{"name": "mfa", "properties": {"displayName": "MFA should be enabled", "status": {"code": "Healthy"}}}]})
        return httpx.Response(200, json={"nextLink": page2, "value": [
            {"name": "mfa", "properties": {"displayName": "MFA should be enabled", "status": {"code": "Unhealthy"}, "metadata": {"categories": ["IdentityAndAccess"]}}},
            {"name": "na", "properties": {"displayName": "N/A", "status": {"code": "NotApplicable"}}}]})

    routes[("GET", f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Security/assessments")] = assessments
    inv = DefenderForCloudProvider().collect({"tenant_id": TENANT, "client_id": "c", "subscription_ids": SUB}, {"client_secret": "s"})
    assert [(x.key, x.compliant, x.detail, x.category) for x in inv.settings] == [("mdc:mfa", False, "1 of 2 resource(s) failing", "IdentityAndAccess")]
    token_body = parse_qs(calls[0].content.decode())
    assert token_body["scope"] == ["https://management.azure.com/.default"]
    assert all(c.headers.get("authorization") == "Bearer t" for c in calls[1:])
    with pytest.raises(ConnectorError, match="GUID"):
        DefenderForCloudProvider().collect({"tenant_id": TENANT, "client_id": "c", "subscription_ids": "../../x"}, {"client_secret": "s"})


def test_defender_next_link_to_another_host_is_refused(mock_http):
    routes, _ = mock_http
    routes[("POST", "https://login.microsoftonline.com/")] = lambda r: httpx.Response(200, json={"access_token": "t"})
    routes[("GET", "https://management.azure.com/")] = lambda r: httpx.Response(200, json={"value": [], "nextLink": "https://attacker.example/steal"})
    with pytest.raises(ConnectorError):
        DefenderForCloudProvider().collect({"tenant_id": TENANT, "client_id": "c", "subscription_ids": SUB}, {"client_secret": "s"})


def _service_account():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return key, json.dumps({"type": "service_account", "client_email": "keystone@p.iam.gserviceaccount.com", "private_key": pem, "token_uri": "https://evil.example/token"})


def test_google_scc_signs_its_own_assertion_and_groups_by_category(mock_http):
    from joserfc import jwt
    from joserfc.jwk import RSAKey

    routes, calls = mock_http
    key, sa = _service_account()
    seen = {}

    def token(req):
        seen["assertion"] = parse_qs(req.content.decode())["assertion"][0]
        return httpx.Response(200, json={"access_token": "g"})

    def findings(req):
        if "pageToken" in str(req.url):
            return httpx.Response(200, json={"listFindingsResults": [{"finding": {"category": "OPEN_FIREWALL", "resourceName": "fw-2", "severity": "HIGH"}}]})
        return httpx.Response(200, json={"nextPageToken": "p/2", "listFindingsResults": [
            {"finding": {"category": "PUBLIC_BUCKET_ACL", "resourceName": "b1", "severity": "HIGH"}},
            {"finding": {"category": "OPEN_FIREWALL", "resourceName": "fw-1", "severity": "HIGH"}}]})

    routes[("POST", "https://oauth2.googleapis.com/token")] = token
    routes[("GET", "https://securitycenter.googleapis.com/v1/organizations/123456789012/sources/-/findings")] = findings
    inv = GoogleSccProvider().collect({"organization_id": "123456789012"}, {"service_account_json": sa})
    s = {x.key: x for x in inv.settings}
    assert s["scc:OPEN_FIREWALL"].detail == "2 resource(s) affected" and s["scc:PUBLIC_BUCKET_ACL"].compliant is False
    assert not any(c.url.host == "evil.example" for c in calls)  # token_uri from the file is ignored
    claims = jwt.decode(seen["assertion"], RSAKey.import_key(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))).claims
    assert claims["aud"] == "https://oauth2.googleapis.com/token" and claims["iss"] == "keystone@p.iam.gserviceaccount.com"
    assert inv.complete == {"settings"}
    for bad in ("not json", json.dumps({"type": "authorized_user"})):
        with pytest.raises(ConnectorError):
            GoogleSccProvider().collect({"organization_id": "123456789012"}, {"service_account_json": bad})
    with pytest.raises(ConnectorError, match="number"):
        GoogleSccProvider().collect({"organization_id": "../x"}, {"service_account_json": sa})


def test_cloud_providers_are_listed_as_inventory_sources():
    from keystone.integrations.providers.base import InventoryProvider
    from keystone.integrations.service import PROVIDERS

    for k in ("aws_security_hub", "defender_for_cloud", "google_scc"):
        assert isinstance(PROVIDERS[k], InventoryProvider) and PROVIDERS[k].categories == ("posture",)
        assert all(f.secret for f in PROVIDERS[k].fields if "secret" in f.name or "key" in f.name and f.name != "region")
