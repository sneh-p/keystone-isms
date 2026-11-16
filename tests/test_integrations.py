"""Phase 7: integrations - providers (mocked), secrets, evidence, errors, SSRF guard, scheduler."""

import json

import httpx
import pytest
from botocore.exceptions import ClientError
from sqlalchemy import select

from keystone.controls.models import Evidence
from keystone.core.audit import AuditLog
from keystone.core.rbac import PermissionDenied
from keystone.frameworks.service import control_by_code
from keystone.integrations import service as integ
from keystone.integrations.models import Integration
from keystone.integrations.providers.aws import AwsProvider
from keystone.integrations.providers.github import GitHubProvider
from keystone.integrations.providers.website import WebsiteProvider, assert_public_host
from tests.conftest import api_login


def website(redirect=True, headers=True, tls=("TLSv1.3", "Dec 31 23:59:59 2099 GMT")):
    def handler(req: httpx.Request):
        if req.url.scheme == "http":
            return httpx.Response(301, headers={"location": "https://shop.example/"}) if redirect else httpx.Response(200)
        h = {"strict-transport-security": "max-age=1", "x-content-type-options": "nosniff", "content-security-policy": "default-src 'self'"} if headers else {}
        return httpx.Response(200, headers=h)
    return WebsiteProvider(client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler)), tls=lambda host: {"version": tls[0], "not_after": tls[1]}, resolve_check=lambda h: None)


def test_website_provider():
    res = {o.key: o.result for o in website().run({"url": "https://shop.example"}, {})}
    assert res == {"https_redirect": "pass", "security_headers": "pass", "tls_version": "pass", "certificate": "pass"}
    bad = {o.key: o for o in website(redirect=False, headers=False, tls=("TLSv1", "Jan 01 00:00:00 2020 GMT")).run({"url": "shop.example"}, {})}
    assert {k: o.result for k, o in bad.items()} == {"https_redirect": "fail", "security_headers": "fail", "tls_version": "fail", "certificate": "fail"}
    assert "content-security-policy" in bad["security_headers"].summary


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1"])
def test_ssrf_guard(host):
    with pytest.raises(ValueError, match="non-public"):
        assert_public_host(host)


def github(two_fa=True, protected=("api",), sa_enabled=True):
    repos = [{"name": n, "default_branch": "main", "archived": False, "security_and_analysis": {"secret_scanning": {"status": "enabled" if sa_enabled else "disabled"}, "dependabot_security_updates": {"status": "enabled" if sa_enabled else "disabled"}}} for n in ("api", "web")]
    def handler(req: httpx.Request):
        assert req.method == "GET"
        p = req.url.path
        if p == "/orgs/acme":
            return httpx.Response(200, json={"two_factor_requirement_enabled": two_fa})
        if p == "/orgs/acme/repos":
            return httpx.Response(200, json=repos)
        if p.endswith("/protection"):
            return httpx.Response(200 if p.split("/")[3] in protected else 404, json={})
        return httpx.Response(404)
    return GitHubProvider(client_factory=lambda: httpx.Client(base_url="https://api.github.com", transport=httpx.MockTransport(handler)))


def test_github_provider():
    r = {o.key: o for o in github().run({"org": "acme"}, {"token": "t"})}
    assert r["org_2fa"].result == "pass" and r["secret_scanning"].result == "pass"
    assert r["branch_protection"].result == "fail" and "web" in r["branch_protection"].summary
    r2 = {o.key: o.result for o in github(two_fa=None, protected=("api", "web"), sa_enabled=False).run({"org": "acme"}, {"token": "t"})}
    assert r2 == {"org_2fa": "unknown", "branch_protection": "pass", "secret_scanning": "fail", "dependabot": "fail"}


class FakeAws:
    def __init__(self, mfa=1, logging=True, pw=None, block=True, detectors=("d1",), deny=()):
        self.mfa, self.logging, self.pw, self.block, self.detectors, self.deny = mfa, logging, pw, block, detectors, deny

    def client(self, name):
        me = self
        class C:
            def __getattr__(self, op):
                def call(**kw):
                    if op in me.deny:
                        raise ClientError({"Error": {"Code": "AccessDenied"}}, op)
                    return {
                        "get_account_summary": {"SummaryMap": {"AccountMFAEnabled": me.mfa}},
                        "describe_trails": {"trailList": [{"Name": "main", "TrailARN": "arn", "IsMultiRegionTrail": True}]},
                        "get_trail_status": {"IsLogging": me.logging},
                        "get_caller_identity": {"Account": "123"},
                        "get_public_access_block": {"PublicAccessBlockConfiguration": {k: me.block for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}},
                        "list_detectors": {"DetectorIds": list(me.detectors)},
                    }[op] if op != "get_account_password_policy" else me._pw()
                return call
        return C()

    def _pw(self):
        if self.pw is None:
            raise ClientError({"Error": {"Code": "NoSuchEntity"}}, "get_account_password_policy")
        return {"PasswordPolicy": self.pw}


def test_aws_provider():
    good = AwsProvider(session_factory=lambda: FakeAws(pw={"MinimumPasswordLength": 14, "RequireSymbols": True, "RequireNumbers": True}))
    assert {o.key: o.result for o in good.run({"region": "eu-west-1"}, {})} == dict.fromkeys(["root_mfa", "cloudtrail", "password_policy", "s3_public_block", "guardduty"], "pass")
    bad = AwsProvider(session_factory=lambda: FakeAws(mfa=0, logging=False, block=False, detectors=(), deny=("list_detectors",)))
    r = {o.key: o.result for o in bad.run({"region": "eu-west-1"}, {})}
    assert r == {"root_mfa": "fail", "cloudtrail": "fail", "password_policy": "fail", "s3_public_block": "fail", "guardduty": "error"}


# ---- service ----------------------------------------------------------------------------------

@pytest.fixture
def site(content, session, users, monkeypatch):
    monkeypatch.setitem(integ.PROVIDERS, "website", website())
    return integ.save_integration(session, users["admin"], provider_key="website", name="Shop", values={"url": "https://shop.example"})


def test_secrets_encrypted_redacted_and_write_only(content, session, users, monkeypatch):
    monkeypatch.setitem(integ.PROVIDERS, "github", github())
    i = integ.save_integration(session, users["admin"], provider_key="github", values={"org": "acme", "token": "ghp_supersecret"})
    assert "ghp_supersecret" not in (i.secret_enc or "") and i.config == {"org": "acme"}
    integ.save_integration(session, users["admin"], i.id, values={"org": "acme2"})  # token kept
    assert json.loads(integ.crypto.decrypt(i.secret_enc)) == {"token": "ghp_supersecret"}
    assert "ghp_supersecret" not in str([r.changes for r in session.scalars(select(AuditLog))])
    with pytest.raises(ValueError, match="Missing"):
        integ.save_integration(session, users["admin"], provider_key="github", values={"org": "x"})
    with pytest.raises(ValueError, match="Unknown settings"):
        integ.save_integration(session, users["admin"], provider_key="github", values={"org": "x", "token": "t", "evil": 1})
    with pytest.raises(PermissionDenied):
        integ.save_integration(session, users["control_owner"], provider_key="website", values={"url": "x.example"})


def test_run_files_evidence_only_for_passing_checks(site, session, users):
    results = integ.run(session, users["admin"], site.id)
    assert {r.result for r in results} == {"pass"}
    ev = session.scalars(select(Evidence).where(Evidence.title.like("Automated check:%"))).all()
    assert {e.common_control_id for e in ev} >= {control_by_code(session, "KC-TEC-24").id}
    assert integ.latest_results_for_control(session, control_by_code(session, "KC-TEC-24").id)


def test_provider_crash_becomes_error_not_pass(content, session, users, monkeypatch):
    class Boom(WebsiteProvider):
        def run(self, *a, **k):
            raise RuntimeError("network down")
    monkeypatch.setitem(integ.PROVIDERS, "website", Boom())
    i = integ.save_integration(session, users["admin"], provider_key="website", values={"url": "https://x.example"})
    res = integ.run(session, users["admin"], i.id)
    assert {r.result for r in res} == {"error"} and i.last_status == "error" and "network down" not in i.last_error
    assert session.scalars(select(Evidence)).all() == []


def test_readiness_counts_failing_checks(content, session, users, monkeypatch):
    from keystone.tasks.service import control_readiness
    monkeypatch.setitem(integ.PROVIDERS, "website", website(redirect=False))
    i = integ.save_integration(session, users["admin"], provider_key="website", values={"url": "https://x.example"})
    integ.run(session, users["admin"], i.id)
    c = control_by_code(session, "KC-TEC-20")
    chk = next(ch for ch in control_readiness(session, c).checks if ch["kind"] == "checks")
    assert not chk["ok"]


def test_entra_provider_unknown_when_data_missing(users, session, tenant_b, content):
    from keystone.tprm.exposure import importer
    i = integ.save_integration(session, users["admin"], provider_key="entra", values={})
    assert {r.result for r in integ.run(session, users["admin"], i.id)} == {"unknown"}
    importer.import_document(session, users["admin"], tenant_b, create_tenant_name="Tailspin")
    r = {x.check_key: x.result for x in integ.run(session, users["admin"], i.id)}
    assert r["user_consent"] == "fail" and r["admin_consent_workflow"] == "fail"
    assert r["expired_credentials"] == "unknown" and r["dormant_high_risk"] == "unknown"  # tenant B lacks those datasets


def test_scheduler_job_runs_due_integrations(content, db, users, monkeypatch):
    from keystone import jobs
    monkeypatch.setitem(integ.PROVIDERS, "website", website())
    with db.session_scope() as s:
        iid = integ.save_integration(s, users["admin"], provider_key="website", values={"url": "https://shop.example"}).id
    with db.session_scope() as s:
        assert [i.id for i in integ.due(s)] == [iid]
    jobs.run_due_integrations()
    with db.session_scope() as s:
        assert integ.due(s) == [] and s.get(Integration, iid).last_status == "ok"
        assert s.scalar(select(AuditLog).where(AuditLog.action == "integration_run")).actor_name == "system"


def test_api_never_returns_secrets(api, ready_users, content, monkeypatch):
    monkeypatch.setitem(integ.PROVIDERS, "github", github())
    api_login(api, "admin")
    r = api.post("/api/integrations", json={"provider": "github", "values": {"org": "acme", "token": "ghp_topsecret"}})
    assert r.status_code == 200 and r.json()["secret_set"] is True and "ghp_topsecret" not in r.text and "secret_enc" not in r.text
    iid = r.json()["id"]
    assert "ghp_topsecret" not in api.get("/api/integrations").text
    run = api.post(f"/api/integrations/{iid}/run").json()
    assert {x["check_key"] for x in run["results"]} == {"org_2fa", "branch_protection", "secret_scanning", "dependabot"}
    api_login(api, "viewer")
    assert api.post(f"/api/integrations/{iid}/run").status_code == 403


def test_dry_run_saves_nothing_and_never_leaks_secrets(content, session, users, monkeypatch):
    from keystone.integrations.models import CheckResult

    monkeypatch.setitem(integ.PROVIDERS, "website", website())
    res = integ.test(session, users["admin"], "website", {"url": "https://shop.example"})
    assert {r["check_key"]: r["result"] for r in res}["https_redirect"] == "pass"
    assert session.scalar(select(CheckResult)) is None and session.scalar(select(Evidence)) is None and session.scalar(select(Integration)) is None
    with pytest.raises(PermissionDenied):
        integ.test(session, users["control_owner"], "website", {"url": "https://shop.example"})
    with pytest.raises(ValueError, match="Missing"):
        integ.test(session, users["admin"], "github", {"org": "acme"})
    # Editing: an empty secret field falls back to the stored secret.
    monkeypatch.setitem(integ.PROVIDERS, "github", github())
    i = integ.save_integration(session, users["admin"], provider_key="github", values={"org": "acme", "token": "ghp_secret_value"})
    res = integ.test(session, users["admin"], values={"org": "acme"}, integration_id=i.id)
    assert {r["result"] for r in res} - {"error"}
    session.flush()
    assert all("ghp_secret_value" not in (r.summary + json.dumps(r.changes or {})) for r in session.scalars(select(AuditLog)))


def test_setup_guides_never_template_secrets():
    import re

    for p in integ.PROVIDERS.values():
        secret = {f.name for f in p.fields if f.secret}
        for st in p.setup:
            assert not set(re.findall(r"\{(\w+)\}", st.code + st.text + st.link)) & secret, p.key
            assert st.kind in ("do", "verify")


def _site(handler, resolve_check=lambda h: None):
    return WebsiteProvider(client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler)), tls=lambda host: {"version": "TLSv1.3", "not_after": "Dec 31 23:59:59 2099 GMT"}, resolve_check=resolve_check)


def _headers_result(provider):
    return next(o for o in provider.run({"url": "https://shop.example"}, {}) if o.key == "security_headers")


def test_blocked_site_is_unknown_not_fail():
    o = _headers_result(_site(lambda req: httpx.Response(301, headers={"location": "https://shop.example/"}) if req.url.scheme == "http" else httpx.Response(403)))
    assert o.result == "unknown" and "403" in o.summary


def test_https_redirects_followed_and_guarded():
    full = {"strict-transport-security": "max-age=1", "x-content-type-options": "nosniff", "content-security-policy": "default-src 'self'"}

    def handler(req):
        if req.url.scheme == "http":
            return httpx.Response(301, headers={"location": "https://shop.example/"})
        if req.url.path == "/":
            return httpx.Response(302, headers={"location": "/en/"})
        return httpx.Response(200, headers=full)

    o = _headers_result(_site(handler))
    assert o.result == "pass" and o.details["url"] == "https://shop.example/en/"

    downgrade = _headers_result(_site(lambda req: httpx.Response(301, headers={"location": "http://shop.example/"})))
    assert downgrade.result == "fail" and "plain HTTP" in downgrade.summary

    def guard(host):
        if host != "shop.example":
            raise ValueError("Refusing to check a non-public address.")

    internal = _headers_result(_site(lambda req: httpx.Response(302, headers={"location": "https://intranet.local/"}), resolve_check=guard))
    assert internal.result == "error" and "non-public" in internal.summary

    loop = _headers_result(_site(lambda req: httpx.Response(302, headers={"location": "https://shop.example/again"})))
    assert loop.result == "error" and "redirects" in loop.summary
