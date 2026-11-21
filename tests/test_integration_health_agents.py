"""Batch A of the integrations and agents work: raw results as evidence, change alerts, integration health and
credential expiry, read-only key checks, agent check-ins, integrity, enrolment key limits, coverage, quiet agents,
the signed Windows agent, and the macOS agent (run here with stand-in macOS tools)."""

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
from datetime import date, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from keystone.configcheck import agents as agt
from keystone.configcheck import custom
from keystone.configcheck.models import ConfigTarget
from keystone.controls.models import Evidence
from keystone.core.attachments import Attachment, read_attachment
from keystone.core.db import utcnow
from keystone.frameworks.service import control_by_code
from keystone.integrations import service as integ
from keystone.integrations.models import Integration
from keystone.integrations.providers.asm_microsoft import read_only, token_roles
from keystone.integrations.providers.aws import AwsProvider
from keystone.integrations.providers.base import CheckDef, ConfigField, Outcome, Provider
from keystone.integrations.providers.github import GitHubProvider
from keystone.notifications.models import Notification
from keystone.notifications.service import items_for
from keystone.tasks.models import Task
from tests.conftest import api_login

ROOT = Path(__file__).resolve().parents[1]
SH = shutil.which("dash") or "/bin/sh"


class Scripted(Provider):
    """A provider whose next outcome is set by the test."""

    key = "scripted"
    name = "Scripted tool"
    fields = (ConfigField("token", "Token", secret=True),)
    checks = (CheckDef("mfa", "MFA enforced", ("KC-TEC-05",)),)

    def __init__(self):
        self.next = "pass"

    def run(self, config, secrets, session=None):
        if self.next == "error":
            raise ValueError("The tool is down")
        return [Outcome("mfa", self.next, "All users" if self.next == "pass" else "3 users without MFA", {"without_mfa": [] if self.next == "pass" else ["a", "b", "c"]})]


@pytest.fixture
def scripted(monkeypatch):
    p = Scripted()
    monkeypatch.setitem(integ.PROVIDERS, "scripted", p)
    return p


def test_raw_results_filed_as_evidence_once_a_day(content, session, users, scripted):
    i = integ.save_integration(session, users["admin"], provider_key="scripted", name="Tool", values={"token": "secret-value"})
    integ.run(session, users["admin"], i.id)
    integ.run(session, users["admin"], i.id)  # same day: no second file
    ev = session.scalar(select(Evidence).where(Evidence.title == "Automated check: MFA enforced (Tool)"))
    files = list(session.scalars(select(Attachment).where(Attachment.entity_type == "Evidence", Attachment.entity_id == ev.id)))
    assert len(files) == 1 and ev.attachment_id == files[0].id and files[0].filename.endswith(".json")
    data = read_attachment(files[0])
    assert files[0].sha256 == hashlib.sha256(data).hexdigest()
    doc = json.loads(data)
    assert doc["result"] == "pass" and doc["check"] == "mfa" and doc["controls"] == ["KC-TEC-05"]
    assert b"secret-value" not in data  # never the credentials


def test_health_counts_failures_and_escalates_after_three(content, session, users, scripted):
    i = integ.save_integration(session, users["admin"], provider_key="scripted", name="Tool", values={"token": "t"})
    integ.run(session, users["admin"], i.id)
    assert i.consecutive_failures == 0 and i.last_success_at is not None
    scripted.next = "error"
    for _ in range(3):
        integ.run(session, users["admin"], i.id)
    h = integ.health(i)
    assert h["consecutive_failures"] == 3 and h["escalated"]
    manager = users["isms_manager"]
    assert any("failed 3 runs in a row" in x["title"] for x in items_for(session, manager))
    assert not any("runs in a row" in x["title"] for x in items_for(session, users["viewer"]))
    scripted.next = "pass"
    integ.run(session, users["admin"], i.id)
    assert i.consecutive_failures == 0


def test_a_check_that_starts_failing_opens_one_task_for_the_control_owner(content, session, users, scripted):
    owner = users["control_owner"]
    control_by_code(session, "KC-TEC-05").owner_id = owner.id
    i = integ.save_integration(session, users["admin"], provider_key="scripted", name="Tool", values={"token": "t"})
    integ.run(session, users["admin"], i.id)
    scripted.next = "fail"
    integ.run(session, users["admin"], i.id)
    integ.run(session, users["admin"], i.id)  # still failing: no second task
    tasks = list(session.scalars(select(Task).where(Task.template_key == f"integration-check:{i.id}:mfa")))
    assert len(tasks) == 1 and tasks[0].assignee_id == owner.id and tasks[0].due_date == date.today() + timedelta(days=14)
    assert [c.code for c in tasks[0].controls] == ["KC-TEC-05"]
    assert session.scalar(select(Notification).where(Notification.user_id == owner.id, Notification.title.like("MFA enforced (Tool) started failing%"))) is not None
    scripted.next = "pass"
    integ.run(session, users["admin"], i.id)
    assert session.scalar(select(Notification).where(Notification.user_id == owner.id, Notification.title.like("%passes again%"))) is not None


def test_flapping_checks_are_flagged_and_do_not_open_new_tasks(content, session, users, scripted):
    i = integ.save_integration(session, users["admin"], provider_key="scripted", name="Tool", values={"token": "t"})
    for r in ("pass", "fail", "pass", "fail", "pass"):
        scripted.next = r
        integ.run(session, users["admin"], i.id)
    assert integ.flapping(session, i.id, "mfa")
    tasks = list(session.scalars(select(Task).where(Task.template_key == f"integration-check:{i.id}:mfa")))
    assert len(tasks) == 1  # the first change opened one; flapping afterwards didn't add more
    scripted.next = "fail"
    integ.run(session, users["admin"], i.id)
    titles = [n.title for n in session.scalars(select(Notification))]
    assert any("keeps changing between pass and fail" in t for t in titles)


def test_credential_expiry_is_validated_and_reminded(content, session, users, scripted):
    i = integ.save_integration(session, users["admin"], provider_key="scripted", name="Tool", values={"token": "t"}, credential_expires_on=date.today() + timedelta(days=10))
    assert integ.health(i)["credential_expiring"] and integ.health(i)["credential_days_left"] == 10
    assert any("The key for Tool expires on" in x["title"] for x in items_for(session, users["admin"]))
    with pytest.raises(ValueError, match="ten years"):
        integ.save_integration(session, users["admin"], i.id, credential_expires_on=date.today() + timedelta(days=5000))
    integ.save_integration(session, users["admin"], i.id, clear_credential_expiry=True)
    assert i.credential_expires_on is None


def test_credential_expiry_through_the_api(api, ready_users, db):
    api_login(api, "admin")
    r = api.post("/api/integrations", json={"provider": "website", "name": "Shop", "values": {"url": "https://shop.example"}, "credential_expires_on": (date.today() + timedelta(days=30)).isoformat()})
    assert r.status_code == 200 and r.json()["health"]["credential_days_left"] == 30
    r = api.patch(f"/api/integrations/{r.json()['id']}", json={"clear_credential_expiry": True})
    assert r.json()["health"]["credential_expires_on"] is None
    assert api.patch(f"/api/integrations/{r.json()['id']}", json={"credential_expires_on": "not a date"}).status_code == 422


# ---- read-only key checks ---------------------------------------------------------------------------------------------

def _github(scopes):
    def handler(req: httpx.Request):
        h = {} if scopes is None else {"x-oauth-scopes": scopes}
        if req.url.path.endswith("/repos"):
            return httpx.Response(200, json=[], headers=h)
        return httpx.Response(200, json={"two_factor_requirement_enabled": True}, headers=h)
    return GitHubProvider(client_factory=lambda: httpx.Client(base_url="https://api.github.com", transport=httpx.MockTransport(handler)))


def test_github_key_permissions():
    assert _github(None).permissions({"org": "acme"}, {"token": "t"}).result == "unknown"  # fine-grained tokens don't say
    assert _github("read:org, read:user").permissions({"org": "acme"}, {"token": "t"}).result == "pass"
    bad = _github("repo, read:org, admin:org").permissions({"org": "acme"}, {"token": "t"})
    assert bad.result == "fail" and bad.extra == ["admin:org", "repo"]


class FakeIam:
    def __init__(self, arn, attached=(), inline=(), groups=()):
        self.arn, self.attached, self.inline, self.groups = arn, attached, inline, groups

    def client(self, name, **kw):
        me = self

        class C:
            def get_caller_identity(self):
                return {"Arn": me.arn, "Account": "111122223333"}

            def list_attached_user_policies(self, **kw):  # boto3 passes UserName=...
                return {"AttachedPolicies": [{"PolicyArn": a} for a in me.attached]}

            def list_user_policies(self, **kw):
                return {"PolicyNames": list(me.inline)}

            def list_groups_for_user(self, **kw):
                return {"Groups": [{"GroupName": g} for g in me.groups]}
        return C()


def test_aws_key_permissions():
    def p(**kw):
        return AwsProvider(session_factory=lambda: FakeIam(**kw)).permissions({"region": "eu-west-1"}, {})
    assert p(arn="arn:aws:iam::111122223333:user/keystone", attached=("arn:aws:iam::aws:policy/SecurityAudit",)).result == "pass"
    wide = p(arn="arn:aws:iam::111122223333:user/keystone", attached=("arn:aws:iam::aws:policy/SecurityAudit", "arn:aws:iam::aws:policy/AdministratorAccess"), groups=("ops",))
    assert wide.result == "fail" and wide.extra == ["AdministratorAccess", "group ops"]
    assert p(arn="arn:aws:iam::111122223333:root").result == "fail"
    assert p(arn="arn:aws:sts::111122223333:assumed-role/keystone/session").result == "unknown"


def test_microsoft_token_roles_are_read_for_display_only():
    claims = base64.urlsafe_b64encode(json.dumps({"roles": ["User.Read.All", "Machine.Read.All", "Device.ReadWrite.All"]}).encode()).decode().rstrip("=")
    roles = token_roles(f"x.{claims}.y")
    assert roles == ["User.Read.All", "Machine.Read.All", "Device.ReadWrite.All"]
    assert [r for r in roles if not read_only(r)] == ["Device.ReadWrite.All"]
    assert token_roles("not-a-token") == [] and token_roles("a.!!!.c") == []


def test_test_connection_reports_the_key_check(content, session, users, monkeypatch):
    monkeypatch.setitem(integ.PROVIDERS, "github", _github("repo"))
    out = integ.test(session, users["admin"], "github", {"org": "acme", "token": "t"})
    perm = next(r for r in out if r["check_key"] == "permissions")
    assert perm["result"] == "fail" and "repo" in perm["summary"]
    assert integ.permission_check(integ.PROVIDERS["website"], {}, {})["result"] == "unknown"


# ---- agents -------------------------------------------------------------------------------------------------------

def _enrol(api, platform="linux", hostname="web-01"):
    api_login(api, "admin")
    key = api.get("/api/config/agent").json()["enrolment_key"]
    api.cookies.clear()
    api.headers.pop("X-CSRF-Token", None)
    r = api.post("/api/agent/v1/enrol", json={"enrolment_key": key, "hostname": hostname, "platform": platform})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_checkin_says_when_a_report_is_due(api, ready_users, db):
    auth = _enrol(api)
    assert api.post("/api/agent/v1/checkin", json={"agent_version": "1.2.0"}).status_code == 401
    r = api.post("/api/agent/v1/checkin", json={"agent_version": "1.2.0", "agent_sha256": "a" * 64}, headers=auth)
    assert r.status_code == 200 and r.json()["report_due"] is True
    assert api.post("/api/agent/v1/report", json={"facts": {"firewall_active": True}, "agent_version": "1.2.0"}, headers=auth).status_code == 200
    assert api.post("/api/agent/v1/checkin", json={"agent_version": "1.2.0"}, headers=auth).json()["report_due"] is False
    assert api.post("/api/agent/v1/checkin", json={"agent_sha256": "x" * 100}, headers=auth).status_code == 422
    with db.session_scope() as s:
        t = s.scalar(select(ConfigTarget))
        assert t.last_seen_at is not None and t.agent_sha256 == "a" * 64


def test_integrity_and_out_of_date_agents(api, ready_users, db):
    auth = _enrol(api)
    current = agt.agent_file("linux")
    api.post("/api/agent/v1/report", json={"facts": {}, "agent_version": current.version, "agent_sha256": current.sha256}, headers=auth)
    api_login(api, "admin")
    t = api.get("/api/config/targets").json()[0]
    assert t["agent"]["integrity"] == "ok" and not t["agent"]["outdated"] and t["agent"]["checks_in"]
    api.cookies.clear()
    api.post("/api/agent/v1/report", json={"facts": {}, "agent_version": "1.1.0", "agent_sha256": "b" * 64}, headers=auth)
    api_login(api, "admin")
    t = api.get("/api/config/targets").json()[0]
    assert t["agent"]["integrity"] == "modified" and t["agent"]["outdated"] and t["agent"]["latest_version"] == current.version
    with db.session_scope() as s:
        admin = s.scalar(select(type(ready_users["admin"])).where(type(ready_users["admin"]).username == "admin"))
        assert any("isn't one Keystone handed out" in x["title"] for x in items_for(s, admin))


def test_enrolment_key_limits(api, ready_users, db):
    api_login(api, "admin")
    view = api.patch("/api/config/agent", json={"set_key_limits": True, "key_days": 7, "key_max_uses": 1}).json()
    assert view["limits"]["max_uses"] == 1 and view["limits"]["uses_left"] == 1 and view["limits"]["days"] == 7
    assert api.patch("/api/config/agent", json={"set_key_limits": True, "key_days": 400}).status_code == 422
    key = view["enrolment_key"]
    api.cookies.clear()
    api.headers.pop("X-CSRF-Token", None)
    body = {"enrolment_key": key, "hostname": "web-01", "platform": "linux"}
    assert api.post("/api/agent/v1/enrol", json=body).status_code == 200
    r = api.post("/api/agent/v1/enrol", json={**body, "hostname": "web-02"})
    assert r.status_code == 401 and "as many times" in r.json()["detail"]
    api_login(api, "admin")
    view = api.post("/api/config/agent/rotate").json()  # a new key: uses start again, the limits stay
    assert view["limits"]["uses"] == 0 and view["limits"]["max_uses"] == 1 and view["limits"]["expires_at"]
    with db.session_scope() as s:
        from keystone.configcheck.service import agent_settings

        agent_settings(s).enrollment_expires_at = utcnow() - timedelta(minutes=1)
    api.cookies.clear()
    api.headers.pop("X-CSRF-Token", None)
    r = api.post("/api/agent/v1/enrol", json={**body, "enrolment_key": view["enrolment_key"]})
    assert r.status_code == 401 and "expired" in r.json()["detail"]


def test_quiet_agents_are_reported(api, ready_users, db):
    auth = _enrol(api)
    api.post("/api/agent/v1/checkin", json={"agent_version": "1.2.0"}, headers=auth)
    api.post("/api/agent/v1/report", json={"facts": {}, "agent_version": "1.2.0"}, headers=auth)
    with db.session_scope() as s:
        t = s.scalar(select(ConfigTarget))
        assert not agt.state(s, t)["silent"]
        t.last_seen_at = t.facts_at = utcnow() - timedelta(hours=agt.SILENT_AFTER_HOURS + 1)
    with db.session_scope() as s:
        t = s.scalar(select(ConfigTarget))
        assert agt.state(s, t)["silent"]
        admin = s.get(type(ready_users["admin"]), ready_users["admin"].id)
        assert any("hasn't been heard from" in x["title"] for x in items_for(s, admin))


def test_coverage_and_device_links(content, session, users):
    from keystone.asm.models import AsmDevice, AsmSourceRecord

    now = utcnow()
    devs = {}
    for name, cats in (("web-01", ("rmm", "edr")), ("web-02", ("rmm",)), ("lap-07", ("rmm", "edr"))):
        d = AsmDevice(name=name, hostname=name, device_type="server" if name.startswith("web") else "workstation", last_seen=now, properties={})
        session.add(d)
        session.flush()
        devs[name] = d
        for c in cats:
            session.add(AsmSourceRecord(category=c, external_id=f"{name}-{c}", device_id=d.id, properties={}))
    t1 = ConfigTarget(kind="agent", platform="linux", name="web-01", hostname="web-01.corp.example", facts={})
    t2 = ConfigTarget(kind="agent", platform="linux", name="web-02", hostname="web-02", facts={})
    t3 = ConfigTarget(kind="agent", platform="macos", name="build-mac", hostname="build-mac", facts={})
    session.add_all([t1, t2, t3])
    session.flush()
    for t in (t1, t2, t3):
        agt.link(session, t)
    assert t1.device_id == devs["web-01"].id and t2.device_id == devs["web-02"].id and t3.device_id is None
    c = agt.coverage(session)
    assert c["devices"] == 3 and c["with_agent"] == 2 and c["percent"] == 67 and c["edr_source"]
    assert [d["name"] for d in c["no_agent"]] == ["lap-07"]
    assert [t["name"] for t in c["no_edr"]] == ["web-02"]
    assert [t["name"] for t in c["not_in_tools"]] == ["build-mac"]


def test_coverage_api_needs_sign_in(api, ready_users, db):
    assert api.get("/api/config/coverage").status_code == 401
    api_login(api, "viewer")
    assert api.get("/api/config/coverage").json()["devices"] == 0


# ---- the signed Windows agent ---------------------------------------------------------------------------------------

def test_signed_windows_agent_is_served_only_if_it_is_the_shipped_script(db, session, tmp_path):
    shipped = (ROOT / "agents/windows/keystone-agent.ps1").read_bytes()
    folder = Path(os.environ["KEYSTONE_DATA_DIR"]) / "agents"
    folder.mkdir(parents=True)
    signed = shipped.replace(b"\n", b"\r\n").rstrip() + b"\r\n# SIG # Begin signature block\r\n# MIIabc\r\n# SIG # End signature block\r\n"
    (folder / "keystone-agent.ps1").write_bytes(signed)
    f = agt.agent_file("windows")
    assert f.signed and f.data == signed and f.sha256 == hashlib.sha256(signed).hexdigest()
    agt.record_releases(session)
    tampered = signed.replace(b"Report-only", b"Report-and-more", 1)
    (folder / "keystone-agent.ps1").write_bytes(tampered)
    f = agt.agent_file("windows")
    assert not f.signed and f.data == shipped
    (folder / "keystone-agent.ps1").write_bytes(shipped)  # no signature block: not used
    assert not agt.agent_file("windows").signed


# ---- deny lists: the server's list must be in every agent ---------------------------------------------------------------

@pytest.mark.parametrize("script", ["agents/linux/keystone-agent.sh", "agents/macos/keystone-agent.sh"])
def test_agents_refuse_every_path_the_server_refuses(script):
    text = (ROOT / script).read_text(encoding="utf-8")
    body = text[text.index("deny_path() {"):text.index("ok_path()")]
    for g in custom.DENIED_PATH_GLOBS:
        assert g in body, f"{script} doesn't refuse {g}"


def test_macos_paths_are_validated():
    with pytest.raises(custom.CheckInvalid, match="doesn't read"):
        custom.validate("macos", "plist_value", {"path": "/Users/ada/Library/Preferences/x.plist", "key": "k", "mode": "value"}, "str")
    with pytest.raises(custom.CheckInvalid, match="doesn't read"):
        custom.validate("macos", "file_contains", {"path": "/Library/Keychains/System.keychain", "text": "x"}, "bool")
    with pytest.raises(custom.CheckInvalid):
        custom.validate("macos", "app_installed", {"name": "../../etc/passwd", "field": "present"}, "bool")
    with pytest.raises(custom.CheckInvalid):
        custom.validate("macos", "registry_value", {"path": "SOFTWARE", "name": "x", "mode": "value"}, "str")
    clean, _ = custom.validate("macos", "app_installed", {"name": "Microsoft Teams", "field": "version"}, "str")
    assert clean["name"] == "Microsoft Teams"
    clean, _ = custom.validate("macos", "file_exists", {"path": "/Library/Application Support/Example"}, "bool")
    assert clean["path"] == "/Library/Application Support/Example"


# ---- the macOS agent, with stand-in macOS tools ---------------------------------------------------------------------------

STUBS = {
    "socketfilterfw": 'case "$1" in --getglobalstate) echo "Firewall is enabled. (State = 1)";; --getstealthmode) echo "Firewall stealth mode is off";; esac',
    "fdesetup": 'echo "FileVault is On."',
    "spctl": 'echo "assessments enabled"',
    "csrutil": 'echo "System Integrity Protection status: enabled."',
    "defaults": 'case "$3" in AutomaticCheckEnabled|CriticalUpdateInstall) echo 1;; GuestEnabled) echo 0;; *) exit 1;; esac',
    "launchctl": 'case "$2" in system/com.openssh.sshd|system/com.example.loaded) exit 0;; *) exit 1;; esac',
    "sshd": 'printf "permitrootlogin no\\npasswordauthentication yes\\n"',
    "dscl": 'echo "GroupMembership: root ada bob"',
    "systemsetup": 'echo "Network Time: On"',
    "scutil": 'echo "build-mac"',
    "sw_vers": 'case "$1" in -productName) echo macOS;; -productVersion) echo 15.1;; -buildVersion) echo 24B83;; esac',
    "shasum": 'sha256sum "$3"',
    "sysctl": '[ "$2" = net.inet.ip.forwarding ] && echo 0 || exit 1',
    "PlistBuddy": 'case "$2" in "Print :SHOWFULLNAME") echo 1;; "Print :CFBundleShortVersionString") echo 24.1;; *) exit 1;; esac',
    "stat": 'case "$2" in %Lp) echo 644;; %Su) echo root;; %Sg) echo wheel;; esac',
}


@pytest.fixture
def mac_tools(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in STUBS.items():
        p = bin_dir / name
        p.write_text(f"#!/bin/sh\n{body}\n")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return bin_dir


def _mac(tmp_path, bin_dir, *args):
    env = {"KEYSTONE_AGENT_EXTRA_PATH": str(bin_dir), "HOME": str(tmp_path), "LC_ALL": "C"}
    out = subprocess.run([SH, str(ROOT / "agents/macos/keystone-agent.sh"), *args], capture_output=True, text=True, timeout=60, env=env, check=True)
    return json.loads(out.stdout)


def test_macos_agent_collects_the_built_in_settings(tmp_path, mac_tools):
    r = _mac(tmp_path, mac_tools, "collect")
    assert r["hostname"] == "build-mac" and r["os_name"] == "macOS 15.1" and r["agent_version"] == agt.agent_file("macos").version
    assert len(r["agent_sha256"]) == 64
    assert r["facts"] == {"firewall_active": True, "firewall_stealth_mode": False, "filevault_enabled": True, "gatekeeper_enabled": True, "sip_enabled": True,
                          "automatic_updates_enabled": True, "remote_login_enabled": True, "ssh_permit_root_login": "no", "ssh_password_authentication": True,
                          "screen_sharing_enabled": False, "guest_account_enabled": False, "auto_login_enabled": False, "local_admin_count": 2, "time_sync_active": True}


def test_macos_agent_custom_checks_and_refusals(tmp_path, mac_tools):
    app = tmp_path / "Applications"
    plist = tmp_path / "loginwindow.plist"
    plist.write_text("<plist/>")
    defs = tmp_path / "defs.tsv"
    lines = [
        ["custom.login_names", "plist_value", "int", f"path={plist}", "key=SHOWFULLNAME", "mode=value"],
        ["custom.fwd", "sysctl", "int", "key=net.inet.ip.forwarding"],
        ["custom.svc", "launchd_service", "bool", "label=com.example.loaded"],
        ["custom.svc_off", "launchd_service", "bool", "label=com.example.other"],
        ["custom.keychain", "file_contains", "bool", "path=/Library/Keychains/System.keychain", "text=x"],
        ["custom.home", "plist_value", "str", "path=/Users/ada/Library/Preferences/x.plist", "key=k", "mode=value"],
        ["custom.dslocal", "file_setting", "str", "path=/private/var/db/dslocal/nodes/Default/users/ada.plist", "key=k", "separator=equals"],
        ["custom.sneaky", "app_installed", "bool", "name=../../../tmp/x", "field=present"],
        ["custom.semi", "launchd_service", "bool", "label=a;reboot"],
        ["custom.mode", "file_mode", "str", f"path={plist}", "field=mode"],
        ["custom.reg", "registry_value", "int", "path=SOFTWARE", "name=x", "mode=value"],
    ]
    defs.write_text("".join("\t".join(x) + "\n" for x in lines))
    r = _mac(tmp_path, mac_tools, "collect-custom", str(defs))
    assert r["facts"] == {"custom.login_names": 1, "custom.fwd": 0, "custom.svc": True, "custom.svc_off": False, "custom.mode": "644"}
    assert r["check_errors"] == {"custom.keychain": "refused", "custom.home": "refused", "custom.dslocal": "refused", "custom.sneaky": "refused",
                                 "custom.semi": "refused", "custom.reg": "unsupported"}
    assert not app.exists()
