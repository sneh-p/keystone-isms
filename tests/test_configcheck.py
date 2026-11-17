"""Configuration baselines: catalogue, firewall parsers, evaluation (unknown is never a pass), drift, exceptions,
evidence, alerts, agent enrolment and reports, firewall uploads, and the real Linux agent run against the API."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from keystone.configcheck import catalogue as cat
from keystone.configcheck import parsers
from keystone.configcheck import service as cfg
from keystone.configcheck.models import ConfigFinding, ConfigRule, ConfigSnapshot, ConfigTarget
from keystone.core.db import utcnow
from keystone.core.rbac import PermissionDenied
from keystone.core.services import today

from .conftest import api_login

ROOT = Path(__file__).resolve().parents[1]
FIX = Path(__file__).parent / "fixtures" / "configcheck"
SH = shutil.which("sh") or "/bin/sh"
SECRETS_IN_FIXTURES = ("SH2FAKEFORTIGATEHASH", "FAKEPRIVATEKEYMATERIAL", "PANOSFAKEHASH", "FakeEnablePassword123", "FAKEVTYPASSWORD", "FAKEASAHASH", "FAKEPFSENSEHASH")


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    from keystone.trust import service as trust

    trust._hits.clear()
    yield
    trust._hits.clear()


def fixture(name: str) -> bytes:
    return (FIX / name).read_bytes()


# ---------------------------------------------------------------- catalogue


def test_catalogue_is_consistent(content, session):
    from keystone.frameworks.models import CommonControl

    codes = set(session.scalars(select(CommonControl.code)))
    for s in cat.SETTINGS:
        assert s.type in cat.TYPES and s.platforms and set(s.platforms) <= set(cat.PLATFORMS), s.key
        if s.recommended:
            op, expected, severity, controls = s.recommended
            assert op in cat.OPERATORS_BY_TYPE[s.type] and severity in cat.SEVERITIES, s.key
            assert set(controls) <= codes, (s.key, set(controls) - codes)
        if s.requires:
            for p in s.platforms:
                req = cat.setting(p, s.requires)
                assert req is not None and req.type == "bool", s.key
    for p in cat.PLATFORMS:
        assert any(s.recommended for s in cat.settings_for(p)), p


def _ps_keys() -> set[str]:
    text = (ROOT / "agents/windows/keystone-agent.ps1").read_text()
    keys = set(re.findall(r"\$facts\['([a-z0-9_]+)'\]", text))
    keys |= {f"firewall_{n}_enabled" for n in ("domain", "private", "public")}  # built from the profile name
    return keys


def _sh_keys() -> set[str]:
    return set(re.findall(r"\badd ([a-z0-9_]+) (?:bool|int|str)\b", (ROOT / "agents/linux/keystone-agent.sh").read_text()))


def test_agents_send_exactly_the_catalogue_keys():
    for platform, keys in (("windows", _ps_keys()), ("linux", _sh_keys())):
        known = {s.key for s in cat.settings_for(platform)}
        assert keys == known, (platform, keys ^ known)


# ---------------------------------------------------------------- firewall parsers


def test_fortigate_parser():
    weak = parsers.parse("fortigate", fixture("fortigate-weak.conf"))
    assert weak.hostname == "FGT-FICTIONAL-HQ" and weak.version == "7.2.5"
    assert weak.facts == {"firmware_version": "7.2.5", "mgmt_http_enabled": True, "mgmt_telnet_enabled": True, "mgmt_access_restricted": False,
                          "admin_mfa_all": False, "ntp_configured": False, "remote_logging": False, "any_any_allow_rules": 1, "rules_without_logging": 1,
                          "admin_timeout_minutes": 480, "strong_crypto": False, "snmp_default_community": True}
    good = parsers.parse("fortigate", fixture("fortigate-hardened.conf")).facts
    assert good["mgmt_http_enabled"] is False and good["mgmt_access_restricted"] is True and good["admin_mfa_all"] is True
    assert good["ntp_configured"] is True and good["remote_logging"] is True and good["any_any_allow_rules"] == 0 and good["strong_crypto"] is True
    assert good["snmp_default_community"] is False and good["admin_timeout_minutes"] == 10


def test_panos_parser():
    p = parsers.parse("panos", fixture("panos.xml"))
    assert p.hostname == "PA-FICTIONAL-01" and p.version == "10.2.9"
    assert p.facts == {"firmware_version": "10.2.9", "mgmt_telnet_enabled": False, "mgmt_http_enabled": True, "mgmt_access_restricted": False,
                       "ntp_configured": True, "remote_logging": True, "any_any_allow_rules": 1, "rules_without_logging": 1, "admin_timeout_minutes": 60}


def test_cisco_parsers():
    ios = parsers.parse("cisco", fixture("cisco-ios.txt"))
    assert ios.hostname == "RTR-FICTIONAL-EDGE" and ios.version == "15.2"
    assert ios.facts == {"firmware_version": "15.2", "mgmt_http_enabled": True, "mgmt_telnet_enabled": True, "mgmt_access_restricted": False,
                         "admin_timeout_minutes": 100_000, "ssh_v2_only": False, "password_encryption": False, "enable_secret_used": False,
                         "aaa_enabled": False, "ntp_configured": False, "remote_logging": False, "any_any_allow_rules": 1, "snmp_default_community": True}
    asa = parsers.parse("cisco", fixture("cisco-asa.txt"))
    assert asa.hostname == "ASA-FICTIONAL" and asa.version == "9.16(4)"
    assert asa.facts == {"firmware_version": "9.16(4)", "mgmt_http_enabled": False, "mgmt_telnet_enabled": False, "mgmt_access_restricted": True,
                         "ssh_v2_only": True, "password_encryption": True, "enable_secret_used": True, "aaa_enabled": True, "admin_timeout_minutes": 10,
                         "ntp_configured": True, "remote_logging": True, "any_any_allow_rules": 0, "snmp_default_community": False}


def test_pfsense_parser():
    p = parsers.parse("pfsense", fixture("pfsense.xml"))
    assert p.hostname == "pf-fictional.example.org"
    assert p.facts == {"mgmt_telnet_enabled": False, "mgmt_http_enabled": False, "ntp_configured": True, "remote_logging": True,
                       "any_any_allow_rules": 1, "rules_without_logging": 1, "snmp_default_community": False}  # SNMP isn't enabled
    opn = parsers.parse("pfsense", b"<opnsense><system><hostname>opn</hostname><webgui><protocol>http</protocol></webgui></system>"
                                   b"<OPNsense><Syslog><destinations><destination><enabled>1</enabled></destination></destinations></Syslog></OPNsense></opnsense>")
    assert opn.facts["mgmt_http_enabled"] is True and opn.facts["remote_logging"] is True and "any_any_allow_rules" not in opn.facts


@pytest.mark.parametrize("platform,data,message", [
    ("pfsense", "xxe.xml", "DTD"),
    ("panos", b"<config", "valid XML"),
    ("fortigate", b"just some text\n", "FortiGate"),
    ("cisco", b"\x00\x01binary", "binary"),
    ("pfsense", b"<other/>", "pfSense"),
    ("fortigate", b"", "empty"),
    ("juniper", b"x", "Choose"),
])
def test_parsers_refuse_bad_input(platform, data, message):
    raw = fixture(data) if isinstance(data, str) else data
    with pytest.raises(parsers.ParseError, match=message):
        parsers.parse(platform, raw)
    with pytest.raises(parsers.ParseError, match="10 MB"):
        parsers.parse("cisco", b"x" * (parsers.MAX_BYTES + 1))


# ---------------------------------------------------------------- evaluation


def _agent(session, platform="linux", facts=None, name="host-1") -> ConfigTarget:
    t = ConfigTarget(kind="agent", platform=platform, name=name, hostname=name, facts=facts or {}, facts_at=utcnow() if facts is not None else None, created_at=utcnow())
    session.add(t)
    session.flush()
    return t


def _statuses(session, t) -> dict[str, str]:
    rules = {r.id: r.key for r in session.scalars(select(ConfigRule))}
    return {rules[f.rule_id]: f.status for f in session.scalars(select(ConfigFinding).where(ConfigFinding.target_id == t.id))}


def test_unknown_is_never_a_pass_and_prerequisites_make_rules_not_applicable(content, session, users):
    b = cfg.create_baseline(session, users["admin"], name="Linux servers", platform="linux")
    assert b.is_default and len(cfg.rules(session, b.id)) == sum(1 for s in cat.settings_for("linux") if s.recommended)
    t = _agent(session, facts={"firewall_active": True, "ssh_server_installed": False, "uid0_accounts": "0", "aslr_full": "maybe", "time_sync_active": False})
    out = cfg.evaluate_target(session, t)
    st = _statuses(session, t)
    assert st["firewall_active"] == "pass" and st["uid0_accounts"] == "pass"  # "0" is coerced to a number
    assert st["ssh_permit_root_login"] == "na" and st["ssh_password_authentication"] == "na"  # no SSH server
    assert st["aslr_full"] == "unknown" and st["auditd_running"] == "unknown"  # unreadable and missing: unknown
    assert st["time_sync_active"] == "fail"
    assert out["pass"] == 2 and out["fail"] == 1 and out["na"] == 2
    t.facts = {**t.facts, "ssh_server_installed": None}
    cfg.evaluate_target(session, t)
    assert _statuses(session, t)["ssh_permit_root_login"] == "unknown"  # prerequisite unknown: so is the rule
    s = cfg.summary(session, t)
    assert s["state"] == "failing" and s["score"] is not None and s["score"] < 100


def test_rule_operators_and_validation(content, session, users):
    b = cfg.create_baseline(session, users["admin"], name="Custom", platform="linux", recommended=False)
    r = cfg.save_rule(session, users["admin"], baseline_id=b.id, key="ssh_permit_root_login", operator="in", expected=["no", "Prohibit-Password"], severity="high", controls=["KC-TEC-02"])
    assert r.expected == ["no", "prohibit-password"]
    cfg.save_rule(session, users["admin"], baseline_id=b.id, key="password_max_days", operator="lte", expected="365", severity="low")
    t = _agent(session, facts={"ssh_server_installed": True, "ssh_permit_root_login": "PROHIBIT-PASSWORD", "password_max_days": 99999})
    cfg.evaluate_target(session, t)
    st = _statuses(session, t)
    assert st == {"ssh_permit_root_login": "pass", "password_max_days": "fail"}
    f = next(f for f in cfg.findings(session, t.id) if f.status == "fail")
    assert f.detail == "Reported 99999; required: at most 365."
    for kwargs, msg in (({"key": "nope"}, "not a Linux setting"), ({"key": "firewall_active", "operator": "gte"}, "use: is on, is off"),
                        ({"key": "uid0_accounts", "operator": "lte", "expected": "many"}, "whole number"), ({"key": "aslr_full", "severity": "urgent"}, "Severity"),
                        ({"key": "aslr_full", "controls": ["KC-NOPE-1"]}, "Unknown control"), ({"key": "password_max_days"}, "already has")):
        with pytest.raises(ValueError, match=msg):
            cfg.save_rule(session, users["admin"], baseline_id=b.id, **{"operator": None, "severity": "medium", **kwargs})
    with pytest.raises(PermissionDenied):
        cfg.save_rule(session, users["viewer"], baseline_id=b.id, key="aslr_full")


def test_drift_history_exceptions_alerts_and_evidence(content, session, users):
    from keystone.controls.models import Evidence
    from keystone.notifications.models import Notification

    b = cfg.create_baseline(session, users["admin"], name="Linux", platform="linux", recommended=False)
    cfg.save_rule(session, users["admin"], baseline_id=b.id, key="firewall_active", severity="critical", controls=["KC-TEC-20"])
    cfg.save_rule(session, users["admin"], baseline_id=b.id, key="aslr_full", severity="low", controls=["KC-TEC-09"])
    t = _agent(session, facts={"firewall_active": True, "aslr_full": True})
    cfg.evaluate_target(session, t)
    assert cfg.file_evidence(session) == 2
    ev = session.scalars(select(Evidence).where(Evidence.title == "Configuration baseline met: Linux")).all()
    assert len(ev) == 2 and all(e.valid_until == today() + timedelta(days=3) for e in ev)

    t.facts = {"firewall_active": False, "aslr_full": True}
    cfg.evaluate_target(session, t, source="agent")
    snap = session.scalars(select(ConfigSnapshot).where(ConfigSnapshot.target_id == t.id).order_by(ConfigSnapshot.id.desc())).first()
    assert snap.changes == [{"key": "firewall_active", "from": "pass", "to": "fail", "value_from": True, "value_to": False}]
    notes = session.scalars(select(Notification).where(Notification.kind == "config")).all()
    assert notes and notes[0].user_id == users["isms_manager"].id and "critical" in notes[0].title  # managers are alerted
    assert cfg.file_evidence(session) == 0  # a failing target: no evidence

    f = next(f for f in cfg.findings(session, t.id) if f.status == "fail")
    with pytest.raises(PermissionDenied):
        cfg.grant_exception(session, users["control_owner"], f.id, "x", today() + timedelta(days=30))
    with pytest.raises(ValueError, match="within a year"):
        cfg.grant_exception(session, users["isms_manager"], f.id, "Lab host", today() + timedelta(days=400))
    cfg.grant_exception(session, users["isms_manager"], f.id, "Lab host behind a network firewall", today() + timedelta(days=30))
    cfg.evaluate_target(session, t)
    assert _statuses(session, t)["firewall_active"] == "excepted"  # still failing, under an exception
    assert cfg.file_evidence(session) == 2
    f.exception_until = today() - timedelta(days=1)
    assert cfg.housekeeping(session)["lapsed"] == 1
    assert _statuses(session, t)["firewall_active"] == "fail"
    t.facts = {"firewall_active": True, "aslr_full": True}
    cfg.evaluate_target(session, t)
    assert set(_statuses(session, t).values()) == {"pass"}


def test_baseline_assignment_default_and_deletion(content, session, users):
    a = cfg.create_baseline(session, users["admin"], name="Workstations", platform="windows")
    b = cfg.create_baseline(session, users["admin"], name="Servers", platform="windows", recommended=False)
    assert a.is_default and not b.is_default
    t = _agent(session, platform="windows", facts={"uac_enabled": True})
    assert cfg.effective_baseline(session, t).id == a.id
    cfg.update_target(session, users["admin"], t.id, baseline_id=b.id)
    assert cfg.findings(session, t.id) == []  # Servers has no rules
    with pytest.raises(ValueError, match="same platform"):
        cfg.update_target(session, users["admin"], t.id, baseline_id=cfg.create_baseline(session, users["admin"], name="L", platform="linux").id)
    cfg.update_baseline(session, users["admin"], b.id, is_default=True)
    session.refresh(a)
    assert not a.is_default
    cfg.delete_baseline(session, users["admin"], b.id)
    session.refresh(t)
    assert t.baseline_id is None and cfg.effective_baseline(session, t) is None
    assert cfg.summary(session, t)["state"] == "no_baseline"


# ---------------------------------------------------------------- API: agents


def _admin(api, ready_users):
    api_login(api, "admin")
    return api.get("/api/config/agent").json()


def _anonymous(api):
    api.post("/api/auth/logout")
    api.cookies.clear()
    api.headers.pop("X-CSRF-Token", None)


def test_enrolment_and_reports(api, ready_users, db):
    view = _admin(api, ready_users)
    key = view["enrolment_key"]
    assert key.startswith("kenr_") and "KEYSTONE_ENROLMENT_KEY" in view["install"]["linux"] and key in view["install"]["windows"]
    assert api.post("/api/config/baselines", json={"name": "Linux", "platform": "linux"}).status_code == 200
    _anonymous(api)

    body = {"enrolment_key": "kenr_wrong", "hostname": "web-01", "platform": "linux"}
    assert api.post("/api/agent/v1/enrol", json=body).status_code == 401
    assert api.post("/api/agent/v1/enrol", json={**body, "enrolment_key": key, "hostname": "bad host;rm"}).status_code == 422
    assert api.post("/api/agent/v1/enrol", json={**body, "enrolment_key": key, "platform": "macos"}).status_code == 400
    r = api.post("/api/agent/v1/enrol", json={**body, "enrolment_key": key, "os_name": "Ubuntu"})
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    assert token.startswith("kagt_")

    report = {"hostname": "web-01", "facts": {"firewall_active": True, "uid0_accounts": 2, "invented_key": True, "aslr_full": "yes"}}
    assert api.post("/api/agent/v1/report", json=report).status_code == 401
    assert api.post("/api/agent/v1/report", json=report, headers={"Authorization": "Bearer kst_personal"}).status_code == 401
    assert api.post("/api/agent/v1/report", json=report, headers={"Authorization": "Bearer " + key}).status_code == 401  # the enrolment key can't report
    r = api.post("/api/agent/v1/report", json=report, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    assert r.json()["accepted"] == 3 and r.json()["ignored"] == ["invented_key"]
    big = {"facts": {"firewall_tool": "x" * 300_000}}
    assert api.post("/api/agent/v1/report", content=json.dumps(big), headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}).status_code == 413

    def chunked():  # no Content-Length: the streamed read still stops at the cap
        yield json.dumps(big).encode()

    assert api.post("/api/agent/v1/report", content=chunked(), headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}).status_code == 413
    # The token is only good for reporting: not for the staff API.
    assert api.get("/api/config/targets", headers={"Authorization": f"Bearer {token}"}).status_code == 401

    with db.session_scope() as s:
        t = s.scalars(select(ConfigTarget)).one()
        assert token not in (t.token_hash or "") and t.token_hash and t.facts == {"firewall_active": True, "uid0_accounts": 2, "aslr_full": True}
        assert _statuses(s, t)["uid0_accounts"] == "fail"
        from keystone.configcheck.models import ConfigAgentSettings

        assert key not in (s.scalars(select(ConfigAgentSettings)).one().enrollment_key_enc or "")
        from keystone.core.audit import AuditLog

        logged = " ".join(s.scalars(select(AuditLog.summary)))
        assert token not in logged and key not in logged and "Agent enrolled: web-01" in logged

    api_login(api, "admin")
    targets = api.get("/api/config/targets").json()
    assert targets[0]["state"] == "failing" and targets[0]["counts"]["fail"] >= 1
    detail = api.get(f"/api/config/targets/{targets[0]['id']}").json()
    assert detail["results"][0]["status"] == "fail" and detail["history"]
    rotated = api.post("/api/config/agent/rotate").json()["enrolment_key"]
    assert rotated != key
    assert api.post(f"/api/config/targets/{targets[0]['id']}/revoke").status_code == 200
    _anonymous(api)
    assert api.post("/api/agent/v1/report", json=report, headers={"Authorization": f"Bearer {token}"}).status_code == 401  # revoked
    assert api.post("/api/agent/v1/enrol", json={**body, "enrolment_key": key}).status_code == 401  # the old key no longer enrols


def test_agent_endpoints_are_rate_limited(api, ready_users):
    key = _admin(api, ready_users)["enrolment_key"]
    _anonymous(api)
    body = {"enrolment_key": key, "hostname": "h", "platform": "linux"}
    token = api.post("/api/agent/v1/enrol", json=body).json()["token"]
    codes = [api.post("/api/agent/v1/report", json={"facts": {}}, headers={"Authorization": f"Bearer {token}"}).status_code for _ in range(31)]
    assert codes[:30] == [200] * 30 and codes[30] == 429
    codes = [api.post("/api/agent/v1/enrol", json={**body, "enrolment_key": "kenr_x"}).status_code for _ in range(30)]
    assert codes[-1] == 429


def test_downloads_and_permissions(api, ready_users):
    _admin(api, ready_users)
    r = api.get("/api/config/agent/download/linux")
    assert r.status_code == 200 and r.text.startswith("#!/bin/sh") and "attachment" in r.headers["content-disposition"]
    assert api.get("/api/config/agent/download/windows").text.lstrip("﻿").startswith("<#")
    assert api.get("/api/config/agent/download/macos").status_code == 404
    _anonymous(api)
    api_login(api, ready_users["auditor"].username)
    assert api.get("/api/config/overview").status_code == 200  # read
    assert api.get("/api/config/agent").status_code == 403  # the enrolment key is for administrators
    assert api.get("/api/config/agent/download/linux").status_code == 403


# ---------------------------------------------------------------- API: firewall uploads


def test_firewall_upload_never_stores_the_file_or_its_secrets(api, ready_users, db):
    _admin(api, ready_users)
    assert api.post("/api/config/baselines", json={"name": "FortiGate", "platform": "fortigate"}).status_code == 200
    data = fixture("fortigate-weak.conf")
    r = api.post("/api/config/firewalls", data={"platform": "fortigate"}, files={"file": ("backup.conf", data, "text/plain")})
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["target"]["name"] == "FGT-FICTIONAL-HQ" and res["result"]["fail"] >= 8
    tid = res["target"]["id"]
    again = api.post("/api/config/firewalls", data={"platform": "fortigate", "target_id": str(tid)}, files={"file": ("new.conf", fixture("fortigate-hardened.conf"), "text/plain")}).json()
    assert again["target"]["id"] == tid and again["result"]["fail"] < res["result"]["fail"]
    hist = api.get(f"/api/config/targets/{tid}").json()["history"]
    assert any(c["key"] == "strong_crypto" and c["to"] == "pass" for c in hist[0]["changes"])
    assert api.post("/api/config/firewalls", data={"platform": "panos", "target_id": str(tid)}, files={"file": ("x.xml", fixture("panos.xml"), "text/xml")}).status_code == 400
    assert api.post("/api/config/firewalls", data={"platform": "pfsense"}, files={"file": ("x.xml", fixture("xxe.xml"), "text/xml")}).status_code == 400
    for name in ("panos.xml", "cisco-ios.txt", "cisco-asa.txt", "pfsense.xml"):
        platform = {"panos.xml": "panos", "pfsense.xml": "pfsense"}.get(name, "cisco")
        assert api.post("/api/config/firewalls", data={"platform": platform}, files={"file": (name, fixture(name), "text/plain")}).status_code == 200
    # Nothing from the files' secret material is anywhere in the database.
    from keystone.core.db import Base

    with db.session_scope() as s:
        dump = []
        for name in ("config_targets", "config_findings", "config_snapshots", "audit_log", "attachments"):
            dump += [json.dumps([str(v) for v in row]) for row in s.execute(select(Base.metadata.tables[name]))]
        blob = "\n".join(dump)
    for secret in SECRETS_IN_FIXTURES:
        assert secret not in blob, secret


# ---------------------------------------------------------------- the real Linux agent


def test_linux_agent_collects_this_host_and_its_report_is_accepted(api, ready_users, db):
    out = subprocess.run([SH, str(ROOT / "agents/linux/keystone-agent.sh"), "collect"], capture_output=True, text=True, timeout=120, check=True)
    report = json.loads(out.stdout)
    assert report["agent_version"] and report["hostname"] and report["facts"]
    known = {s.key: s for s in cat.settings_for("linux")}
    for k, v in report["facts"].items():
        assert k in known and cat.clean_value(known[k], v) == v, (k, v)  # every value already has the catalogue type
    key = _admin(api, ready_users)["enrolment_key"]
    api.post("/api/config/baselines", json={"name": "Linux", "platform": "linux"})
    _anonymous(api)
    token = api.post("/api/agent/v1/enrol", json={"enrolment_key": key, "hostname": "ci-host", "platform": "linux"}).json()["token"]
    r = api.post("/api/agent/v1/report", json=report, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and r.json()["ignored"] == [], r.text
    with db.session_scope() as s:
        t = s.scalars(select(ConfigTarget)).one()
        assert t.facts == report["facts"] and _statuses(s, t)


def test_linux_agent_refuses_plain_http_to_remote_servers(tmp_path):
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "KEYSTONE_AGENT_CONF_DIR": str(tmp_path)}
    (tmp_path / "agent.conf").write_text("SERVER=http://keystone.example.org\n")
    r = subprocess.run([SH, str(ROOT / "agents/linux/keystone-agent.sh"), "status"], capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode != 0 and "https://" in r.stderr
