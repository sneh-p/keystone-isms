"""Customising configuration checks: custom checks (definition limits, the agent channel, the real Linux agent,
firewall probes), the library, scoping by tags and host-name patterns, per-rule tags, clone, export/import, bulk
exceptions, reset to recommended, asset links and the compliance report."""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import timedelta
from io import BytesIO
from pathlib import Path

import pytest
from openpyxl import load_workbook
from sqlalchemy import select

from keystone.configcheck import custom
from keystone.configcheck import service as cfg
from keystone.configcheck.models import ConfigFinding, ConfigRule, ConfigTarget
from keystone.core.db import utcnow
from keystone.core.rbac import PermissionDenied
from keystone.core.services import today

from .conftest import api_login

ROOT = Path(__file__).resolve().parents[1]
FIX = Path(__file__).parent / "fixtures" / "configcheck"
SH = shutil.which("sh") or "/bin/sh"


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    from keystone.trust import service as trust

    trust._hits.clear()
    yield
    trust._hits.clear()


def _target(session, platform="linux", name="web-01", facts=None, tags=None, kind="agent") -> ConfigTarget:
    t = ConfigTarget(kind=kind, platform=platform, name=name, hostname=name, facts=facts or {}, facts_at=utcnow(), created_at=utcnow(), tags=tags)
    session.add(t)
    session.flush()
    return t


def _status(session, t) -> dict[str, str]:
    rules = {r.id: r.key for r in session.scalars(select(ConfigRule))}
    return {rules[f.rule_id]: f.status for f in session.scalars(select(ConfigFinding).where(ConfigFinding.target_id == t.id))}


# ---------------------------------------------------------------- definitions


@pytest.mark.parametrize("platform,probe,params,vtype,message", [
    ("linux", "file_setting", {"path": "/etc/shadow", "key": "root", "separator": "colon"}, "str", "doesn't read this file"),
    ("linux", "file_contains", {"path": "/home/alice/.bashrc", "text": "x"}, "bool", "doesn't read this file"),
    ("linux", "file_setting", {"path": "/etc/ssl/private/server.key", "key": "a", "separator": "equals"}, "str", "doesn't read"),
    ("linux", "file_setting", {"path": "/etc/../etc/shadow", "key": "a", "separator": "equals"}, "str", "without '..'"),
    ("linux", "file_setting", {"path": "/etc/ssh/sshd_config;id", "key": "a", "separator": "equals"}, "str", "full path"),
    ("linux", "sysctl", {"key": "net.ipv4.ip_forward$(id)"}, "int", "aren't allowed"),
    ("linux", "file_mode", {"path": "/etc/shadow", "field": "mode"}, "int", "reports str"),
    ("linux", "registry_value", {"path": "SOFTWARE\\X", "name": "a", "mode": "value"}, "int", "isn't available for Linux"),
    ("windows", "registry_value", {"path": "SAM\\SAM\\Domains", "name": "F", "mode": "value"}, "str", "never read"),
    ("windows", "registry_value", {"path": "SOFTWARE\\..\\SECURITY", "name": "x", "mode": "value"}, "str", "under HKEY_LOCAL_MACHINE"),
    ("windows", "registry_value", {"path": "SOFTWARE\\X", "name": "a", "mode": "exists", "extra": "1"}, "bool", "Unexpected parameters"),
    ("windows", "run_command", {"command": "whoami"}, "str", "isn't available"),
    ("panos", "panos_xpath", {"path": "/config/../x", "mode": "text"}, "str", "aren't allowed"),
    ("cisco", "cisco_line", {"prefix": "login\nbad", "mode": "present"}, "bool", "aren't allowed"),
])
def test_definitions_are_limited(platform, probe, params, vtype, message):
    with pytest.raises(custom.CheckInvalid, match=message):
        custom.validate(platform, probe, params, vtype)


def test_metadata_probes_may_name_sensitive_paths_and_defaults_are_typed():
    clean, default = custom.validate("linux", "file_mode", {"path": "/etc/shadow", "field": "mode"}, "str")
    assert clean == {"path": "/etc/shadow", "field": "mode"} and default is None
    assert custom.validate("linux", "file_setting", {"path": "/etc/login.defs", "key": "PASS_MIN_DAYS", "separator": "whitespace"}, "int", "0")[1] == 0
    with pytest.raises(custom.CheckInvalid, match="whole number"):
        custom.validate("linux", "file_setting", {"path": "/etc/login.defs", "key": "PASS_MIN_DAYS", "separator": "whitespace"}, "int", "soon")
    with pytest.raises(custom.CheckInvalid, match="no default"):
        custom.validate("linux", "sysctl", {"key": "kernel.dmesg_restrict"}, "int", 1)


def test_library_entries_are_all_valid():
    entries = custom.library()
    assert len(entries) >= 25 and len({(e["platform"], e["slug"]) for e in entries}) == len(entries)
    for e in entries:
        custom.validate(e["platform"], e["probe"], e.get("params") or {}, e["type"], e.get("default"))
        assert custom.SLUG_RE.match(e["slug"]) and e["rule"]["severity"] in ("low", "medium", "high", "critical")


def test_glob_match_without_regex():
    assert cfg.glob_match("WEB-01.corp.example", "web-*")
    assert cfg.glob_match("db1", "db?") and not cfg.glob_match("db10", "db?")
    assert cfg.glob_match("anything", "*") and not cfg.glob_match("x", "")
    assert not cfg.glob_match("a" * 200, "*a*a*a*a*a*a*a*a*a*b")  # no pathological backtracking: returns at once


# ---------------------------------------------------------------- custom checks in rules and evaluation


def test_custom_check_lifecycle(content, session, users):
    admin = users["admin"]
    c = cfg.save_custom_check(session, admin, platform="linux", slug="max_tries", title="SSH MaxAuthTries", probe="file_setting",
                              params={"path": "/etc/ssh/sshd_config", "key": "MaxAuthTries", "separator": "whitespace"}, value_type="int", default_value=6,
                              recommended={"operator": "lte", "expected": 4, "severity": "medium", "controls": ["KC-TEC-05", "KC-NOPE-1"]})
    assert c.recommended == {"operator": "lte", "expected": 4, "severity": "medium", "controls": ["KC-TEC-05"]}  # unknown codes dropped
    with pytest.raises(ValueError, match="already"):
        cfg.save_custom_check(session, admin, platform="linux", slug="max_tries", title="x", probe="sysctl", params={"key": "a.b"}, value_type="int")
    with pytest.raises(PermissionDenied):
        cfg.save_custom_check(session, users["viewer"], platform="linux", slug="zz", title="x", probe="sysctl", params={"key": "a.b"}, value_type="int")
    b = cfg.create_baseline(session, admin, name="Linux", platform="linux", recommended=False)
    r = cfg.save_rule(session, admin, baseline_id=b.id, key="custom.max_tries")
    assert (r.operator, r.expected, r.severity, r.controls) == ("lte", 4, "medium", ["KC-TEC-05"])  # pre-filled from the check
    t = _target(session, facts={"custom.max_tries": 10})
    cfg.evaluate_target(session, t)
    assert _status(session, t) == {"custom.max_tries": "fail"}
    t.facts, t.check_errors = {}, {"custom.max_tries": "refused"}
    cfg.evaluate_target(session, t)
    f = cfg.findings(session, t.id)[0]
    assert f.status == "unknown" and "Refused by the agent" in f.detail
    t.check_errors, t.custom_checks = None, "disabled"
    cfg.evaluate_target(session, t)
    assert "turned off on this host" in cfg.findings(session, t.id)[0].detail
    with pytest.raises(ValueError, match="Rules in Linux use this check"):
        cfg.delete_custom_check(session, admin, c.id)
    with pytest.raises(ValueError, match="value type can't change"):
        cfg.save_custom_check(session, admin, c.id, probe="file_setting", params={"path": "/etc/ssh/sshd_config", "key": "MaxAuthTries", "separator": "whitespace"},
                              value_type="str")
    cfg.delete_rule(session, admin, r.id)
    cfg.delete_custom_check(session, admin, c.id)
    lib = cfg.add_from_library(session, admin, "suid_core_dumps_off")
    assert lib.probe == "sysctl" and lib.library_key == "suid_core_dumps_off"
    with pytest.raises(ValueError, match="already been added"):
        cfg.add_from_library(session, admin, "suid_core_dumps_off")


def test_scoping_by_tags_names_and_rule_tags(content, session, users):
    admin = users["admin"]
    default = cfg.create_baseline(session, admin, name="All Linux", platform="linux", recommended=False)
    cfg.save_rule(session, admin, baseline_id=default.id, key="aslr_full")
    web = cfg.create_baseline(session, admin, name="Web servers", platform="linux", recommended=False, scope={"tags": ["web"], "names": []})
    cfg.save_rule(session, admin, baseline_id=web.id, key="firewall_active")
    cfg.save_rule(session, admin, baseline_id=web.id, key="ip_forwarding_enabled", applies_to_tags=["dmz"])
    db = cfg.create_baseline(session, admin, name="Databases", platform="linux", recommended=False, scope={"tags": [], "names": ["db-*"]})
    cfg.save_rule(session, admin, baseline_id=db.id, key="root_fs_encrypted")
    facts = {"aslr_full": True, "firewall_active": True, "ip_forwarding_enabled": False, "root_fs_encrypted": False}
    plain = _target(session, name="app-01", facts=facts)
    tagged = _target(session, name="web-01", facts=facts, tags=["web"])
    dmz = _target(session, name="web-02", facts=facts, tags=["web", "dmz"])
    dbh = _target(session, name="DB-07.corp", facts=facts)
    for t in (plain, tagged, dmz, dbh):
        cfg.evaluate_target(session, t)
    assert set(_status(session, plain)) == {"aslr_full"}
    assert set(_status(session, tagged)) == {"aslr_full", "firewall_active"}
    assert set(_status(session, dmz)) == {"aslr_full", "firewall_active", "ip_forwarding_enabled"}
    assert _status(session, dbh) == {"aslr_full": "pass", "root_fs_encrypted": "fail"}
    assert [b["name"] for b in cfg.summary(session, dbh)["baselines"]] == ["All Linux", "Databases"]
    cfg.update_target(session, admin, plain.id, tags=["Web"])
    assert set(_status(session, plain)) == {"aslr_full", "firewall_active"}
    with pytest.raises(ValueError, match="isn't a tag"):
        cfg.update_target(session, admin, plain.id, tags=["no spaces"])
    with pytest.raises(ValueError, match="host-name pattern"):
        cfg.update_baseline(session, admin, db.id, scope={"names": ["db-[0-9]"]})
    cfg.update_target(session, admin, plain.id, baseline_id=web.id)  # pinned: no longer the default
    assert set(_status(session, plain)) == {"firewall_active"}


def test_clone_export_import_reset_and_bulk_exceptions(content, session, users):
    admin = users["admin"]
    cfg.save_custom_check(session, admin, platform="linux", slug="dmesg", title="dmesg restricted", probe="sysctl", params={"key": "kernel.dmesg_restrict"}, value_type="int")
    b = cfg.create_baseline(session, admin, name="Linux", platform="linux", scope={"tags": ["prod"], "names": ["srv-*"]})
    rule = cfg.save_rule(session, admin, baseline_id=b.id, key="custom.dmesg", operator="eq", expected=1, severity="low", remediation="Set kernel.dmesg_restrict = 1")
    fw = next(r for r in cfg.rules(session, b.id) if r.key == "firewall_active")
    cfg.save_rule(session, admin, rule_id=fw.id, severity="low", applies_to_tags=["edge"])
    copy = cfg.clone_baseline(session, admin, b.id)
    assert copy.name == "Linux (copy)" and not copy.is_default and len(cfg.rules(session, copy.id)) == len(cfg.rules(session, b.id))
    data = cfg.export_baseline(session, admin, b.id)
    assert data["custom_checks"][0]["slug"] == "dmesg" and data["baseline"]["scope"] == {"tags": ["prod"], "names": ["srv-*"]}
    imported, notes = cfg.import_baseline(session, admin, json.loads(json.dumps(data)))
    assert imported.name == "Linux (imported)" and any("reused" in n for n in notes)
    keys = {r.key: r for r in cfg.rules(session, imported.id)}
    assert keys["custom.dmesg"].remediation == "Set kernel.dmesg_restrict = 1" and keys["firewall_active"].applies_to_tags == ["edge"]
    data["custom_checks"][0]["params"] = {"key": "kernel.kptr_restrict"}
    with pytest.raises(ValueError, match="different custom check"):
        cfg.import_baseline(session, admin, data)
    with pytest.raises(ValueError, match="version 1"):
        cfg.import_baseline(session, admin, {"format": "other", "version": 1})
    restored = cfg.reset_rule(session, admin, fw.id)
    assert (restored.operator, restored.severity) == ("is_true", "high")
    t1 = _target(session, name="srv-1", facts={"custom.dmesg": 0})
    t2 = _target(session, name="srv-2", facts={"custom.dmesg": 0})
    for t in (t1, t2):
        cfg.evaluate_target(session, t)
    with pytest.raises(PermissionDenied):
        cfg.grant_exceptions(session, users["control_owner"], rule.id, None, "lab", today() + timedelta(days=10))
    assert cfg.grant_exceptions(session, users["isms_manager"], rule.id, [t1.id], "Lab host", today() + timedelta(days=10)) == 1
    by_rule = {(f.target_id, f.rule_id): f.status for f in session.scalars(select(ConfigFinding))}  # the copies share the scope, so check this rule
    assert by_rule[(t1.id, rule.id)] == "excepted" and by_rule[(t2.id, rule.id)] == "fail"


# ---------------------------------------------------------------- firewalls


def test_firewall_custom_checks_run_at_upload(content, session, users):
    admin = users["admin"]
    for slug in ("admin_lockout_threshold", "pre_login_banner"):
        cfg.add_from_library(session, admin, slug)
    cfg.save_custom_check(session, admin, platform="fortigate", slug="policy_count", title="Policies", probe="fortigate_setting",
                          params={"block": "firewall policy", "mode": "count"}, value_type="int")
    cfg.save_custom_check(session, admin, platform="fortigate", slug="hq_policy_log", title="Policy 1 logs", probe="fortigate_setting",
                          params={"block": "firewall policy", "edit": "1", "setting": "logtraffic", "mode": "value"}, value_type="str")
    cfg.save_custom_check(session, admin, platform="fortigate", slug="nothing_here", title="Absent", probe="fortigate_setting",
                          params={"block": "system dns", "setting": "primary", "mode": "value"}, value_type="str")
    for slug in ("login_block_for", "login_banner"):
        cfg.add_from_library(session, admin, slug)
    cfg.save_custom_check(session, admin, platform="cisco", slug="ntp_value", title="NTP server", probe="cisco_line", params={"prefix": "ntp server", "mode": "value"}, value_type="str")
    cfg.add_from_library(session, admin, "panos_login_banner")
    cfg.save_custom_check(session, admin, platform="panos", slug="rules", title="Rules", probe="panos_xpath", params={"path": "devices/entry/vsys/entry/rulebase/security/rules/entry", "mode": "count"},
                          value_type="int")
    cfg.save_custom_check(session, admin, platform="pfsense", slug="gui", title="GUI protocol", probe="pfsense_xpath", params={"path": "system/webgui/protocol", "mode": "text"}, value_type="str")
    t, _, _ = cfg.upload_firewall(session, admin, platform="fortigate", filename="f.conf", data=(FIX / "fortigate-weak.conf").read_bytes())
    assert {k: v for k, v in t.facts.items() if k.startswith("custom.")} == {"custom.admin_lockout_threshold": 3, "custom.pre_login_banner": "disable",
                                                                             "custom.policy_count": 3, "custom.hq_policy_log": "disable"}
    assert t.check_errors == {"custom.nothing_here": "missing"}
    c, _, _ = cfg.upload_firewall(session, admin, platform="cisco", filename="asa.txt", data=(FIX / "cisco-asa.txt").read_bytes())
    assert c.facts["custom.login_block_for"] is False and c.facts["custom.ntp_value"] == "198.51.100.123"
    p, _, _ = cfg.upload_firewall(session, admin, platform="panos", filename="p.xml", data=(FIX / "panos.xml").read_bytes())
    assert p.facts["custom.panos_login_banner"] is False and p.facts["custom.rules"] == 3
    f, _, _ = cfg.upload_firewall(session, admin, platform="pfsense", filename="c.xml", data=(FIX / "pfsense.xml").read_bytes())
    assert f.facts["custom.gui"] == "https"


# ---------------------------------------------------------------- API and the real Linux agent


def _anonymous(api):
    api.post("/api/auth/logout")
    api.cookies.clear()
    api.headers.pop("X-CSRF-Token", None)


def test_agent_channel_and_the_real_linux_agent(api, ready_users, db, tmp_path):
    api_login(api, "admin")
    key = api.get("/api/config/agent").json()["enrolment_key"]
    assert api.post("/api/config/baselines", json={"name": "Linux", "platform": "linux", "recommended": False}).status_code == 200
    bid = api.get("/api/config/baselines").json()[0]["id"]
    for body in (
        {"platform": "linux", "slug": "fwd", "title": "IP forwarding", "probe": "sysctl", "params": {"key": "net.ipv4.ip_forward"}, "value_type": "int",
         "recommended": {"operator": "eq", "expected": 0, "severity": "low", "controls": []}},
        {"platform": "linux", "slug": "passwd_mode", "title": "passwd mode", "probe": "file_mode", "params": {"path": "/etc/passwd", "field": "mode"}, "value_type": "str"},
        {"platform": "linux", "slug": "login_defs_umask", "title": "UMASK", "probe": "file_setting", "params": {"path": "/etc/login.defs", "key": "UMASK", "separator": "whitespace"},
         "value_type": "str", "default_value": "022"},
        {"platform": "linux", "slug": "missing_file", "title": "Missing", "probe": "file_contains", "params": {"path": "/etc/keystone-nope.conf", "text": "x"}, "value_type": "bool"},
    ):
        r = api.post("/api/config/custom-checks", json=body)
        assert r.status_code == 200, r.text
    assert api.post("/api/config/custom-checks", json={"platform": "linux", "slug": "shadow", "title": "x", "probe": "file_contains", "params": {"path": "/etc/shadow", "text": "root"},
                                                       "value_type": "bool"}).status_code == 400
    for k in ("custom.fwd", "custom.passwd_mode", "custom.login_defs_umask", "custom.missing_file"):
        assert api.post(f"/api/config/baselines/{bid}/rules", json={"key": k, "operator": "eq" if k != "custom.missing_file" else "is_false",
                                                                     "expected": {"custom.fwd": 0, "custom.passwd_mode": "644", "custom.login_defs_umask": "077"}.get(k)}).status_code == 200
    lib = api.get("/api/config/custom-checks").json()
    assert lib["probes"] and any(e["slug"] == "aide_installed" and not e["added"] for e in lib["library"])
    _anonymous(api)
    assert api.get("/api/agent/v1/checks").status_code == 401
    token = api.post("/api/agent/v1/enrol", json={"enrolment_key": key, "hostname": "ci-host", "platform": "linux", "tags": ["ci"]}).json()["token"]
    auth = {"Authorization": f"Bearer {token}"}
    as_json = api.get("/api/agent/v1/checks", headers=auth).json()["checks"]
    assert {c["key"] for c in as_json} == {"custom.fwd", "custom.passwd_mode", "custom.login_defs_umask", "custom.missing_file"}
    lines = api.get("/api/agent/v1/checks?format=lines", headers=auth).text
    assert lines.count("\n") == 4 and "custom.login_defs_umask\tfile_setting\tstr\t" in lines and "default=022" in lines
    defs = tmp_path / "checks.tsv"
    defs.write_text(lines)
    out = subprocess.run([SH, str(ROOT / "agents/linux/keystone-agent.sh"), "collect-custom", str(defs)], capture_output=True, text=True, timeout=120, check=True)
    report = json.loads(out.stdout)
    assert set(report["facts"]) == {"custom.fwd", "custom.passwd_mode", "custom.login_defs_umask"} and report["check_errors"] == {"custom.missing_file": "missing"}
    r = api.post("/api/agent/v1/report", json=report, headers=auth)
    assert r.status_code == 200 and r.json()["ignored"] == [], r.text
    with db.session_scope() as s:
        t = s.scalars(select(ConfigTarget)).one()
        assert t.tags == ["ci"] and t.check_errors == {"custom.missing_file": "missing"}
        st = _status(s, t)
        assert st["custom.passwd_mode"] == "pass" and st["custom.missing_file"] == "unknown"
    # A report may not invent check errors for keys it doesn't know, or error codes outside the list.
    bad = {"facts": {}, "check_errors": {"custom.nope": "refused", "custom.fwd": "exploded"}}
    api.post("/api/agent/v1/report", json=bad, headers=auth)
    with db.session_scope() as s:
        assert s.scalars(select(ConfigTarget)).one().check_errors is None


def test_api_customisation_routes(api, ready_users, db):
    from keystone.assets.models import Asset

    api_login(api, "admin")
    with db.session_scope() as s:
        s.add(Asset(name="web-01", asset_type="hardware", classification="internal", confidentiality=3, integrity=3, availability=3, status="active", contains_personal_data=False))
    b = api.post("/api/config/baselines", json={"name": "Linux", "platform": "linux", "scope": {"tags": ["web"], "names": []}}).json()
    assert b["scope"] == {"tags": ["web"], "names": []}
    exported = api.get(f"/api/config/baselines/{b['id']}/export")
    assert exported.status_code == 200 and "attachment" in exported.headers["content-disposition"]
    imported = api.post("/api/config/baselines/import", json=exported.json())
    assert imported.status_code == 200 and imported.json()["baseline"]["name"] == "Linux (imported)"
    assert api.post(f"/api/config/baselines/{b['id']}/clone", json={"name": "Linux strict"}).json()["name"] == "Linux strict"
    assert api.post("/api/config/custom-checks/library/aide_installed").status_code == 200
    assert api.post("/api/config/custom-checks/library/NOPE").status_code == 404
    key = api.get("/api/config/agent").json()["enrolment_key"]
    _anonymous(api)
    token = api.post("/api/agent/v1/enrol", json={"enrolment_key": key, "hostname": "web-01", "platform": "linux"}).json()["token"]
    api.post("/api/agent/v1/report", json={"facts": {"firewall_active": False, "aslr_full": True}}, headers={"Authorization": f"Bearer {token}"})
    api_login(api, "admin")
    tid = api.get("/api/config/targets").json()[0]["id"]
    detail = api.get(f"/api/config/targets/{tid}").json()
    assert detail["asset"] is None and detail["asset_suggestions"][0]["name"] == "web-01"
    assert api.patch(f"/api/config/targets/{tid}", json={"asset_id": detail["asset_suggestions"][0]["id"], "tags": ["web"]}).status_code == 200
    detail = api.get(f"/api/config/targets/{tid}").json()
    assert detail["asset"]["name"] == "web-01" and detail["tags"] == ["web"] and {x["baseline"] for x in detail["results"]} >= {"Linux"}
    failing = next(x for x in detail["results"] if x["key"] == "firewall_active")
    assert failing["status"] == "fail"
    until = (today() + timedelta(days=30)).isoformat()
    assert api.post(f"/api/config/rules/{failing['rule_id']}/exceptions", json={"reason": "Behind the edge firewall", "until": until}).json()["excepted"] == 1
    xl = api.get("/api/config/report.xlsx")
    assert xl.status_code == 200
    ws = load_workbook(BytesIO(xl.content)).active
    rows = list(ws.iter_rows(values_only=True))
    header_row = next(i for i, r in enumerate(rows) if r and r[0] == "Target")
    assert any(r[0] == "web-01" and r[5] == "Host firewall active" and r[9] == "excepted" for r in rows[header_row + 1:])
    _anonymous(api)
    api_login(api, ready_users["viewer"].username)
    assert api.get("/api/config/custom-checks").status_code == 200
    assert api.post("/api/config/custom-checks/library/kptr_restrict").status_code == 403
    assert api.get(f"/api/config/baselines/{b['id']}/export").status_code == 200  # read
    assert api.post("/api/config/baselines/import", json=exported.json()).status_code == 403
