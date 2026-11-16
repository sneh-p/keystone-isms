"""Attack surface management core: ingest and matching, baselines, findings, exceptions, alerts, evidence, CSV."""

from datetime import date, datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from keystone.asm import baselines as bl
from keystone.asm.models import AsmDevice, AsmFinding, AsmIdentity, AsmVulnerability, Baseline
from keystone.asm.vocabulary import DeviceObs, IdentityObs, Inventory, SettingObs, VulnObs
from keystone.core import auth
from keystone.integrations import service as integ
from keystone.integrations.providers.base import ConfigField, InventoryProvider
from keystone.notifications.models import Notification

from .conftest import api_login

NOW = datetime.now(timezone.utc).replace(tzinfo=None)


class FakeSource(InventoryProvider):
    """Stands in for a real connector; the test sets `inv` before each run."""

    def __init__(self, key, category):
        self.key, self.name, self.category = key, key.upper(), category
        self.fields = (ConfigField("token", "Token", secret=True),)
        self.inv = Inventory()
        self.fail = None

    def collect(self, config, secrets):
        if self.fail:
            raise self.fail
        return self.inv


@pytest.fixture
def sources(monkeypatch, db, content):
    rmm, edr, vuln, idp = FakeSource("fakermm", "rmm"), FakeSource("fakeedr", "edr"), FakeSource("fakevuln", "vuln"), FakeSource("fakeidp", "identity")
    for p in (rmm, edr, vuln, idp):
        monkeypatch.setitem(integ.PROVIDERS, p.key, p)
    return {"rmm": rmm, "edr": edr, "vuln": vuln, "idp": idp}


def _connect(s, admin, src):
    return integ.save_integration(s, admin, provider_key=src.key, name=src.name, values={"token": "t"}).id


def _dev(ext, name, cat, **kw):
    return DeviceObs(external_id=ext, name=name, category=cat, last_seen=kw.pop("last_seen", NOW), **kw)


def test_devices_are_matched_across_tools_and_coverage_gaps_found(db, users, sources):
    admin = users["admin"]
    with db.session_scope(admin) as s:
        bl.add_recommended(s, admin)
        ids = {k: _connect(s, admin, v) for k, v in sources.items()}
        sources["rmm"].inv = Inventory(devices=[
            _dev("r1", "LAPTOP-01", "rmm", hostname="laptop-01.corp.example", serial="SN-AAA1", os="Windows 11", owner_email=admin.email or "ada@example.test", props={"disk_encrypted": True, "patches_pending": 0}),
            _dev("r2", "LAPTOP-02", "rmm", hostname="laptop-02", serial="SN-BBB2", os="Windows 11", props={"disk_encrypted": False}),
            _dev("r3", "SRV-01", "rmm", hostname="srv-01", os="Windows Server 2022", device_type="server"),
        ], complete={"devices"})
        integ.run(s, admin, ids["rmm"])
        # EDR reports laptop-01 by serial (different name) and laptop-02 by host name; srv-01 has no agent.
        sources["edr"].inv = Inventory(devices=[
            _dev("e-9", "Laptop01", "edr", serial="sn-aaa1", os="Windows", props={"edr_active": True, "av_up_to_date": True}),
            _dev("e-8", "LAPTOP-02", "edr", hostname="LAPTOP-02", props={"edr_active": False}),
        ], complete={"devices"})
        integ.run(s, admin, ids["edr"])
        devs = {d.name: d for d in s.scalars(select(AsmDevice))}
        assert len(devs) == 3  # matched, not duplicated
        l1 = devs["LAPTOP-01"]
        assert l1.properties["covered_by_edr"]["value"] is True and l1.properties["edr_active"]["source"] == "FAKEEDR"
        assert devs["SRV-01"].properties["covered_by_edr"]["value"] is False
        f = {(x.baseline_id, x.entity_id): x for x in s.scalars(select(AsmFinding).where(AsmFinding.status == "open"))}
        b = {x.name: x.id for x in s.scalars(select(Baseline))}
        assert (b["Devices have an EDR agent"], devs["SRV-01"].id) in f  # coverage gap
        assert (b["Disk encryption on"], devs["LAPTOP-02"].id) in f
        assert (b["EDR agent active and healthy"], devs["LAPTOP-02"].id) in f
        assert (b["Disk encryption on"], devs["LAPTOP-01"].id) not in f
        # srv-01 isn't in scope for disk encryption (workstations and mobiles only)
        assert (b["Disk encryption on"], devs["SRV-01"].id) not in f


def test_findings_resolve_and_partial_runs_never_retire(db, users, sources):
    admin = users["admin"]
    with db.session_scope(admin) as s:
        bl.add_recommended(s, admin)
        rid = _connect(s, admin, sources["rmm"])
        sources["rmm"].inv = Inventory(devices=[_dev("r2", "LAPTOP-02", "rmm", os="Windows 11", props={"disk_encrypted": False})], complete={"devices"})
        integ.run(s, admin, rid)
        enc = s.scalar(select(Baseline).where(Baseline.name == "Disk encryption on"))
        dev = s.scalar(select(AsmDevice))
        f = s.scalar(select(AsmFinding).where(AsmFinding.baseline_id == enc.id, AsmFinding.entity_id == dev.id))
        assert f.status == "open"
        sources["rmm"].inv = Inventory(devices=[_dev("r2", "LAPTOP-02", "rmm", os="Windows 11", props={"disk_encrypted": True})], complete={"devices"})
        integ.run(s, admin, rid)
        assert s.get(AsmFinding, f.id).status == "resolved"
        # A failed run changes nothing; a partial run (devices not complete) retires nothing.
        sources["rmm"].fail = ValueError("401 Unauthorized")
        integ.run(s, admin, rid)
        assert not s.get(AsmDevice, dev.id).retired
        sources["rmm"].fail = None
        sources["rmm"].inv = Inventory(devices=[], complete=set())
        integ.run(s, admin, rid)
        assert not s.get(AsmDevice, dev.id).retired
        sources["rmm"].inv = Inventory(devices=[], complete={"devices"})
        integ.run(s, admin, rid)
        assert s.get(AsmDevice, dev.id).retired  # fully listed and gone


def test_vulnerability_age_and_exploitability(db, users, sources):
    admin = users["admin"]
    with db.session_scope(admin) as s:
        bl.add_recommended(s, admin)
        vid = _connect(s, admin, sources["vuln"])
        old = date.today() - timedelta(days=20)
        sources["vuln"].inv = Inventory(devices=[_dev("v1", "WEB-01", "vuln", os="Ubuntu server", device_type="server")], vulns=[
            VulnObs("v1", "plugin-1", "OpenSSL RCE", "critical", cve="CVE-2026-0001", cvss=9.8, exploitable=True, first_seen=old),
            VulnObs("v1", "plugin-2", "Weak cipher", "medium", first_seen=old),
        ], complete={"devices", "vulns"})
        integ.run(s, admin, vid)
        d = s.scalar(select(AsmDevice))
        assert d.properties["critical_vulns"]["value"] == 1 and d.properties["oldest_critical_vuln_days"]["value"] == 20
        names = {s.get(Baseline, f.baseline_id).name for f in s.scalars(select(AsmFinding).where(AsmFinding.status == "open"))}
        assert {"Critical vulnerabilities fixed within 7 days", "No vulnerabilities with a known exploit"} <= names
        sources["vuln"].inv = Inventory(devices=[_dev("v1", "WEB-01", "vuln", os="Ubuntu server", device_type="server")], vulns=[], complete={"devices", "vulns"})
        integ.run(s, admin, vid)
        assert {v.state for v in s.scalars(select(AsmVulnerability))} == {"fixed"}
        assert s.scalar(select(AsmDevice)).properties["critical_vulns"]["value"] == 0


def test_identities_mfa_and_alerts(db, users, sources):
    admin = users["admin"]
    with db.session_scope(admin) as s:
        bl.add_recommended(s, admin)
        iid = _connect(s, admin, sources["idp"])
        viewer = s.get(auth.User, users["viewer"].id)
        viewer.email = "vic@example.test"
        sources["idp"].inv = Inventory(identities=[
            IdentityObs("vic@example.test", "Vic", {"mfa_registered": False, "account_enabled": True, "last_sign_in_days": 3}),
            IdentityObs("old@example.test", "Old", {"mfa_registered": False, "account_enabled": False}),
            IdentityObs("ok@example.test", "Ok", {"mfa_registered": True, "account_enabled": True}),
        ], complete={"identities"})
        integ.run(s, admin, iid)
        mfa = s.scalar(select(Baseline).where(Baseline.name.like("MFA registered%")))
        open_f = list(s.scalars(select(AsmFinding).where(AsmFinding.baseline_id == mfa.id, AsmFinding.status == "open")))
        assert [s.get(AsmIdentity, f.entity_id).upn for f in open_f] == ["vic@example.test"]  # disabled accounts out of scope
        # The account's owner is told (critical baseline).
        n = s.scalar(select(Notification).where(Notification.user_id == viewer.id, Notification.kind == "asm"))
        assert n and "MFA registered" in n.title


def test_exceptions_need_risk_accept_and_not_your_own(api, ready_users, db, sources):
    admin = ready_users["admin"]
    with db.session_scope(admin) as s:
        bl.add_recommended(s, admin)
        rid = _connect(s, admin, sources["rmm"])
        s.get(auth.User, ready_users["isms_manager"].id).email = "mgr@example.test"
        sources["rmm"].inv = Inventory(devices=[_dev("r1", "MGR-LAPTOP", "rmm", os="Windows 11", owner_email="mgr@example.test", props={"disk_encrypted": False})], complete={"devices"})
        integ.run(s, admin, rid)
        f = s.scalar(select(AsmFinding).join(Baseline).where(Baseline.name == "Disk encryption on", AsmFinding.status == "open"))
        fid = f.id
    until = (date.today() + timedelta(days=30)).isoformat()
    api_login(api, "viewer")
    assert api.post(f"/api/asm/findings/{fid}/exception", json={"reason": "x", "until": until}).status_code == 403
    api_login(api, "ismsmanager")
    r = api.post(f"/api/asm/findings/{fid}/exception", json={"reason": "Replacing laptop", "until": until})
    assert r.status_code == 400 and "own device" in r.json()["detail"]
    api_login(api, "admin")
    assert api.post(f"/api/asm/findings/{fid}/exception", json={"reason": "x", "until": (date.today() + timedelta(days=400)).isoformat()}).status_code == 400
    assert api.post(f"/api/asm/findings/{fid}/exception", json={"reason": "Replacing laptop next week", "until": until}).status_code == 200
    rows = api.get("/api/asm/findings", params={"status": "excepted"}).json()
    assert rows[0]["exception_reason"] == "Replacing laptop next week"
    # An expired exception reopens on the next evaluation.
    with db.session_scope() as s:
        s.get(AsmFinding, fid).exception_until = date.today() - timedelta(days=1)
        bl.evaluate(s)
        assert s.get(AsmFinding, fid).status == "open"


def test_met_baselines_file_evidence(db, users, sources):
    from keystone.controls.models import Evidence

    admin = users["admin"]
    with db.session_scope(admin) as s:
        bl.save_baseline(s, admin, name="Disk encryption on", entity="device", property="disk_encrypted", operator="is_true", value=None, scope={}, severity="high", controls=["KC-TEC-01"], missing="flag")
        rid = _connect(s, admin, sources["rmm"])
        sources["rmm"].inv = Inventory(devices=[_dev("r1", "A", "rmm", props={"disk_encrypted": True}), _dev("r2", "B", "rmm", props={"disk_encrypted": True})], complete={"devices"})
        integ.run(s, admin, rid)
        ev = s.scalar(select(Evidence).where(Evidence.title == "Attack surface baseline met: Disk encryption on"))
        assert ev and "2 device(s)" in ev.description


def test_csv_import_and_preview(api, ready_users, db, content):
    api_login(api, "admin")
    rows = [{"name": "KIOSK-01", "serial": "KSK0001", "os": "Windows 10", "device_type": "workstation", "disk_encrypted": "no", "edr_active": "yes"},
            {"name": "KIOSK-02", "serial": "KSK0002", "os": "Windows 10", "disk_encrypted": "maybe"}]
    r = api.post("/api/import/devices", json={"rows": rows})
    assert r.json()["errors"] == 1 and "yes or no" in r.json()["rows"][1]["errors"][0]
    with db.session_scope() as s:
        assert s.scalar(select(AsmDevice)) is None  # preview saves nothing
    rows[1]["disk_encrypted"] = "yes"
    api.post("/api/asm/baselines/recommended")
    assert api.post("/api/import/devices", json={"rows": rows, "preview": False}).status_code == 200
    devs = {d["name"]: d for d in api.get("/api/asm/devices").json()}
    assert devs["KIOSK-01"]["encrypted"] is False and devs["KIOSK-01"]["open_findings"] >= 1
    assert api.post("/api/import/devices", json={"rows": rows, "preview": False}).status_code == 200
    assert len(api.get("/api/asm/devices").json()) == 2  # re-import updates, doesn't duplicate
    ov = api.get("/api/asm/overview").json()
    assert ov["devices"] == 2 and ov["findings_total"] >= 1
    api_login(api, "riskowner")
    assert api.post("/api/import/devices", json={"rows": rows}).status_code == 403


def test_baseline_validation_and_permissions(api, ready_users, content):
    api_login(api, "controlowner")
    assert api.post("/api/asm/baselines/recommended").status_code == 403
    api_login(api, "admin")
    good = {"name": "Servers patched", "entity": "device", "property": "patches_pending", "operator": "lte", "value": "0", "scope": {"device_types": ["server"]}, "severity": "high", "controls": ["KC-TEC-08"], "missing": "ignore"}
    assert api.post("/api/asm/baselines", json=good).status_code == 200
    for bad in ({"property": "mfa_registered"}, {"operator": "is_true"}, {"value": "lots"}, {"severity": "urgent"}, {"scope": {"tags": ["x"]}}, {"controls": ["KC-NOPE"]},
                {"scope": {"device_types": ["toaster"]}}):
        assert api.post("/api/asm/baselines", json={**good, **bad}).status_code == 400, bad
    body = api.get("/api/asm/baselines").json()
    assert body["baselines"][0]["rule"].startswith("Security patches pending at most 0")
    api_login(api, "viewer")
    assert api.get("/api/asm/overview").status_code == 200
    api_login(api, "employee")
    assert api.get("/api/asm/overview").status_code == 403
