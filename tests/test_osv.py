"""Installed software from agents, and vulnerabilities from downloaded OSV data (decided 2026-11-21: download, match
locally)."""

import io
import json
import zipfile

import httpx
import pytest
from sqlalchemy import select

from keystone.asm import osv
from keystone.asm.models import AsmVulnerability
from keystone.configcheck.models import ConfigTarget
from keystone.core.db import utcnow
from keystone.integrations import http
from keystone.integrations import service as integ
from tests.conftest import api_login


@pytest.mark.parametrize("a,b,expected", [
    ("1.0", "1.0", 0), ("1.0~rc1", "1.0", -1), ("1:0.9", "2.0", 1), ("1.0-1", "1.0-1+deb12u1", -1), ("3.0.11-1~deb12u2", "3.0.11-1~deb12u1", 1),
    ("2.36-9+deb12u7", "2.36-9+deb12u10", -1), ("1.2.3", "1.2.3a", -1), ("1.10", "1.9", 1), ("0:1.0", "1.0", 0), ("1.0+b1", "1.0", 1),
])
def test_dpkg_order(a, b, expected):
    got = osv.dpkg_compare(a, b)
    assert (got > 0) - (got < 0) == expected


@pytest.mark.parametrize("a,b,expected", [
    ("1.0", "1.0", 0), ("1.0", "1.0.1", -1), ("1.0~rc1", "1.0", -1), ("1.0^git1", "1.0", 1), ("2.el9", "10.el9", -1), ("1:3.0.7-25.el9_3", "1:3.0.7-27.el9", -1),
    ("1:1.0-1", "0:2.0-1", 1), ("3.0.7-25.el9_3", "1:3.0.7-24.el9", -1), ("1.0a", "1.0b", -1), ("1.001", "1.1", 0),
])
def test_rpm_order(a, b, expected):
    got = osv.rpm_compare(a, b)
    assert (got > 0) - (got < 0) == expected


def test_releases():
    assert osv.release_of("debian", "12") == osv.Release("Debian:12", "Debian", "dpkg")
    assert osv.release_of("ubuntu", "24.04").ecosystem == "Ubuntu:24.04:LTS"
    assert osv.release_of("ubuntu", "24.10").ecosystem == "Ubuntu:24.10"
    assert osv.release_of("almalinux", "9.4").ecosystem == "AlmaLinux:9"
    assert osv.release_of("rocky", "8.10").ecosystem == "Rocky Linux:8"
    assert osv.release_of("windows", "10.0.26100") is None and osv.release_of("debian", "../12") is None and osv.release_of(None, None) is None


def _adv(id_, eco, name, events, aliases=(), **extra):
    return {"id": id_, "aliases": list(aliases), "summary": f"{name} problem", "affected": [{"package": {"ecosystem": eco, "name": name}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}], **extra}


def _zip(docs: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, doc in docs.items():
            z.writestr(name, doc if isinstance(doc, (str, bytes)) else json.dumps(doc))
    return buf.getvalue()


ARCHIVE = _zip({
    "DSA-5532-1.json": _adv("DSA-5532-1", "Debian:12", "openssl", [{"introduced": "0"}, {"fixed": "3.0.11-1~deb12u2"}], ["CVE-2023-5363"]),
    "DEBIAN-CVE-2023-5363.json": _adv("DEBIAN-CVE-2023-5363", "Debian:12", "openssl", [{"introduced": "0"}, {"fixed": "3.0.11-1~deb12u2"}]),
    "DEBIAN-CVE-2024-0001.json": _adv("DEBIAN-CVE-2024-0001", "Debian:12", "openssl", [{"introduced": "0"}]),  # no fix yet: not matched
    "DEBIAN-CVE-2024-0002.json": _adv("DEBIAN-CVE-2024-0002", "Debian:11", "openssl", [{"introduced": "0"}, {"fixed": "9"}]),  # another release
    "DEBIAN-CVE-2024-0003.json": _adv("DEBIAN-CVE-2024-0003", "Debian:12", "curl", [{"introduced": "0"}, {"fixed": "7.88.1-10+deb12u5"}], severity=[{"type": "Ubuntu", "score": "high"}]),
    "DEBIAN-CVE-2024-0004.json": {**_adv("DEBIAN-CVE-2024-0004", "Debian:12", "curl", [{"introduced": "0"}, {"fixed": "99"}]), "withdrawn": "2024-01-01T00:00:00Z"},
    "nested/DSA-1.json": _adv("DSA-1", "Debian:12", "curl", [{"introduced": "0"}, {"fixed": "99"}]),
    "broken.json": "{not json",
    "README.txt": "ignored",
})


def test_reading_an_archive(tmp_path):
    p = tmp_path / "Debian.zip"
    p.write_bytes(ARCHIVE)
    found = osv.read(p, {"Debian:12"}, {"Debian:12": {"openssl", "curl"}})
    assert sorted(a.id for a in found[("Debian:12", "openssl")]) == ["DEBIAN-CVE-2023-5363", "DSA-5532-1"]
    assert [(a.id, a.severity) for a in found[("Debian:12", "curl")]] == [("DEBIAN-CVE-2024-0003", "high")]
    assert osv.read(p, {"Debian:12"}, {"Debian:12": {"bash"}}) == {}
    (tmp_path / "bad.zip").write_bytes(b"not a zip")
    with pytest.raises(http.ConnectorError, match="damaged"):
        osv.read(tmp_path / "bad.zip", {"Debian:12"}, {})


def test_affected_ranges():
    ev = [[{"introduced": "0"}, {"fixed": "1.2-1"}], [{"introduced": "2.0-1"}, {"fixed": "2.0-5"}]]
    assert osv.affected("1.1-1", ev, "dpkg") == "1.2-1"
    assert osv.affected("1.2-1", ev, "dpkg") is None
    assert osv.affected("1.5-1", ev, "dpkg") is None
    assert osv.affected("2.0-3", ev, "dpkg") == "2.0-5"
    assert osv.affected("1:3.0.7-25.el9_3", [[{"introduced": "0"}, {"fixed": "1:3.0.7-27.el9"}]], "rpm") == "1:3.0.7-27.el9"


@pytest.fixture
def osv_server(monkeypatch):
    calls = []

    def handler(req: httpx.Request):
        calls.append((req.url.path, req.headers.get("if-none-match")))
        assert req.url.host == osv.OSV_HOST and req.method == "GET"
        if req.url.path != "/Debian/all.zip":
            return httpx.Response(404)
        if req.headers.get("if-none-match") == '"v1"':
            return httpx.Response(304)
        return httpx.Response(200, content=ARCHIVE, headers={"etag": '"v1"', "content-type": "application/zip"})
    monkeypatch.setattr(http, "TEST_TRANSPORT", httpx.MockTransport(handler))
    return calls


def test_download_only_when_changed_and_within_limits(db, osv_server, tmp_path):
    path = osv.fetch("Debian")
    assert path.read_bytes() == ARCHIVE and osv_server == [("/Debian/all.zip", None)]
    osv.fetch("Debian")
    assert osv_server[-1] == ("/Debian/all.zip", '"v1"') and path.read_bytes() == ARCHIVE  # unchanged: kept
    with pytest.raises(http.ConnectorError, match="larger"):
        http.Api(osv.OSV_POLICY).download(f"https://{osv.OSV_HOST}/Debian/all.zip", tmp_path / "x.zip", max_bytes=100)
    assert not (tmp_path / "x.zip").exists() and not (tmp_path / "x.zip.part").exists()
    with pytest.raises(ValueError):
        osv.fetch("../../etc")
    with pytest.raises(http.ConnectorError, match="Refused"):
        http.Api(osv.OSV_POLICY).download("https://evil.example/all.zip", tmp_path / "y.zip", max_bytes=100)


def _host(session, name, release, software):
    t = ConfigTarget(kind="agent", platform="linux", name=name, hostname=name, facts={}, created_at=utcnow(), os_release=release, software=software, software_at=utcnow())
    session.add(t)
    session.flush()
    return t


def test_agents_as_a_vulnerability_source(content, session, users, osv_server):
    _host(session, "web-01", "debian 12", [["openssl", "3.0.11-1~deb12u1"], ["curl", "7.88.1-10+deb12u5"], ["bash", "5.2.15-2+b2"]])
    _host(session, "web-02", "debian 12", [["openssl", "3.0.11-1~deb12u2"]])  # already fixed
    _host(session, "ws-01", "windows 10.0.26100", [["Google Chrome", "131.0"]])  # listed, not matched
    i = integ.save_integration(session, users["admin"], provider_key="keystone_agents", name="Keystone agents", values={})
    preview = integ.test(session, users["admin"], integration_id=i.id)
    assert len(preview) == 1 and "Nothing was downloaded" in preview[0]["summary"] and osv_server == []
    integ.run(session, users["admin"], i.id)
    rows = list(session.scalars(select(AsmVulnerability).where(AsmVulnerability.integration_id == i.id)))
    assert len(rows) == 1  # DSA and DEBIAN-CVE name the same CVE: recorded once
    v = rows[0]
    assert v.cve == "CVE-2023-5363" and v.state == "open" and "fixed in 3.0.11-1~deb12u2" in v.title and v.severity == "medium" and v.priority
    assert i.last_status == "ok"
    session.scalar(select(ConfigTarget).where(ConfigTarget.name == "web-01")).software = [["openssl", "3.0.11-1~deb12u2"]]
    integ.run(session, users["admin"], i.id)
    assert session.get(AsmVulnerability, v.id).state == "fixed"


def test_report_software_and_search(api, ready_users, db):
    api_login(api, "admin")
    key = api.get("/api/config/agent").json()["enrolment_key"]
    api.cookies.clear()
    api.headers.pop("X-CSRF-Token", None)
    token = api.post("/api/agent/v1/enrol", json={"enrolment_key": key, "hostname": "web-01", "platform": "linux"}).json()["token"]
    auth = {"Authorization": f"Bearer {token}"}
    body = {"facts": {}, "software": [["openssl", "3.0.11-1~deb12u1"], ["openssl", "3.0.11-1~deb12u1"], ["bad\x01", "1"], ["", "1"], ["zlib", "1:1.2.13"]],
            "os_release": {"id": "debian", "version_id": "12"}}
    assert api.post("/api/agent/v1/report", json=body, headers=auth).status_code == 200
    assert api.post("/api/agent/v1/report", json={"facts": {}, "software": [["a", "b", "c"]]}, headers=auth).status_code == 200  # dropped, not refused
    assert api.post("/api/agent/v1/report", json={"facts": {}, "software": "everything"}, headers=auth).status_code == 422
    big = {"facts": {}, "software": [[f"pkg{i}" + "x" * 150, "1.0"] for i in range(6000)]}
    assert api.post("/api/agent/v1/report", json=big, headers=auth).status_code in (413, 422)
    api.post("/api/agent/v1/report", json=body, headers=auth)
    api_login(api, "viewer")
    tid = api.get("/api/config/targets").json()[0]["id"]
    t = api.get(f"/api/config/targets/{tid}").json()
    assert t["software"] == [["openssl", "3.0.11-1~deb12u1"], ["zlib", "1:1.2.13"]] and t["os_release"] == "debian 12"
    found = api.get("/api/config/software", params={"q": "SSL"}).json()
    assert found["hosts"] == 1 and found["rows"] == [{"name": "openssl", "version": "3.0.11-1~deb12u1", "hosts": [{"id": tid, "name": "web-01", "platform": "linux"}]}]
    api.cookies.clear()
    assert api.get("/api/config/software").status_code == 401


def test_bad_os_release_is_dropped(api, ready_users, db):
    api_login(api, "admin")
    key = api.get("/api/config/agent").json()["enrolment_key"]
    api.cookies.clear()
    api.headers.pop("X-CSRF-Token", None)
    token = api.post("/api/agent/v1/enrol", json={"enrolment_key": key, "hostname": "web-01", "platform": "linux"}).json()["token"]
    api.post("/api/agent/v1/report", json={"facts": {}, "os_release": {"id": "debian; rm -rf", "version_id": "12"}}, headers={"Authorization": f"Bearer {token}"})
    with db.session_scope() as s:
        assert s.scalar(select(ConfigTarget)).os_release is None
