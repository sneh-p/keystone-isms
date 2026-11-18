"""Vulnerability prioritisation: KEV and EPSS feeds (mocked), priorities, fix-by dates, policy, API."""

from __future__ import annotations

import gzip
import json
from datetime import date, timedelta

import httpx
import pytest
from sqlalchemy import select

from keystone.asm import vulnintel as vi
from keystone.asm.models import AsmDevice, AsmVulnerability, EpssScore, KevEntry
from keystone.integrations import http
from keystone.integrations.http import ConnectorError

from .conftest import api_login

TODAY = date(2026, 11, 16)
KEV = {"title": "CISA Catalog", "count": 2, "vulnerabilities": [
    {"cveID": "CVE-2024-0001", "vendorProject": "Acme", "product": "VPN", "vulnerabilityName": "Acme VPN RCE", "dateAdded": "2026-11-10", "dueDate": "2026-12-01", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2023-9999", "vendorProject": "Other", "product": "X", "vulnerabilityName": "Other", "dateAdded": "2023-01-01", "dueDate": "2023-02-01", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "not-a-cve"},
]}


def epss_file(rows: dict[str, float], day: str = "2026-11-16") -> bytes:
    body = f"#model_version:v2026.06.15,score_date:{day}T12:00:00Z\ncve,epss,percentile\n" + "".join(f"{c},{s},0.5\n" for c, s in rows.items())
    return gzip.compress(body.encode())


@pytest.fixture
def feeds(monkeypatch):
    """Mock the two public feeds. state['epss_days'] lists the days that exist; calls are recorded."""
    state = {"kev": KEV, "kev_status": 200, "epss": {"CVE-2024-0002": 0.42, "CVE-2024-0003": 0.01, "CVE-2099-0001": 0.9}, "epss_days": {"2026-11-16"}, "calls": []}

    def handler(req: httpx.Request) -> httpx.Response:
        state["calls"].append(str(req.url))
        if req.url.host == "www.cisa.gov":
            return httpx.Response(state["kev_status"], json=state["kev"])
        if req.url.host == "epss.empiricalsecurity.com":
            day = req.url.path.removeprefix("/epss_scores-").removesuffix(".csv.gz")
            if day in state["epss_days"]:
                return httpx.Response(200, content=epss_file(state["epss"], day))
            return httpx.Response(404)
        return httpx.Response(599)

    monkeypatch.setattr(http, "TEST_TRANSPORT", httpx.MockTransport(handler))
    return state


@pytest.fixture
def vulns(session):
    d = AsmDevice(name="LAPTOP-1", properties={})
    session.add(d)
    session.flush()
    seen = TODAY - timedelta(days=20)
    rows = {
        "kev": AsmVulnerability(device_id=d.id, vuln_key="a", cve="CVE-2024-0001", title="Acme VPN", severity="medium", first_seen=seen),
        "epss": AsmVulnerability(device_id=d.id, vuln_key="b", cve="CVE-2024-0002, CVE-2024-0003", title="Likely", severity="low", first_seen=seen),
        "exploit": AsmVulnerability(device_id=d.id, vuln_key="c", cve=None, title="Public exploit", severity="high", exploitable=True, first_seen=seen),
        "crit": AsmVulnerability(device_id=d.id, vuln_key="d", cve="CVE-2024-0003", title="Critical", severity="critical", first_seen=seen),
        "low": AsmVulnerability(device_id=d.id, vuln_key="e", cve=None, title="Low", severity="low", first_seen=seen),
    }
    session.add_all(rows.values())
    session.flush()
    return rows


def test_refresh_prioritises_and_sets_fix_by_dates(session, feeds, vulns):
    out = vi.refresh(session, today=TODAY)
    assert out["kev"] == 2 and out["epss"] == 2  # only the CVEs Keystone has; CVE-2099-0001 isn't kept
    assert set(session.scalars(select(EpssScore.cve))) == {"CVE-2024-0002", "CVE-2024-0003"}
    v = vulns
    assert (v["kev"].priority, v["epss"].priority, v["exploit"].priority, v["crit"].priority, v["low"].priority) == ("P1", "P2", "P2", "P3", "P4")
    assert v["kev"].kev and v["epss"].epss == pytest.approx(0.42)  # the highest score among its CVEs
    seen = TODAY - timedelta(days=20)
    # medium = 90 days, but known-exploited: 14 days from when it was added to KEV (later than first seen)
    assert v["kev"].fix_by == date(2026, 11, 10) + timedelta(days=14)
    assert v["crit"].fix_by == seen + timedelta(days=15) and v["low"].fix_by == seen + timedelta(days=180)
    s = vi.summary(session, TODAY)
    assert s["known_exploited"] == 1 and s["by_priority"] == {"P1": 1, "P2": 2, "P3": 1, "P4": 1}
    assert s["overdue"] == 1  # the critical one: first seen 20 days ago, 15-day deadline
    assert session.get(KevEntry, "CVE-2024-0001").ransomware is True


def test_epss_falls_back_to_yesterdays_file(session, feeds, vulns):
    feeds["epss_days"] = {"2026-11-15"}
    vi.refresh(session, today=TODAY)
    assert vi.policy(session).epss_score_date == date(2026, 11, 15)
    assert any(c.endswith("epss_scores-2026-11-16.csv.gz") for c in feeds["calls"])


def test_a_failing_feed_keeps_its_old_data_and_reports(session, feeds, vulns):
    vi.refresh(session, today=TODAY)
    feeds["kev_status"] = 500
    feeds["epss"]["CVE-2024-0003"] = 0.5
    with pytest.raises(ConnectorError, match="KEV"):
        vi.refresh(session, today=TODAY)
    assert session.scalar(select(KevEntry.cve).where(KevEntry.cve == "CVE-2024-0001"))  # still there
    assert vulns["kev"].priority == "P1"
    assert vulns["crit"].priority == "P2"  # EPSS still refreshed: 0.5 is above the threshold
    assert "KEV" in vi.policy(session).last_error


def test_disabled_feeds_make_no_requests(session, feeds, vulns):
    p = vi.policy(session)
    p.kev_enabled = p.epss_enabled = False
    vi.refresh(session, today=TODAY)
    assert feeds["calls"] == []
    assert vulns["kev"].priority == "P4" and vulns["exploit"].priority == "P2"


def test_policy_changes_move_deadlines(users, session, feeds, vulns):
    vi.refresh(session, today=TODAY)
    vi.update_policy(session, users["admin"], sla_critical=30, epss_threshold=0.5)
    assert vulns["crit"].fix_by == TODAY - timedelta(days=20) + timedelta(days=30)
    assert vulns["epss"].priority == "P4"  # 0.42 is now below the threshold
    with pytest.raises(ValueError):
        vi.update_policy(session, users["admin"], sla_high=0)
    from keystone.core.rbac import PermissionDenied

    with pytest.raises(PermissionDenied):
        vi.update_policy(session, users["control_owner"], sla_high=10)


def test_feed_parsers_refuse_bad_input(monkeypatch):
    with pytest.raises(ConnectorError):
        vi.parse_kev({"vulnerabilities": "nope"})
    with pytest.raises(ConnectorError):
        vi.parse_kev({"vulnerabilities": [{"cveID": "bad"}]})
    with pytest.raises(ConnectorError, match="decompressed"):
        vi.parse_epss(b"not gzip", set())
    with pytest.raises(ConnectorError, match="format"):
        vi.parse_epss(gzip.compress(b"a,b\n1,2\n"), set())
    monkeypatch.setattr(vi, "MAX_EPSS_UNCOMPRESSED", 1000)
    with pytest.raises(ConnectorError, match="larger"):  # a small download that inflates past the cap
        vi.parse_epss(gzip.compress(b"cve,epss,percentile\n" + b"0" * 5000), set())
    assert vi.cves_of("cve-2024-1234, CVE-2023-00001; junk") == ["CVE-2023-00001", "CVE-2024-1234"]


def test_vulnerability_api(api, ready_users, db, feeds):
    with db.session_scope() as s:
        d = AsmDevice(name="SRV-1", properties={})
        s.add(d)
        s.flush()
        s.add(AsmVulnerability(device_id=d.id, vuln_key="a", cve="CVE-2024-0001", title="Acme VPN", severity="medium", first_seen=TODAY))
        vi.refresh(s, today=TODAY)
    assert api.get("/api/asm/vulnerabilities").status_code == 401
    api_login(api, ready_users["viewer"].username)
    body = api.get("/api/asm/vulnerabilities?kev=true").json()
    assert [i["priority"] for i in body["items"]] == ["P1"] and body["items"][0]["ransomware"] is True
    assert api.get("/api/asm/vulnerabilities?priority=P9").status_code == 422
    assert api.put("/api/asm/vuln-policy", json={"sla_high": 10}).status_code == 403
    assert api.post("/api/asm/vuln-intel/refresh").status_code == 403
    api.post("/api/auth/logout")
    api_login(api, "admin")
    r = api.put("/api/asm/vuln-policy", json={"sla_kev": 7})
    assert r.status_code == 200 and r.json()["sla_kev"] == 7
    assert api.put("/api/asm/vuln-policy", json={"sla_kev": 0}).status_code == 422
    assert api.put("/api/asm/vuln-policy", json={"last_error": "x"}).status_code == 422  # read-only fields refused
    from keystone.core.services import today

    feeds["epss_days"].add(today().isoformat())  # the route refreshes as of the real date, not TODAY
    assert api.post("/api/asm/vuln-intel/refresh").status_code == 200
    feeds["kev_status"] = 503
    r = api.post("/api/asm/vuln-intel/refresh")
    assert r.status_code == 502 and "KEV" in r.json()["detail"]
    assert json.dumps(api.get("/api/asm/vuln-policy").json()).count("KEV") >= 1


def test_connector_client_handles_compressed_responses(monkeypatch):
    """Real APIs send Content-Encoding: gzip; the client must decode once (this broke every live connector)."""
    payload = json.dumps({"ok": True, "items": list(range(100))}).encode()

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Encoding": "gzip", "Content-Type": "application/json"}, content=gzip.compress(payload))

    monkeypatch.setattr(http, "TEST_TRANSPORT", httpx.MockTransport(handler))
    api = http.Api(http.HostPolicy(hosts=frozenset({"api.example.com"})))
    assert api.json("GET", "https://api.example.com/x") == {"ok": True, "items": list(range(100))}
