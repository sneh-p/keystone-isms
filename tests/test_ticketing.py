"""Ticketing: provider requests (mocked), permissions, one ticket per record, status sync, automatic tickets, API."""

from __future__ import annotations

import base64
import json
from datetime import date

import httpx
import pytest
from sqlalchemy import select

from keystone.asm.models import AsmDevice, AsmVulnerability
from keystone.integrations import http
from keystone.integrations import service as integ
from keystone.integrations.http import ConnectorError
from keystone.integrations.providers.ticketing import AutotaskProvider, ConnectWisePsaProvider, JiraProvider, ServiceNowProvider, Ticket
from keystone.ticketing import service as tk
from keystone.ticketing.models import TicketLink

from .conftest import api_login

JIRA = {"site_url": "https://acme.atlassian.net", "email": "keystone@acme.example", "project_key": "SEC", "api_token": "tok"}


@pytest.fixture
def remote(monkeypatch):
    """A tiny fake of all four systems. state['closed'] holds ids reported as closed."""
    state = {"calls": [], "closed": set(), "next": 100, "fail_create": False}

    def handler(req: httpx.Request) -> httpx.Response:
        state["calls"].append(req)
        host, path, m = req.url.host, req.url.path, req.method
        body = json.loads(req.content) if req.content else None
        if m == "POST" and state["fail_create"]:
            return httpx.Response(400, json={"errors": "nope"})
        if host.endswith(".atlassian.net"):
            if path == "/rest/api/3/myself":
                return httpx.Response(200, json={"displayName": "Keystone Bot"})
            if m == "POST" and path == "/rest/api/3/issue":
                state["next"] += 1
                return httpx.Response(201, json={"id": str(state["next"]), "key": f"SEC-{state['next']}"})
            if path.startswith("/rest/api/3/issue/"):
                iid = path.rsplit("/", 1)[1]
                return httpx.Response(200, json={"fields": {"status": {"statusCategory": {"key": "done" if iid in state["closed"] else "new"}}}})
        if host.endswith(".service-now.com"):
            if m == "POST":
                return httpx.Response(201, json={"result": {"sys_id": "a" * 32, "number": "INC0010001"}})
            if path.endswith("a" * 32):
                return httpx.Response(200, json={"result": {"active": "false" if "a" * 32 in state["closed"] else "true"}})
            return httpx.Response(200, json={"result": []})
        if host.endswith("myconnectwise.net"):
            if m == "POST":
                return httpx.Response(201, json={"id": 555})
            if path.endswith("/system/info"):
                return httpx.Response(200, json={"version": "v2026.1"})
            return httpx.Response(200, json={"closedFlag": "555" in state["closed"]})
        if host.endswith(".autotask.net"):
            if m == "POST":
                return httpx.Response(200, json={"itemId": 777})
            if "/Companies/" in path:
                return httpx.Response(200, json={"item": {"companyName": "Alpine"}})
            return httpx.Response(200, json={"item": {"status": 5 if "777" in state["closed"] else 1}})
        return httpx.Response(404)

    monkeypatch.setattr(http, "TEST_TRANSPORT", httpx.MockTransport(handler))
    return state


T = Ticket("Fix it", "Line one\nLine two")


def test_jira_request_shape(remote):
    p = JiraProvider()
    api, base = p.api(JIRA, {"api_token": "tok"}), p.base(JIRA)
    c = p.create(api, base, JIRA, T)
    assert (c.key, c.url) == ("SEC-101", "https://acme.atlassian.net/browse/SEC-101")
    req = remote["calls"][-1]
    assert req.headers["authorization"] == "Basic " + base64.b64encode(b"keystone@acme.example:tok").decode()
    fields = json.loads(req.content)["fields"]
    assert fields["project"] == {"key": "SEC"} and fields["issuetype"] == {"name": "Task"} and fields["description"]["type"] == "doc"
    assert p.is_closed(api, base, JIRA, "101") is False
    remote["closed"].add("101")
    assert p.is_closed(api, base, JIRA, "101") is True
    assert p.run(JIRA, {"api_token": "tok"})[0].summary == "Connected as Keystone Bot"
    with pytest.raises(ConnectorError):
        p.base({"site_url": "https://acme.atlassian.net.evil.example"})


def test_other_providers_request_shapes(remote):
    sn = {"instance_url": "https://acme.service-now.com", "username": "svc", "table": "incident"}
    p = ServiceNowProvider()
    c = p.create(p.api(sn, {"password": "pw"}), p.base(sn), sn, T)
    assert c.key == "INC0010001" and json.loads(remote["calls"][-1].content)["short_description"] == "Fix it"
    with pytest.raises(ConnectorError):
        p.create(p.api(sn, {}), p.base(sn), {**sn, "table": "sys_user"}, T)  # only incident or problem

    cw = {"site": "https://api-eu.myconnectwise.net", "company_id": "alpine", "public_key": "pub", "board_id": "12", "company_rec_id": "250"}
    p2 = ConnectWisePsaProvider()
    c = p2.create(p2.api(cw, {"private_key": "priv", "client_id": "cid"}), p2.base(cw), cw, T)
    req = remote["calls"][-1]
    assert c.key == "#555" and req.headers["clientid"] == "cid" and json.loads(req.content)["board"] == {"id": 12}
    assert req.headers["authorization"] == "Basic " + base64.b64encode(b"alpine+pub:priv").decode()

    at = {"zone_url": "https://webservices16.autotask.net", "username": "api@alpine", "company_id": "0"}
    p3 = AutotaskProvider()
    c = p3.create(p3.api(at, {"secret": "s", "integration_code": "ic"}), p3.base(at), at, T)
    req = remote["calls"][-1]
    assert c.key == "T777" and req.headers["apiintegrationcode"] == "ic" and json.loads(req.content)["companyID"] == 0
    remote["closed"].add("777")
    assert p3.is_closed(p3.api(at, {}), p3.base(at), at, "777")


@pytest.fixture
def jira(db, users, remote):
    with db.session_scope() as s:
        i = integ.save_integration(s, users["admin"], provider_key="jira", name="Jira", values=JIRA)
        return i.id


@pytest.fixture
def vuln(db):
    with db.session_scope() as s:
        d = AsmDevice(name="SRV-1", properties={})
        s.add(d)
        s.flush()
        v = AsmVulnerability(device_id=d.id, vuln_key="k", cve="CVE-2021-44228", title="Log4Shell", severity="critical", kev=True, priority="P1", fix_by=date(2026, 11, 30))
        s.add(v)
        s.flush()
        return v.id


def test_tickets_need_the_records_write_permission_and_are_one_per_record(db, users, jira, vuln, remote):
    from keystone.core.rbac import PermissionDenied

    with db.session_scope(users["control_owner"]) as s:
        link = tk.create_ticket(s, s.get(type(users["admin"]), users["control_owner"].id), jira, "vulnerability", vuln)
        assert link.external_key == "SEC-101" and link.created_by_id == users["control_owner"].id
        sent = json.loads(remote["calls"][-1].content)["fields"]
        assert sent["summary"] == "[P1] Log4Shell on SRV-1"
        with pytest.raises(ValueError, match="already has ticket SEC-101"):
            tk.create_ticket(s, users["control_owner"], jira, "vulnerability", vuln)
    for role in ("viewer", "auditor", "risk_owner"):
        with db.session_scope() as s, pytest.raises(PermissionDenied):
            tk.create_ticket(s, users[role], jira, "vulnerability", vuln)


def test_incident_tickets_carry_no_details(db, users, jira, remote):
    from keystone.incidents.models import Incident
    from keystone.core.db import utcnow

    with db.session_scope(users["admin"]) as s:
        inc = Incident(title="Phishing", description="Mia's mailbox: password reset for Raj Patel", severity="high", detected_at=utcnow())
        s.add(inc)
        s.flush()
        tk.create_ticket(s, users["admin"], jira, "incident", inc.id)
    text = remote["calls"][-1].content.decode()
    assert "Phishing" in text and "Raj Patel" not in text and "mailbox" not in text


def test_run_syncs_status_and_opens_automatic_tickets(db, users, jira, vuln, remote):
    from keystone.notifications.models import Notification

    with db.session_scope(users["control_owner"]) as s:
        tk.create_ticket(s, users["control_owner"], jira, "vulnerability", vuln)
    remote["closed"].add("101")
    with db.session_scope() as s:
        results = {r.check_key: r for r in integ.run(s, users["admin"], jira)}
        assert results["connection"].result == "pass" and "1 closed" in results["sync"].summary
    with db.session_scope() as s:
        link = s.scalars(select(TicketLink)).one()
        assert link.state == "closed" and link.closed_at
        note = s.scalars(select(Notification).where(Notification.kind == "ticket")).one()
        assert note.user_id == users["control_owner"].id and "SEC-101" in note.title
        # automatic tickets for P1 vulnerabilities, never twice for the same one
        d = s.scalars(select(AsmDevice)).first()
        for n in range(30):
            s.add(AsmVulnerability(device_id=d.id, vuln_key=f"auto{n}", title=f"KEV {n}", severity="high", kev=True, priority="P1"))
        integ.save_integration(s, users["admin"], jira, values={"auto_create": "known_exploited"})
    with db.session_scope() as s:
        out = {r.check_key: r for r in integ.run(s, users["admin"], jira)}["sync"].summary
        assert "opened 25 automatically" in out
    with db.session_scope() as s:
        assert "opened 5 automatically" in {r.check_key: r for r in integ.run(s, users["admin"], jira)}["sync"].summary
        assert s.scalars(select(TicketLink).where(TicketLink.automatic.is_(True))).all().__len__() == 30
    with db.session_scope() as s, pytest.raises(ValueError, match="listed options"):
        integ.save_integration(s, users["admin"], jira, values={"auto_create": "everything"})


def test_changing_the_site_drops_the_stored_token(db, users, jira):
    with db.session_scope() as s, pytest.raises(ValueError, match="enter the credentials again"):
        integ.save_integration(s, users["admin"], jira, values={"site_url": "https://other.atlassian.net"})


def test_ticket_api(api, ready_users, db, jira, vuln, remote):
    assert api.post("/api/tickets", json={"integration_id": jira, "kind": "vulnerability", "record_id": vuln}).status_code == 401
    api_login(api, ready_users["viewer"].username)
    assert api.get("/api/tickets/systems").json() == [{"id": jira, "name": "Jira", "provider": "jira"}]
    assert api.post("/api/tickets", json={"integration_id": jira, "kind": "vulnerability", "record_id": vuln}).status_code == 403
    assert api.post("/api/tickets", json={"integration_id": jira, "kind": "users", "record_id": 1}).status_code == 422
    api.post("/api/auth/logout")
    api_login(api, ready_users["control_owner"].username)
    remote["fail_create"] = True
    r = api.post("/api/tickets", json={"integration_id": jira, "kind": "vulnerability", "record_id": vuln})
    assert r.status_code == 502 and "refused" in r.json()["detail"]
    remote["fail_create"] = False
    r = api.post("/api/tickets", json={"integration_id": jira, "kind": "vulnerability", "record_id": vuln})
    assert r.status_code == 200 and r.json()["key"].startswith("SEC-")
    links = api.get(f"/api/tickets?kind=vulnerability&ids={vuln},999").json()
    assert [(x["record_id"], x["system"], x["state"]) for x in links] == [(vuln, "Jira", "open")]
    assert api.get("/api/tickets?kind=vulnerability&ids=1;drop").status_code == 422
    assert api.post("/api/tickets", json={"integration_id": jira, "kind": "vulnerability", "record_id": 999999}).status_code == 404
