"""HR system connectors (mocked) and how they update the People register."""

from __future__ import annotations

import base64
import json
from datetime import date, timedelta

import httpx
import pytest
from sqlalchemy import select

from keystone.integrations import http
from keystone.integrations import service as integ
from keystone.integrations.http import ConnectorError
from keystone.integrations.providers.hr import BambooHrProvider, HiBobProvider, HrPerson, HrResult, PersonioProvider
from keystone.people import hr_sync
from keystone.people.models import Person

TODAY = date(2026, 11, 16)


@pytest.fixture
def remote(monkeypatch):
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        if req.url.host == "api.bamboohr.com":
            return httpx.Response(200, json={"employees": [
                {"id": "7", "displayName": "Mia Novak", "workEmail": "mia@alpine.example", "jobTitle": "CISO", "department": "IT", "hireDate": "2020-01-06",
                 "terminationDate": "0000-00-00", "status": "Active", "employmentHistoryStatus": "Full-Time", "supervisorEmail": None},
                {"id": "8", "displayName": "Kai Freelancer", "workEmail": "kai@alpine.example", "employmentHistoryStatus": "Contractor", "status": "Active", "supervisorEmail": "mia@alpine.example"}]})
        if req.url.host == "api.personio.de":
            if req.url.path == "/v1/auth":
                return httpx.Response(200, json={"success": True, "data": {"token": "tok"}})
            return httpx.Response(200, json={"data": [{"type": "Employee", "attributes": {
                "id": {"value": 101}, "first_name": {"value": "Ana"}, "last_name": {"value": "Lopez"}, "email": {"value": "ana@alpine.example"},
                "position": {"value": "Receptionist"}, "department": {"value": {"type": "Department", "attributes": {"name": "Hotels"}}},
                "hire_date": {"value": "2026-12-01T00:00:00+01:00"}, "termination_date": {"value": None}, "status": {"value": "onboarding"},
                "employment_type": {"value": "internal"}, "supervisor": {"value": {"type": "Employee", "attributes": {"email": {"value": "mia@alpine.example"}}}}}}]})
        if req.url.host == "api.hibob.com":
            return httpx.Response(200, json={"employees": [{"id": "b1", "displayName": "Leo Leaver", "email": "leo@alpine.example",
                                                            "work": {"title": "Ski instructor", "department": "Ski school", "startDate": "2024-12-01"},
                                                            "internal": {"lifecycleStatus": "Terminated", "terminationDate": "2026-11-10"}}]})
        return httpx.Response(404)

    monkeypatch.setattr(http, "TEST_TRANSPORT", httpx.MockTransport(handler))
    return calls


def test_providers_map_only_work_fields(remote):
    r = BambooHrProvider().collect({"subdomain": "alpine"}, {"api_key": "k"})
    assert [p.email for p in r.people] == ["mia@alpine.example", "kai@alpine.example"] and r.complete
    assert r.people[0].start_date == date(2020, 1, 6) and r.people[0].end_date is None and r.people[1].employment_type == "contractor"
    req = remote[-1]
    assert req.headers["authorization"] == "Basic " + base64.b64encode(b"k:x").decode()
    assert "salary" not in json.dumps(json.loads(req.content)).lower()  # only the listed work fields are requested
    with pytest.raises(ConnectorError):
        BambooHrProvider().collect({"subdomain": "../evil"}, {"api_key": "k"})

    p = PersonioProvider().collect({"client_id": "c"}, {"client_secret": "s"}).people[0]
    assert (p.full_name, p.department, p.start_date, p.manager_email, p.employment_type) == ("Ana Lopez", "Hotels", date(2026, 12, 1), "mia@alpine.example", "employee")

    h = HiBobProvider().collect({"service_user_id": "svc"}, {"service_user_token": "t"}).people[0]
    assert h.left and h.end_date == date(2026, 11, 10)


def test_sync_adds_joiners_updates_and_offboards_leavers(users, session):
    from keystone.integrations.models import Integration
    from keystone.notifications.models import Notification

    i = Integration(provider="bamboohr", name="BambooHR", config={})
    session.add(i)
    existing = Person(full_name="Leo L.", email="LEO@alpine.example", status="active", employment_type="employee")
    session.add(existing)
    session.flush()
    people = [HrPerson("1", "Mia Novak", "mia@alpine.example", job_title="CISO", start_date=TODAY - timedelta(days=900)),
              HrPerson("2", "Kai New", "kai@alpine.example", manager_email="mia@alpine.example", start_date=TODAY + timedelta(days=14)),
              HrPerson("3", "Leo Leaver", "leo@alpine.example", end_date=TODAY - timedelta(days=1)),
              HrPerson("4", "Gone Before", "gone@alpine.example", left=True),
              HrPerson("5", "No Email", None)]
    out = hr_sync.sync(session, i, HrResult(people, True, {}), on=TODAY)
    assert out == {"read": 5, "added": 2, "updated": 1, "leavers": 1, "skipped_no_email": 1}
    by = {p.email: p for p in session.scalars(select(Person))}
    assert "gone@alpine.example" not in by  # left before Keystone knew them
    assert by["kai@alpine.example"].status == "onboarding" and by["kai@alpine.example"].manager_id == by["mia@alpine.example"].id
    leo = by["LEO@alpine.example"]
    assert leo.status == "offboarding" and leo.offboarding == {} and leo.full_name == "Leo Leaver" and leo.hr_external_id == "3"
    notes = session.scalars(select(Notification).where(Notification.key.like("hr-leaver:%"))).all()
    assert {n.user_id for n in notes} >= {users["admin"].id, users["isms_manager"].id}
    # a second run changes nothing and repeats no notification
    assert hr_sync.sync(session, i, HrResult(people, True, {}), on=TODAY) == {"read": 5, "added": 0, "updated": 0, "leavers": 0, "skipped_no_email": 1}
    assert len(session.scalars(select(Notification).where(Notification.key.like("hr-leaver:%"))).all()) == len(notes)


def test_integration_run_applies_people(db, users, remote):
    with db.session_scope() as s:
        i = integ.save_integration(s, users["admin"], provider_key="hibob", name="HiBob", values={"service_user_id": "svc", "service_user_token": "t"})
        iid = i.id
        s.add(Person(full_name="Leo", email="leo@alpine.example", status="active", employment_type="employee"))
    with db.session_scope() as s:
        r = {x.check_key: x for x in integ.run(s, users["admin"], iid)}
        assert r["people"].result == "pass" and "1 moved to offboarding" in r["people"].summary
    with db.session_scope() as s:
        assert s.scalars(select(Person)).one().status == "offboarding"
        tested = integ.test(s, users["admin"], integration_id=iid)
        assert tested[0]["result"] == "pass" and "Read 1 people" in tested[0]["summary"]
