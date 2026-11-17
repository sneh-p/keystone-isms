"""Asset register depth (A.5.9-5.14): reviews, lifecycle dates, linked records, device links, offboarding."""

from datetime import date, timedelta

import pytest

from keystone.assets import service as assets
from keystone.asm.models import AsmDevice
from keystone.core.db import utcnow
from keystone.core.services import add_months, today
from keystone.incidents import service as incidents
from keystone.reporting.routing import routed_items
from keystone.risk import service as risk

from .conftest import api_login


def test_review_lifecycle_links_and_devices(session, users):
    admin = users["admin"]
    a = assets.save_asset(session, admin, name="booking-db", asset_type="hardware", classification="confidential", owner_id=users["risk_owner"].id,
                          review_date=today() + timedelta(days=3), acquired_on=date(2024, 1, 10))
    assert any("Review asset booking-db" in i["what"] for i in routed_items(session)[users["risk_owner"].id])
    a = assets.mark_reviewed(session, users["isms_manager"], a.id)
    assert a.review_date == add_months(today(), 12) and a.last_reviewed_at
    with pytest.raises(ValueError, match="Only retired assets"):
        assets.save_asset(session, admin, a.id, disposed_on=today())
    with pytest.raises(ValueError, match="before the acquisition"):
        assets.save_asset(session, admin, a.id, status="retired", disposed_on=date(2023, 1, 1))
    r = risk.save_risk(session, admin, title="DB theft", category="technology", owner_id=admin.id, asset_ids=[a.id])
    inc = incidents.report_incident(session, admin, title="Disk failure", detected_at=utcnow(), asset_ids=[a.id])
    dev = AsmDevice(name="BOOKING-DB.corp", hostname="booking-db", device_type="server", properties={}, first_seen=utcnow())
    other = AsmDevice(name="laptop-7", hostname="laptop-7", device_type="workstation", properties={}, first_seen=utcnow())
    session.add_all([dev, other])
    session.flush()
    links = assets.links(session, a.id)
    assert [x["id"] for x in links["risks"]] == [r.id] and [x["id"] for x in links["incidents"]] == [inc.id]
    assert [d["id"] for d in links["device_suggestions"]] == [dev.id]  # matched by host name, not the laptop
    assets.link_device(session, admin, a.id, dev.id)
    links = assets.links(session, a.id)
    assert [d["id"] for d in links["devices"]] == [dev.id] and links["device_suggestions"] == []
    assets.link_device(session, admin, a.id, dev.id, linked=False)
    assert assets.links(session, a.id)["devices"] == []


def test_asset_routes_and_offboarding(api, ready_users, db):
    from keystone.people.models import Person

    api_login(api, "admin")
    owner = ready_users["control_owner"]
    a = api.post("/api/assets", json={"name": "Laptop LT-17", "asset_type": "hardware", "owner_id": owner.id}).json()
    detail = api.get(f"/api/assets/{a['id']}").json()
    assert detail["links"]["risks"] == [] and detail["review_date"] is None
    assert api.post(f"/api/assets/{a['id']}/review").json()["review_date"]
    with db.session_scope() as s:
        p = Person(full_name="Leaver", email="leaver@example.org", employment_type="employee", status="offboarding", user_id=owner.id, offboarding={})
        s.add(p)
        s.flush()
        pid = p.id
    assert [x["name"] for x in api.get(f"/api/people/{pid}/assets").json()] == ["Laptop LT-17"]
    api.post("/api/auth/logout")
    api.cookies.clear()
    api_login(api, ready_users["viewer"].username)
    assert api.get(f"/api/assets/{a['id']}").status_code == 200
    assert api.post(f"/api/assets/{a['id']}/review").status_code == 403
