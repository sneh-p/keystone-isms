"""Guided tours: each user's own state, any role (employees included), never anyone else's."""

from keystone.collab.models import TourState

from .conftest import api_login


def test_tour_state_is_per_user(api, ready_users, db):
    assert api.get("/api/portal/tours").status_code == 401
    assert api.put("/api/portal/tours/app", json={"outcome": "completed"}).status_code in (401, 403)

    api_login(api, "riskowner")
    t = api.get("/api/portal/tours").json()
    assert t["app"] == {"version": 1, "seen": False, "outcome": None} and t["portal"]["seen"] is False
    r = api.put("/api/portal/tours/app", json={"outcome": "skipped"})
    assert r.status_code == 200 and r.json()["app"]["seen"] is True and r.json()["app"]["outcome"] == "skipped"
    assert api.put("/api/portal/tours/app", json={"outcome": "completed"}).json()["app"]["outcome"] == "completed"

    # Another user is unaffected, and an employee can record the portal tour.
    api_login(api, "employee")
    assert api.get("/api/portal/tours").json()["app"]["seen"] is False
    assert api.put("/api/portal/tours/portal", json={"outcome": "completed"}).json()["portal"]["seen"] is True

    # Showing it again removes the row; unknown tours, outcomes and extra fields are refused.
    api_login(api, "riskowner")
    assert api.put("/api/portal/tours/app", json={"outcome": None}).json()["app"] == {"version": 1, "seen": False, "outcome": None}
    assert api.put("/api/portal/tours/payroll", json={"outcome": "completed"}).status_code == 422
    assert api.put("/api/portal/tours/app", json={"outcome": "maybe"}).status_code == 422
    assert api.put("/api/portal/tours/app", json={"outcome": "completed", "user_id": 1}).status_code == 422
    with db.session_scope() as s:
        rows = {(r.user_id, r.tour) for r in s.query(TourState).all()}
    assert rows == {(ready_users["employee"].id, "portal")}


def test_a_newer_tour_version_is_shown_again(api, ready_users, monkeypatch):
    from keystone.collab import service as col

    api_login(api, "viewer")
    api.put("/api/portal/tours/app", json={"outcome": "completed"})
    monkeypatch.setitem(col.TOURS, "app", 2)
    assert api.get("/api/portal/tours").json()["app"] == {"version": 2, "seen": False, "outcome": "completed"}


def test_csrf_is_required(api, ready_users):
    api_login(api, "viewer")
    api.headers.pop("X-CSRF-Token")
    assert api.put("/api/portal/tours/app", json={"outcome": "completed"}).status_code == 403
