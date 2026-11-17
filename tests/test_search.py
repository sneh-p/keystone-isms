"""Record search for the command palette: matching, references, literal wildcards, and who may search."""

from keystone.assets import service as assets
from keystone.reporting.search import search
from keystone.risk import service as risk

from .conftest import api_login


def test_search_matches_titles_refs_and_treats_wildcards_literally(content, session, users):
    admin = users["admin"]
    r = risk.save_risk(session, admin, title="Ransomware on the 100% booking platform", category="technology", owner_id=admin.id)
    assets.save_asset(session, admin, name="Booking_DB", asset_type="software", classification="internal")
    hits = search(session, admin, "booking")
    assert {h["kind"] for h in hits} >= {"risk", "asset"}
    assert search(session, admin, "100%")[0]["title"].startswith("Ransomware")
    assert [h["title"] for h in search(session, admin, "_DB")] == ["Booking_DB"]
    assert search(session, admin, "%") == [] and search(session, admin, "x") == []  # too short
    assert all(h["kind"] != "risk" for h in search(session, admin, "%%"))  # a literal %%, matching nothing
    by_ref = search(session, admin, r.ref)
    assert by_ref[0]["page"] == f"/risks?open={r.id}"
    controls = search(session, admin, "KC-TEC-05")
    assert controls[0]["kind"] == "control" and controls[0]["ref"] == "KC-TEC-05"


def test_search_route_is_for_staff(api, ready_users):
    api_login(api, ready_users["viewer"].username)
    assert api.get("/api/search?q=bo").status_code == 200
    api.post("/api/auth/logout")
    api.cookies.clear()
    api_login(api, ready_users["employee"].username)
    assert api.get("/api/search?q=bo").status_code == 403
