"""Access review campaigns: scope, reviewer assignment and segregation of duties, decisions, revocation, completion."""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from sqlalchemy import select

from keystone.access_reviews import service as ar
from keystone.access_reviews.models import AccessReviewItem
from keystone.core.auth import User
from keystone.core.rbac import PermissionDenied

from .conftest import api_login

DUE = date.today() + timedelta(days=14)


@pytest.fixture
def org(db, users):
    """People: the control owner reports to the risk owner; an Entra identity for the viewer, one admin, one disabled."""
    from keystone.asm.models import AsmIdentity
    from keystone.people.models import Person

    with db.session_scope() as s:
        boss = Person(full_name="Risk Owner", email="ro@alpine.example", status="active", employment_type="employee", user_id=users["risk_owner"].id)
        s.add(boss)
        s.flush()
        s.add(Person(full_name="Control Owner", email="co@alpine.example", status="active", employment_type="employee", user_id=users["control_owner"].id, manager_id=boss.id))
        s.add(AsmIdentity(source="entra", upn="sam@alpine.example", display_name="Sam", user_id=users["viewer"].id, properties={"is_admin": True, "last_sign_in_days": 3, "account_enabled": True}))
        s.add(AsmIdentity(source="entra", upn="old@alpine.example", display_name="Old", properties={"account_enabled": False}))
    return users


def test_campaign_scope_and_reviewers(db, org):
    mgr = org["isms_manager"]
    with db.session_scope(mgr) as s:
        r = ar.start(s, mgr, "Q4 access review", ["keystone", "identities"], DUE)
        its = {i.subject: i for i in s.scalars(select(AccessReviewItem).where(AccessReviewItem.review_id == r.id))}
        co = next(i for k, i in its.items() if k.startswith("Control Owner") or "controlowner" in k)
        assert co.reviewer_id == org["risk_owner"].id  # their manager
        mine = next(i for i in its.values() if i.user_id == mgr.id)
        assert mine.reviewer_id != mgr.id  # nobody reviews their own access
        sam = next(i for i in its.values() if i.source == "identities")
        assert "administrator" in sam.access and "last sign-in 3 days ago" in sam.access
        assert not any("old@alpine.example" in k for k in its)  # disabled accounts aren't reviewed
    with db.session_scope() as s, pytest.raises(ValueError, match="six months"):
        ar.start(s, mgr, "x", ["keystone"], date.today())
    with db.session_scope() as s, pytest.raises(PermissionDenied):
        ar.start(s, org["control_owner"], "x", ["keystone"], DUE)


def test_decisions_revocation_and_completion(db, org, content):
    from keystone.controls.models import Evidence
    from keystone.tasks.models import Task

    mgr, ro = org["isms_manager"], org["risk_owner"]
    with db.session_scope(mgr) as s:
        rid = ar.start(s, mgr, "Q4", ["keystone", "identities"], DUE).id
    with db.session_scope() as s:
        its = list(s.scalars(select(AccessReviewItem).where(AccessReviewItem.review_id == rid)))
        co_item = next(i for i in its if i.user_id == org["control_owner"].id)
        with pytest.raises(PermissionDenied):  # not the assigned reviewer
            ar.decide(s, mgr, co_item.id, "keep")
        with pytest.raises(ValueError, match="Say what"):
            ar.decide(s, ro, co_item.id, "revoke")
        ar.decide(s, ro, co_item.id, "revoke", "Moved to marketing; no longer needs control access")
        with pytest.raises(ValueError, match="still need a decision"):
            ar.complete(s, mgr, rid)
        for i in its:
            if i.decision is None:
                reviewer = s.get(User, i.reviewer_id)
                ar.decide(s, reviewer, i.id, "change" if i.source == "identities" else "keep", "Remove admin role" if i.source == "identities" else None)
    with db.session_scope() as s:
        with pytest.raises(PermissionDenied):
            ar.apply_revocation(s, mgr, co_item.id)  # users.manage needed
        ar.apply_revocation(s, org["admin"], co_item.id)
        assert s.get(User, org["control_owner"].id).active is False
        r = ar.complete(s, mgr, rid)
        assert r.status == "completed"
        task = s.scalars(select(Task).where(Task.title.like("Carry out access review%"))).one()
        assert "CHANGE: Sam" in task.description and "Moved to marketing" not in task.description  # applied revocations don't need a task
        assert len(s.scalars(select(Evidence).where(Evidence.title.like("Access review AR-%"))).all()) == 2
        with pytest.raises(ValueError, match="closed"):
            ar.decide(s, ro, co_item.id, "keep")


def test_access_review_api_and_routing(api, ready_users, db, org):
    from keystone.reporting.routing import routed_items

    api_login(api, ready_users["isms_manager"].username)
    r = api.post("/api/access-reviews", json={"title": "Q4", "sources": ["keystone"], "due_date": DUE.isoformat()})
    assert r.status_code == 200
    rid = r.json()["id"]
    assert api.post("/api/access-reviews", json={"title": "x", "sources": ["everything"], "due_date": DUE.isoformat()}).status_code == 400
    with db.session_scope() as s:
        routed = routed_items(s)
        assert any("Review" in it["what"] and "Q4" in it["what"] for it in routed[ready_users["risk_owner"].id])
    api.post("/api/auth/logout")
    api_login(api, ready_users["risk_owner"].username)
    mine = api.get(f"/api/access-reviews/{rid}/items?mine=true").json()
    assert mine and all(i["reviewer_id"] == ready_users["risk_owner"].id for i in mine)
    assert api.post(f"/api/access-reviews/items/{mine[0]['id']}/decide", json={"decision": "maybe"}).status_code == 422
    assert api.post(f"/api/access-reviews/items/{mine[0]['id']}/decide", json={"decision": "keep"}).status_code == 200
    assert api.post(f"/api/access-reviews/{rid}/complete").status_code == 403
