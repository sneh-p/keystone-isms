"""Deleting records created in error: allowed only while nothing depends on them; links cleaned up; audit-logged."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from keystone.assets import service as assets
from keystone.collab import service as collab
from keystone.core.audit import AuditLog
from keystone.core.deletion import DeleteRefused, delete_record
from keystone.core.rbac import PermissionDenied
from keystone.core.services import today
from keystone.incidents import service as incidents
from keystone.risk import service as risk
from keystone.tasks import service as tasks

from .conftest import api_login


def _asset(session, users, name="Laptop fleet"):
    return assets.save_asset(session, users["admin"], name=name, asset_type="hardware", classification="internal")


def test_risk_and_asset_rules(session, users):
    admin = users["admin"]
    a = _asset(session, users)
    r = risk.save_risk(session, admin, title="Lost laptop", category="technology", owner_id=users["risk_owner"].id, asset_ids=[a.id])
    with pytest.raises(DeleteRefused, match="risks are linked to it. Unlink it or set it to retired"):
        delete_record(session, admin, "asset", a.id)
    collab.add_comment(session, admin, "risk", r.id, "Created by mistake")
    with pytest.raises(PermissionDenied):
        delete_record(session, users["viewer"], "risk", r.id)
    r2 = risk.save_risk(session, admin, title="Accepted one", category="technology", owner_id=users["risk_owner"].id, inherent_likelihood=2, inherent_impact=2)
    risk.accept_risk(session, users["isms_manager"], r2.id, "Within appetite", today() + timedelta(days=90))
    with pytest.raises(DeleteRefused, match="risk acceptance on record. Close it instead"):
        delete_record(session, admin, "risk", r2.id)
    delete_record(session, admin, "risk", r.id)
    from keystone.collab.models import Comment

    assert session.scalars(select(Comment).where(Comment.entity_type == "risk", Comment.entity_id == r.id)).all() == []
    delete_record(session, admin, "asset", a.id)  # no longer linked
    assert session.scalars(select(AuditLog.summary).where(AuditLog.action == "delete", AuditLog.entity_type == "Risk")).first()


def test_asset_cleanup_and_incident_rules(session, users):
    from keystone.configcheck.models import ConfigTarget
    from keystone.continuity import service as continuity
    from keystone.core.db import utcnow

    admin = users["admin"]
    a = _asset(session, users)
    p = continuity.save_process(session, admin, name="Bookings", asset_ids=[a.id])
    t = ConfigTarget(kind="agent", platform="linux", name="h", facts={}, created_at=utcnow(), asset_id=a.id)
    session.add(t)
    session.flush()
    delete_record(session, admin, "asset", a.id)
    session.refresh(p)
    session.refresh(t)
    assert p.asset_ids == [] and t.asset_id is None
    inc = incidents.report_incident(session, admin, title="Phish", detected_at=datetime.now())
    inc.regulator_notified_at = datetime.now()
    session.flush()
    with pytest.raises(DeleteRefused, match="regulator notification"):
        delete_record(session, admin, "incident", inc.id)
    other = incidents.report_incident(session, admin, title="Duplicate", detected_at=datetime.now())
    delete_record(session, admin, "incident", other.id)


def test_task_rules(session, users):
    admin = users["admin"]
    t = tasks.save_task(session, admin, title="Collect logs")
    t.status = "done"
    session.flush()
    with pytest.raises(DeleteRefused, match="approved and its evidence filed. Mark it not relevant"):
        delete_record(session, admin, "task", t.id)
    t2 = tasks.save_task(session, admin, title="Typo")
    delete_record(session, admin, "task", t2.id)


def test_delete_routes(api, ready_users, db):
    api_login(api, ready_users["risk_owner"].username)
    rid = api.post("/api/risks", json={"title": "Oops", "category": "technology", "owner_id": ready_users["risk_owner"].id}).json()["id"]
    api.post("/api/auth/logout")
    api.cookies.clear()
    api_login(api, ready_users["viewer"].username)
    assert api.delete(f"/api/risks/{rid}").status_code == 403
    api.post("/api/auth/logout")
    api.cookies.clear()
    api_login(api, ready_users["risk_owner"].username)
    assert api.delete(f"/api/risks/{rid}").status_code == 200
    assert api.delete(f"/api/risks/{rid}").status_code == 404
