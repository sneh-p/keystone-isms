"""Phase 6: exposure importer and classification."""

import json

import pytest
from sqlalchemy import select

from keystone.core.rbac import PermissionDenied
from keystone.tprm.exposure import classification, importer
from keystone.tprm.exposure.models import AppExposure, ConsentPosture, ExposureSnapshot, TenantApp
from keystone.tprm.exposure.schema import CollectedFileInvalid

MS = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
TENANT = "10d5462f-38da-515b-a569-c7498116626c"


@pytest.mark.parametrize(
    "owner,sp_type,expected",
    [
        (MS, "Application", ("microsoft", False)),
        ("72F988BF-86F1-41AF-91AB-2D7CD011DB47", "Application", ("microsoft", False)),
        (TENANT, "Application", ("internal", False)),
        ("22222222-2222-4222-8222-222222222222", "Application", ("third_party", False)),
        (None, "Legacy", ("unknown", True)),
        (None, "ManagedIdentity", ("internal", False)),
    ],
)
def test_classify(owner, sp_type, expected):
    assert classification.classify(owner, TENANT, sp_type) == expected


def _import(session, actor, doc, name="Alpine Ski House"):
    return importer.import_document(session, actor, doc, create_tenant_name=name)


def _apps(session, snapshot_id):
    return {a.display_name: a for a in session.scalars(select(TenantApp).where(TenantApp.snapshot_id == snapshot_id))}


def test_import_tenant_a(users, session, tenant_a):
    res = _import(session, users["isms_manager"], tenant_a)
    apps = _apps(session, res.snapshot_id)
    assert res.apps == len(tenant_a["service_principals"])
    assert res.by_class == {"microsoft": 4, "third_party": 7, "internal": 2, "unknown": 1}
    assert apps["Microsoft Graph"].owner_class == "microsoft"
    assert apps["Legacy Print Connector"].owner_class == "unknown" and apps["Legacy Print Connector"].needs_review
    assert apps["ash-automation-mi"].owner_class == "internal"
    nw = apps["Northwind Signatures"]
    assert nw.publisher_verified and nw.reply_url_domains == ["app.northwindsignatures.example", "www.northwindsignatures.example"]
    assert {(p.permission_type, p.value, p.tier) for p in nw.permissions} == {("application", "User.Read.All", "medium"), ("application", "MailboxSettings.ReadWrite", "high")}
    assert [c.owner_type for c in nw.credentials] == ["servicePrincipal"]
    lit = apps["Litware Scheduler"]
    cal = next(p for p in lit.permissions if p.value == "Calendars.ReadWrite")
    assert cal.consent_type == "Principal" and cal.user_count == 14 and cal.resource_name == "Microsoft Graph"
    cp = session.scalar(select(ConsentPosture).where(ConsentPosture.snapshot_id == res.snapshot_id))
    assert cp.users_can_consent is True and cp.admin_consent_workflow_enabled is False


def test_credential_status_relative_to_collection(users, session, tenant_a):
    res = _import(session, users["admin"], tenant_a)
    rep = _apps(session, res.snapshot_id)["ASH Internal Reporting"]
    states = {c.display_name: c.status for c in rep.credentials}
    # collected 2026-10-01: 2024 secret expired, 2026 secret ends 2026-10-20 (within 30 days)
    assert states == {"reporting-secret-2024": "expired", "reporting-cert": "valid", "reporting-secret-2026": "expiring_30d"}
    assert next(c for c in rep.credentials if c.display_name == "reporting-cert").lifetime_days == 1095


def test_tenant_b_nulls_preserved(users, session, tenant_b):
    res = _import(session, users["admin"], tenant_b, "Tailspin Toys")
    snap = session.get(ExposureSnapshot, res.snapshot_id)
    assert snap.entra_p1_available is False and snap.write_scopes_present is True
    assert not importer.status_ok(snap.endpoint_status, "credentials")
    assert not importer.status_ok(snap.endpoint_status, "signin_activity")
    for app in _apps(session, res.snapshot_id).values():
        assert app.sign_in_data_available is False and app.last_sign_in_utc is None
        assert app.exposure.dormant is None  # unknown, not False and not True
        assert app.exposure.credential_flags is None
        assert app.credentials == []
        if app.owner_class != "microsoft":
            assert app.exposure.incomplete_data
            assert any(r["rule_id"] == "R0" for r in app.exposure.reasons)


def test_duplicate_snapshot_rejected(users, session, tenant_a):
    _import(session, users["admin"], tenant_a)
    with pytest.raises(importer.DuplicateSnapshot):
        _import(session, users["admin"], tenant_a)
    assert importer.preview(session, tenant_a).duplicate


def test_unknown_tenant_requires_explicit_creation(users, session, tenant_a):
    with pytest.raises(importer.UnknownTenant):
        importer.import_document(session, users["admin"], tenant_a)


def test_second_snapshot_links_to_existing_tenant(users, session, tenant_a, tenant_a_later):
    r1 = _import(session, users["admin"], tenant_a)
    r2 = importer.import_document(session, users["admin"], tenant_a_later)
    assert r1.tenant_id == r2.tenant_id
    assert [s.id for s in importer.latest_snapshots(session, r1.tenant_id)] == [r2.snapshot_id, r1.snapshot_id]


def test_import_requires_permission(users, session, tenant_a):
    with pytest.raises(PermissionDenied):
        _import(session, users["risk_owner"], tenant_a)


def test_invalid_files_rejected(tenant_a):
    with pytest.raises(CollectedFileInvalid, match="not valid JSON"):
        importer.load_document(b"{nope")
    bad = dict(tenant_a, credentials=[{**tenant_a["credentials"][0], "hint": "abc"}])
    with pytest.raises(CollectedFileInvalid, match="hint"):
        importer.load_document(json.dumps(bad).encode())
    assert importer.load_document(json.dumps(tenant_a).encode())["metadata"]["tenant_name"] == "Alpine Ski House"


def test_preview_banners(users, session, tenant_b):
    p = importer.preview(session, tenant_b)
    sev = {(s, k) for s, k, _ in p.problems}
    assert ("error", "credentials.applications") in sev and ("warning", "signin_activity") in sev
    assert p.write_scopes_present and p.counts["credentials"] is None and p.counts["service_principals"] == 8


def test_import_is_audited(users, db, tenant_a):
    from keystone.core.audit import AuditLog
    with db.session_scope() as s:
        _import(s, users["admin"], tenant_a)
    with db.session_scope() as s:
        assert s.scalar(select(AuditLog).where(AuditLog.action == "import")).actor_name == "admin"
