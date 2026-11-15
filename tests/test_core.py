"""Phase 1: accounts, RBAC, audit log, attachments, workflow, organisation."""

from datetime import timedelta

import pytest
from sqlalchemy import select, text

from keystone.core import auth
from keystone.core.attachments import AttachmentRejected, read_attachment, safe_filename, save_attachment
from keystone.core.audit import AuditLog, AuditLogImmutable, verify_chain
from keystone.core.db import utcnow
from keystone.core.rbac import PermissionDenied, Role, has_permission, require
from keystone.core.workflow import InvalidTransition, Workflow
from keystone.org import service as org
from tests.conftest import PASSWORD


# ---- accounts ---------------------------------------------------------------------

def test_first_user_is_admin_without_actor(db):
    with db.session_scope() as s:
        u = auth.create_user(s, None, username="First", display_name="First", password=PASSWORD, role="viewer")
        assert u.role == "admin" and u.username == "first" and not u.must_change_password
        with pytest.raises(PermissionDenied):
            auth.create_user(s, None, username="second", display_name="x", password=PASSWORD)


def test_password_hash_is_argon2_and_never_plain(users, session):
    u = session.scalar(select(auth.User).where(auth.User.username == "admin"))
    assert u.password_hash.startswith("$argon2id$")
    assert PASSWORD not in u.password_hash


@pytest.mark.parametrize("pw", ["short1A!", "alllowercaseletters", "Admin-Password-123"])
def test_password_policy(pw):
    with pytest.raises(auth.PasswordPolicyError):
        auth.check_password_policy(pw, "admin")


def test_authenticate_and_lockout(users, db):
    with db.session_scope() as s:
        assert auth.authenticate(s, "ADMIN ", PASSWORD).username == "admin"
    for _ in range(5):
        with db.session_scope() as s:
            with pytest.raises(auth.AuthError):
                auth.authenticate(s, "admin", "wrong-password")
    with db.session_scope() as s:
        with pytest.raises(auth.AuthError, match="locked"):
            auth.authenticate(s, "admin", PASSWORD)
        u = s.scalar(select(auth.User).where(auth.User.username == "admin"))
        u.locked_until = utcnow() - timedelta(seconds=1)
    with db.session_scope() as s:
        assert auth.authenticate(s, "admin", PASSWORD)


def test_unknown_and_disabled_users_get_same_message(users, db):
    with db.session_scope() as s:
        with pytest.raises(auth.AuthError, match="Invalid username or password"):
            auth.authenticate(s, "nobody", PASSWORD)
        viewer = s.get(auth.User, users["viewer"].id)
        auth.update_user(s, users["admin"], viewer, active=False)
    with db.session_scope() as s:
        with pytest.raises(auth.AuthError, match="Invalid username or password"):
            auth.authenticate(s, "viewer", PASSWORD)


def test_cannot_demote_self(users, session):
    admin = session.get(auth.User, users["admin"].id)
    with pytest.raises(ValueError):
        auth.update_user(session, admin, admin, role="viewer")


def test_change_password(users, session):
    u = session.get(auth.User, users["viewer"].id)
    with pytest.raises(auth.AuthError):
        auth.change_password(session, u, "nope", "Another-Strong-Pass-7")
    auth.change_password(session, u, PASSWORD, "Another-Strong-Pass-7")
    assert not u.must_change_password
    assert auth.authenticate(session, "viewer", "Another-Strong-Pass-7")


# ---- RBAC ---------------------------------------------------------------------------

def test_role_permissions(users):
    assert has_permission(users["admin"], "users.manage")
    assert not has_permission(users["isms_manager"], "users.manage")
    assert has_permission(users["isms_manager"], "policy.approve")
    assert not has_permission(users["viewer"], "risk.write")
    assert has_permission(users["viewer"], "read")
    assert has_permission(users["auditor"], "audit.findings")
    assert not has_permission(users["auditor"], "control.write")
    assert not has_permission(None, "read")
    with pytest.raises(ValueError):
        has_permission(users["admin"], "made.up")
    with pytest.raises(PermissionDenied):
        require(users["viewer"], "org.write")


def test_every_role_has_read():
    from keystone.core.rbac import ROLE_PERMISSIONS
    assert all("read" in perms for perms in ROLE_PERMISSIONS.values())


# ---- audit log ----------------------------------------------------------------------

def test_changes_are_audited_with_actor_and_redaction(users, db):
    admin = users["admin"]
    with db.session_scope(admin) as s:
        org.save_org(s, admin, name="Alpine Ski House", industry="Leisure")
    with db.session_scope(admin) as s:
        org.save_org(s, admin, industry="Hospitality")
    with db.session_scope() as s:
        rows = s.scalars(select(AuditLog).where(AuditLog.entity_type == "Organisation").order_by(AuditLog.id)).all()
        assert [r.action for r in rows] == ["create", "update"]
        assert rows[1].changes["industry"] == ["Leisure", "Hospitality"]
        assert rows[1].actor_name == "admin"
        user_rows = s.scalars(select(AuditLog).where(AuditLog.entity_type == "User")).all()
        assert user_rows and all(r.changes is None or r.changes.get("password_hash") in (None, "***redacted***") for r in user_rows)
        assert PASSWORD not in str([r.changes for r in user_rows])


def test_audit_chain_verifies(users, db):
    with db.session_scope(users["admin"]) as s:
        org.save_org(s, users["admin"], name="Org")
    with db.session_scope() as s:
        assert verify_chain(s) == (True, None)


def test_audit_log_rejects_orm_update_and_delete(users, db):
    with pytest.raises(AuditLogImmutable):
        with db.session_scope() as s:
            s.scalars(select(AuditLog)).first().summary = "tampered"
    with pytest.raises(AuditLogImmutable):
        with db.session_scope() as s:
            s.delete(s.scalars(select(AuditLog)).first())
    with db.session_scope() as s:
        assert verify_chain(s) == (True, None)


def test_audit_log_rejects_raw_sql_update_and_delete(users, db):
    from sqlalchemy.exc import DatabaseError
    for stmt in ("UPDATE audit_log SET summary='x'", "DELETE FROM audit_log"):
        with pytest.raises(DatabaseError, match="append-only"):
            with db.engine().begin() as conn:
                conn.execute(text(stmt))


def test_tampering_detected_by_chain(users, db):
    # Bypass the guard by dropping the trigger, simulating a direct DB edit.
    with db.engine().begin() as conn:
        conn.execute(text("DROP TRIGGER audit_log_no_update"))
        conn.execute(text("UPDATE audit_log SET summary='tampered' WHERE id=2"))
    with db.session_scope() as s:
        assert verify_chain(s) == (False, 2)


def test_login_events_logged(users, db):
    with db.session_scope() as s:
        with pytest.raises(auth.AuthError):
            auth.authenticate(s, "admin", "bad")
    with db.session_scope() as s:
        actions = s.scalars(select(AuditLog.action)).all()
        assert "login_failed" in actions


# ---- attachments ---------------------------------------------------------------------

def test_attachment_roundtrip_and_dedup(users, session):
    a1 = save_attachment(session, users["admin"], "../../etc/report.pdf", b"%PDF-1.7 test", "Evidence", 1)
    a2 = save_attachment(session, users["admin"], "copy.pdf", b"%PDF-1.7 test", "Evidence", 2)
    assert a1.filename == "report.pdf" and a1.sha256 == a2.sha256
    assert read_attachment(a1) == b"%PDF-1.7 test"


@pytest.mark.parametrize(
    "name,data,msg",
    [("x.exe", b"MZ", "not allowed"), ("x.html", b"<html>", "not allowed"), ("fake.pdf", b"MZ\x90", "does not match"), ("e.txt", b"", "empty")],
)
def test_attachment_rejections(users, session, name, data, msg):
    with pytest.raises(AttachmentRejected, match=msg):
        save_attachment(session, users["admin"], name, data)


def test_attachment_size_limit(users, session, monkeypatch):
    monkeypatch.setenv("KEYSTONE_MAX_UPLOAD_MB", "1")
    with pytest.raises(AttachmentRejected, match="larger"):
        save_attachment(session, users["admin"], "big.txt", b"x" * (1024 * 1024 + 1))


def test_attachment_tamper_detected(users, session, tmp_path):
    from keystone.core.attachments import _blob_path
    a = save_attachment(session, users["admin"], "n.txt", b"original")
    _blob_path(a.sha256).write_bytes(b"changed")
    with pytest.raises(RuntimeError, match="integrity"):
        read_attachment(a)


def test_safe_filename():
    assert safe_filename("C:\\Users\\x\\evil<>.pdf") == "evil__.pdf"
    assert safe_filename("...") == "file"


# ---- workflow -------------------------------------------------------------------------

def test_workflow(users):
    wf = Workflow("demo", {"draft": {"review": "policy.write"}, "review": {"approved": "policy.approve", "draft": "policy.write"}}, "draft")

    class Obj:
        status = "draft"

    o = Obj()
    with pytest.raises(InvalidTransition):
        wf.apply(o, "approved", users["admin"])
    wf.apply(o, "review", users["admin"])
    with pytest.raises(PermissionDenied):
        wf.apply(o, "approved", users["control_owner"])
    wf.apply(o, "approved", users["isms_manager"])
    assert o.status == "approved" and wf.states == ["draft", "review", "approved"]


# ---- organisation ------------------------------------------------------------------------

def test_scope_approval_reset_on_scope_change(users, session):
    admin = users["admin"]
    with pytest.raises(ValueError):
        org.approve_scope(session, admin)
    org.save_org(session, admin, name="Org", scope_statement="All IT systems in Geneva")
    o = org.approve_scope(session, admin)
    assert o.scope_approved_by_id == admin.id
    org.save_org(session, admin, industry="Retail")  # non-scope change keeps approval
    assert o.scope_approved_at is not None
    org.save_org(session, admin, scope_statement="All IT systems")
    assert o.scope_approved_at is None


def test_org_write_permission_and_field_whitelist(users, session):
    with pytest.raises(PermissionDenied):
        org.save_org(session, users["viewer"], name="x")
    with pytest.raises(ValueError, match="not editable"):
        org.save_org(session, users["admin"], name="x", scope_approved_by_id=1)


def test_objectives_and_parties(users, session):
    a = users["admin"]
    ob = org.save_objective(session, a, title="MFA for all staff", target="100%", status="on_track")
    org.save_objective(session, a, ob.id, status="achieved")
    assert ob.status == "achieved" and ob.ref == "OBJ-0001"
    with pytest.raises(ValueError):
        org.save_objective(session, a, ob.id, status="done")
    p = org.add_interested_party(session, a, name="Customers", party_type="external", needs="Data kept confidential")
    assert p.created_by_id == a.id
    row = session.scalars(select(AuditLog).where(AuditLog.entity_type == "InterestedParty")).one()
    assert row.actor_id == a.id
