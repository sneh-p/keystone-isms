"""Policy e-signatures (approval and acknowledgement bound to a content fingerprint) and versioned PDFs."""

from __future__ import annotations

import re
import zlib

import pytest
from sqlalchemy import select, text

from keystone.policies import service as pol
from keystone.policies.models import PolicyAcknowledgement, PolicyVersion

from .conftest import api_login


def _pdf_text(data: bytes) -> str:
    """Undo ReportLab's ASCII85 + Flate stream encoding so test assertions can look for text."""
    import base64

    out = []
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", data, re.S):
        raw = m.group(1).strip()
        try:
            if raw.endswith(b"~>"):
                raw = base64.a85decode(raw.removeprefix(b"<~").removesuffix(b"~>"))
            out.append(zlib.decompress(raw).decode("latin-1"))
        except (ValueError, zlib.error):
            out.append(raw.decode("latin-1"))
    return "\n".join(out)


@pytest.fixture
def approved(db, users):
    """POL-T v1.0, approved and signed by the ISMS manager; requires acknowledgement."""
    author = users["admin"]
    with db.session_scope(author) as s:
        d = pol.save_document(s, users["isms_manager"], code="POL-T", title="Test Policy", requires_acknowledgement=True)
        v = pol.start_version(s, author, d.id, body="# Purpose\nAll staff must **lock** screens.\n- one\n- two\n\n<font color='red'>x</font> & <img src='http://evil.example/a.png'/>",
                              change_summary="First issue")
        pol.submit_version(s, author, v.id)
        return v.id


def test_approval_is_signed_with_the_approvers_name_and_a_fingerprint(db, users, approved):
    with db.session_scope() as s:
        with pytest.raises(ValueError, match="Type your full name"):
            pol.approve_version(s, users["isms_manager"], approved, "ok", signed_name="Someone Else")
    with db.session_scope(users["isms_manager"]) as s:
        v = pol.approve_version(s, users["isms_manager"], approved, "ok", signed_name=f"  {users['isms_manager'].display_name.upper()} ")
        assert v.approval_signed_name == users["isms_manager"].display_name.upper().strip()
        assert v.content_sha256 == pol.content_hash(s, v) and len(v.content_sha256) == 64


def test_acknowledgement_signature_and_tamper_check(db, users, approved):
    emp = users["viewer"]
    with db.session_scope(users["isms_manager"]) as s:
        pol.approve_version(s, users["isms_manager"], approved, signed_name=users["isms_manager"].display_name)
    with db.session_scope(emp) as s:
        with pytest.raises(ValueError, match="Type your full name"):
            pol.acknowledge(s, emp, approved, signed_name="nope")
    with db.session_scope(emp) as s:
        a = pol.acknowledge(s, emp, approved, signed_name=emp.display_name, ip="203.0.113.9", user_agent="Mozilla/5.0 test")
        v = s.get(PolicyVersion, approved)
        assert (a.signed_name, a.ip, a.content_sha256) == (emp.display_name, "203.0.113.9", v.content_sha256)
    with db.engine().begin() as conn:  # someone edits the approved text in the database
        conn.execute(text("UPDATE policy_versions SET body = 'Changed after approval' WHERE id = :i"), {"i": approved})
    other = users["auditor"]
    with db.session_scope(other) as s, pytest.raises(ValueError, match="changed since it was approved"):
        pol.acknowledge(s, other, approved, signed_name=other.display_name)


def test_pdf_shows_version_fingerprint_and_escapes_markup(db, users, approved):
    from keystone.policies.pdf import version_pdf

    with db.session_scope() as s:  # draft: watermark, draft fingerprint
        data, name = version_pdf(s, users["viewer"], approved)
        assert data.startswith(b"%PDF") and name == "POL-T-v1.0.pdf"
        txt = _pdf_text(data)
        assert "(DRAFT) Tj" in txt and "draft: changes with" in txt  # watermark, and the draft fingerprint note
    with db.session_scope(users["isms_manager"]) as s:
        v = pol.approve_version(s, users["isms_manager"], approved, signed_name=users["isms_manager"].display_name)
        digest = v.content_sha256
    with db.session_scope(users["viewer"]) as s:
        pol.acknowledge(s, users["viewer"], approved, signed_name=users["viewer"].display_name)
    with db.session_scope() as s:
        txt = _pdf_text(version_pdf(s, users["isms_manager"], approved, with_signatures=True)[0])
        assert digest in txt and "(DRAFT) Tj" not in txt
        assert "lock" in txt and "Purpose" in txt
        assert "font color" in txt and "&lt;" not in txt  # the markup is printed as text, not applied
        assert "evil.example" in txt  # the img tag is printed literally, never fetched
        assert users["viewer"].display_name in txt and "matches" in txt
        from keystone.core.rbac import PermissionDenied

        with pytest.raises(PermissionDenied):  # the signature register lists people: policy.write only
            version_pdf(s, users["viewer"], approved, with_signatures=True)
        with pytest.raises(PermissionDenied):
            version_pdf(s, users["employee"], approved)


def test_signature_api(api, ready_users, db, approved):
    api_login(api, ready_users["isms_manager"].username)
    assert api.post(f"/api/policies/versions/{approved}/approve", json={"note": "ok"}).status_code == 422  # signature required
    r = api.post(f"/api/policies/versions/{approved}/approve", json={"note": "ok", "signed_name": ready_users["isms_manager"].display_name})
    assert r.status_code == 200 and r.json()["content_sha256"]
    r = api.get(f"/api/policies/versions/{approved}/pdf?signatures=true")
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf" and "POL-T-v1.0.pdf" in r.headers["content-disposition"]
    api.post("/api/auth/logout")
    api_login(api, ready_users["viewer"].username)
    assert api.post(f"/api/policies/versions/{approved}/acknowledge", json={}).status_code == 422
    r = api.post(f"/api/policies/versions/{approved}/acknowledge", json={"signed_name": ready_users["viewer"].display_name})
    assert r.status_code == 200 and r.json()["signed_name"] == ready_users["viewer"].display_name
    assert api.get(f"/api/policies/versions/{approved}/pdf?signatures=true").status_code == 403
    assert api.get(f"/api/policies/versions/{approved}/pdf").status_code == 200
    with db.session_scope() as s:
        ack = s.scalars(select(PolicyAcknowledgement)).one()
        assert ack.ip and ack.user_agent
