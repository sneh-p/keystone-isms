"""Phase 6: Trust Center - publication rules, passing controls, access requests, NDA, downloads."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from keystone.core.audit import AuditLog
from keystone.core.rbac import PermissionDenied
from keystone.frameworks.service import control_by_code
from keystone.org import service as org
from keystone.trust import service as trust
from keystone.trust.models import AccessRequest
from tests.conftest import api_login


@pytest.fixture
def published(content, db, users):
    with db.session_scope(users["admin"]) as s:
        org.save_org(s, users["admin"], name="Alpine Ski House")
        trust.update_settings(s, users["admin"], published=True, slug="alpine", headline="Security at Alpine", contact_email="security@alpine.example")
        trust.add_document(s, users["admin"], title="ISO 27001 certificate", kind="certificate", access="public", filename="cert.pdf", data=b"%PDF-1.4 cert")
        d = trust.add_document(s, users["admin"], title="Penetration test summary", kind="report", access="nda", filename="pentest.pdf", data=b"%PDF-1.4 secret report")
        trust.save_faq(s, users["admin"], question="Do you encrypt data?", answer="Yes, at rest and in transit.")
        return {"nda_doc": d.public_id}


def test_settings_validation(users, session):
    for bad, msg in [({"slug": "A B"}, "Slug"), ({"brand_color": "red"}, "hex"), ({"contact_email": "nope"}, "email"), ({"access_days": 999}, "1-365")]:
        with pytest.raises(ValueError, match=msg):
            trust.update_settings(session, users["admin"], **bad)
    with pytest.raises(PermissionDenied):
        trust.update_settings(session, users["control_owner"], published=True)


def test_nda_version_bumps_on_text_change(users, session):
    s = trust.settings(session)
    v = s.nda_version
    trust.update_settings(session, users["admin"], nda_text="New terms")
    assert s.nda_version == v + 1
    trust.update_settings(session, users["admin"], headline="x")
    assert s.nda_version == v + 1


def test_unpublished_is_invisible(content, session, users):
    trust.settings(session)
    with pytest.raises(trust.TrustUnavailable):
        trust.public_view(session, trust.settings(session).slug)


def test_only_ready_controls_are_shown(published, db, users):
    from keystone.controls import service as ctl

    with db.session_scope() as s:
        assert trust.passing_controls(s) == {}
        c = control_by_code(s, "KC-TEC-13")
        ctl.update_control(s, users["admin"], c.id, status="implemented")
        assert trust.passing_controls(s) == {}  # implemented but no evidence: not shown
        ctl.add_evidence(s, users["admin"], c.id, title="Backup report", kind="note", description="ok")
        assert trust.passing_controls(s) == {"Technological": ["Backup"]}
        ctl.update_control(s, users["admin"], c.id, status="partial")
        assert trust.passing_controls(s) == {}  # drops off when no longer implemented


def test_public_view_contents(published, db):
    with db.session_scope() as s:
        v = trust.public_view(s, "alpine")
    assert v["company"] == "Alpine Ski House" and v["headline"] == "Security at Alpine"
    assert {d["title"] for d in v["documents"]} == {"ISO 27001 certificate", "Penetration test summary"}
    assert all(len(d["id"]) == 32 for d in v["documents"])  # opaque ids, not row numbers
    assert v["faqs"][0]["question"] == "Do you encrypt data?"
    assert "attachment_id" not in str(v) and "created_by" not in str(v)


def test_access_flow_api(api, published, ready_users, db):
    public = TestClient(api.app)
    page = public.get("/api/public/trust/alpine").json()
    cert = next(d for d in page["documents"] if d["access"] == "public")
    assert public.get(f"/api/public/trust/alpine/documents/{cert['id']}").content == b"%PDF-1.4 cert"
    nda = published["nda_doc"]
    assert public.get(f"/api/public/trust/alpine/documents/{nda}").status_code == 404  # no token
    assert public.post("/api/public/trust/alpine/requests", json={"name": "Dana", "email": "dana@customer.example", "company": "Customer Ltd", "reason": "Vendor review"}).status_code == 200
    # honeypot: accepted silently, nothing stored
    public.post("/api/public/trust/alpine/requests", json={"name": "bot", "email": "b@b.example", "company": "x", "website": "spam"})
    with db.session_scope() as s:
        reqs = s.scalars(select(AccessRequest)).all()
        assert [r.email for r in reqs] == ["dana@customer.example"]
        rid = reqs[0].id
    api_login(api, "viewer")
    assert api.post(f"/api/trust-center/requests/{rid}/approve", json={}).status_code == 403
    api_login(api, "ismsmanager")
    url = api.post(f"/api/trust-center/requests/{rid}/approve", json={"days": 14}).json()["url"]
    token = url.split("access=")[1]
    g = public.get(f"/api/public/trust/alpine/access/{token}").json()
    assert g["nda_required"] and not g["nda_ok"]
    assert public.get(f"/api/public/trust/alpine/documents/{nda}?token={token}").status_code == 403
    assert public.post(f"/api/public/trust/alpine/access/{token}/nda", json={"signed_name": "Dana Smith"}).status_code == 200
    assert public.get(f"/api/public/trust/alpine/documents/{nda}?token={token}").content == b"%PDF-1.4 secret report"
    with db.session_scope() as s:
        r = s.get(AccessRequest, rid)
        assert r.view_count == 1 and r.nda_signed_name == "Dana Smith" and r.token_hash and token not in r.token_hash
        acts = [a.action for a in s.scalars(select(AuditLog).where(AuditLog.action.in_(["nda_accepted", "trust_download"])))]
        assert acts.count("trust_download") == 2 and "nda_accepted" in acts
    assert api.post(f"/api/trust-center/requests/{rid}/revoke").status_code == 200
    assert public.get(f"/api/public/trust/alpine/documents/{nda}?token={token}").status_code == 404


def test_nda_change_requires_reacceptance(published, db, users):
    with db.session_scope() as s:
        r = trust.request_access(s, "alpine", name="A", email="a@x.example", company="X", reason=None, ip="1.1.1.1")
        tok = trust.approve(s, users["admin"], r.id)
        trust.accept_nda(s, "alpine", tok, "A Person", "1.1.1.1")
        assert trust.nda_ok(trust.settings(s), r)
        trust.update_settings(s, users["admin"], nda_text="Changed terms")
        assert not trust.nda_ok(trust.settings(s), r)


def test_request_rate_limit(published, db):
    with db.session_scope() as s:
        for i in range(5):
            trust.request_access(s, "alpine", name="n", email=f"n{i}@x.example", company="c", reason=None, ip="9.9.9.9")
        with pytest.raises(PermissionError, match="Too many"):
            trust.request_access(s, "alpine", name="n", email="z@x.example", company="c", reason=None, ip="9.9.9.9")
