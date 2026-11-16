"""SC-AUTHZ-002: GET /attachments/{id} serves a file only through the record it belongs to."""

from datetime import date, timedelta

import pytest

from keystone.controls import service as ctl
from keystone.core.attachments import Attachment, save_attachment
from keystone.frameworks.service import control_by_code
from keystone.people import service as ppl
from keystone.people.models import DEVICE_CHECKS
from keystone.trust import service as trust

from .conftest import api_login

PNG = b"\x89PNG\r\n\x1a\nscreenshot"
PDF = b"%PDF-1.4 file"


@pytest.fixture
def files(db, users, content):
    with db.session_scope(users["admin"]) as s:
        ev = ctl.add_evidence(s, users["control_owner"], control_by_code(s, "KC-TEC-13").id, title="Backup report", kind="file", filename="backup.pdf", data=PDF + b"1", valid_until=date.today() + timedelta(days=30))
        dev = ppl.attest_device(s, users["employee"], device_name="Laptop", os="macos", checks={k: True for k in DEVICE_CHECKS}, filename="screen.png", data=PNG)
        doc = trust.add_document(s, users["admin"], title="SOC 2 report", kind="report", access="nda", filename="soc2.pdf", data=PDF + b"2")
        vendor = save_attachment(s, None, "vendor.pdf", PDF + b"3", "VendorQuestionnaire", 1, external_channel="test")
        removed = save_attachment(s, None, "removed.pdf", PDF + b"4", "VendorQuestionnaireRemoved", 1, external_channel="test")
        loose = save_attachment(s, users["admin"], "loose.pdf", PDF + b"5")
        return {"evidence": ev.attachment_id, "device": dev.attachment_id, "trust": doc.attachment_id, "vendor": vendor.id, "removed": removed.id, "loose": loose.id}


def test_readers_get_record_files_only(api, ready_users, files):
    api_login(api, "viewer")
    assert api.get(f"/api/attachments/{files['evidence']}").content == PDF + b"1"
    assert api.get(f"/api/attachments/{files['vendor']}").status_code == 200
    for kind in ("device", "trust", "removed", "loose"):
        r = api.get(f"/api/attachments/{files[kind]}")
        assert r.status_code == 404 and "not found" in r.json()["detail"], kind  # same answer as a missing file
    assert api.get("/api/attachments/999999").status_code == 404


def test_device_screenshots_are_never_served_here(api, ready_users, files):
    for user in ("admin", "isms_manager".replace("_", ""), "auditor"):
        api_login(api, user)
        assert api.get(f"/api/attachments/{files['device']}").status_code == 404, user


def test_gated_trust_documents_need_trust_manage(api, ready_users, files):
    api_login(api, "auditor")
    assert api.get(f"/api/attachments/{files['trust']}").status_code == 404
    api_login(api, "ismsmanager")
    assert api.get(f"/api/attachments/{files['trust']}").content == PDF + b"2"


def test_employees_and_anonymous_are_refused(api, ready_users, files):
    api_login(api, "employee")
    assert api.get(f"/api/attachments/{files['device']}").status_code == 403  # not even their own, via this route
    api.cookies.clear()
    assert api.get(f"/api/attachments/{files['evidence']}").status_code == 401


def test_every_stored_type_is_classified(db, files):
    """A new kind of upload must be added to DOWNLOAD_PERMISSION (or deliberately left out) when it is introduced."""
    from keystone.core.attachments import DOWNLOAD_PERMISSION

    known = set(DOWNLOAD_PERMISSION) | {"DeviceAttestation", "VendorQuestionnaireRemoved"}
    with db.session_scope() as s:
        types = {a.entity_type for a in s.query(Attachment) if a.entity_type}
    assert types <= known
