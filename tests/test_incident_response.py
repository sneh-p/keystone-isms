"""Incident response depth (A.5.24-5.28, ISO/IEC 27035): playbooks, response actions, evidence with hashes and chain of
custody, and raising a nonconformity."""

from sqlalchemy import select

import pytest

from keystone.core.attachments import Attachment
from keystone.core.db import utcnow
from keystone.incidents import service as inc
from keystone.incidents.models import IncidentEvidence

from .conftest import api_login


def test_playbook_actions_and_closing(session, users):
    admin = users["admin"]
    i = inc.report_incident(session, admin, title="Mail account taken over", category="account_compromise", severity="high", detected_at=utcnow())
    steps = inc.playbook(i)
    assert steps and "revoke all sessions" in steps[0]["step"]
    inc.tick_playbook(session, admin, i.id, 0, True)
    assert inc.playbook(i)[0]["done"]["by"]
    with pytest.raises(ValueError, match="No such playbook step"):
        inc.tick_playbook(session, admin, i.id, 99, True)
    a = inc.add_action(session, admin, i.id, "Reset password and revoke tokens", owner_id=admin.id)
    for status in ("triage", "contained", "eradicated", "recovered"):
        inc.move(session, admin, i.id, status)
    i.root_cause, i.lessons_learned = "Password reuse", "Enforce phishing-resistant MFA"
    with pytest.raises(ValueError, match="open response actions"):
        inc.move(session, admin, i.id, "closed", "resolved")
    inc.complete_action(session, admin, a.id)
    nc = inc.raise_nonconformity(session, admin, i.id)
    assert nc.incident_id == i.id and nc.severity == "major" and "Password reuse" in nc.description
    with pytest.raises(ValueError, match="already raised"):
        inc.raise_nonconformity(session, admin, i.id)
    inc.move(session, admin, i.id, "closed", "resolved")


def test_evidence_custody_api(api, ready_users, db):
    api_login(api, "admin")
    iid = api.post("/api/incidents", json={"title": "Malware on laptop", "category": "malware", "detected_at": "2026-11-17T09:00:00Z"}).json()["id"]
    r = api.post(f"/api/incidents/{iid}/evidence", data={"description": "EDR alert export", "source": "EDR console"}, files={"file": ("alert.txt", b"alert: trojan.generic", "text/plain")})
    assert r.status_code == 200, r.text
    ev = r.json()["evidence"][0]
    assert len(ev["sha256"]) == 64 and ev["custody"][0]["action"].startswith("collected")
    att_id = None
    with db.session_scope() as s:
        att_id = s.scalars(select(IncidentEvidence.attachment_id)).one()
    assert api.get(f"/api/attachments/{att_id}").status_code == 404  # only through the custody-recording route
    d = api.get(f"/api/incident-evidence/{ev['id']}/download")
    assert d.status_code == 200 and d.content == b"alert: trojan.generic"
    assert [c["action"] for c in api.get(f"/api/incidents/{iid}").json()["evidence"][0]["custody"]][-1] == "downloaded (hash verified)"
    with db.session_scope() as s:  # simulate tampering with the stored record of the hash
        s.scalars(select(IncidentEvidence)).one().sha256 = "0" * 64
    assert api.get(f"/api/incident-evidence/{ev['id']}/download").status_code == 400
    assert api.delete(f"/api/incidents/{iid}").status_code == 400  # evidence keeps the incident
    api.post("/api/auth/logout")
    api.cookies.clear()
    api_login(api, ready_users["viewer"].username)
    assert api.get(f"/api/incident-evidence/{ev['id']}/download").status_code == 403
    with db.session_scope() as s:
        assert s.get(Attachment, att_id) is not None
