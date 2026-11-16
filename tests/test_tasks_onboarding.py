"""Phase 4: tasks (SoD, evidence, recurrence), control readiness, onboarding wizard."""

from datetime import date, timedelta

import pytest
from sqlalchemy import func, select

from keystone.controls.models import Evidence
from keystone.core.rbac import PermissionDenied
from keystone.frameworks.models import CommonControl, Framework
from keystone.frameworks.service import control_by_code
from keystone.onboarding import service as onb
from keystone.policies.models import PolicyDocument
from keystone.tasks import service as tsk
from keystone.tasks.models import Task


def _task(session, users, **kw):
    c = control_by_code(session, "KC-TEC-13")
    return tsk.save_task(session, users["control_owner"], title="Test a restore", frequency="quarterly", assignee_id=users["control_owner"].id, control_ids=[c.id], **kw)


def test_task_lifecycle_with_sod_evidence_and_recurrence(content, session, users):
    owner, mgr = users["control_owner"], users["isms_manager"]
    t = _task(session, users, due_date=date.today() + timedelta(days=7))
    with pytest.raises(ValueError, match="note or attach"):
        tsk.submit(session, owner, t.id, "")
    tsk.start(session, owner, t.id)
    tsk.add_attachment(session, owner, t.id, "restore.pdf", b"%PDF-1.4 restore ok")
    tsk.submit(session, owner, t.id, "Restored the booking DB in 42 minutes")
    assert t.status == "in_review"
    with pytest.raises(PermissionDenied):
        tsk.approve(session, owner, t.id)
    tsk.send_back(session, mgr, t.id, "Add the restore log")
    assert t.status == "in_progress" and t.review_comment
    tsk.submit(session, owner, t.id, "Restored in 42 minutes; log attached")
    tsk.approve(session, mgr, t.id, "Good")
    assert t.status == "done" and t.approved_by_id == mgr.id
    ev = session.scalars(select(Evidence).where(Evidence.common_control_id == control_by_code(session, "KC-TEC-13").id)).all()
    assert len(ev) == 1 and ev[0].attachment_id and ev[0].valid_until == date.today() + timedelta(days=92 + 14)
    nxt = session.scalar(select(Task).where(Task.previous_task_id == t.id))
    assert nxt.status == "todo" and nxt.due_date == date.today() + timedelta(days=92) and [c.code for c in nxt.controls] == ["KC-TEC-13"]
    with pytest.raises(ValueError, match="records"):
        tsk.save_task(session, owner, t.id, title="edit")


def test_assignee_cannot_approve_own_task(content, session, users):
    mgr = users["isms_manager"]
    t = tsk.save_task(session, mgr, title="x", assignee_id=mgr.id)
    tsk.submit(session, mgr, t.id, "done")
    with pytest.raises(ValueError, match="Segregation"):
        tsk.approve(session, mgr, t.id)


def test_once_task_has_no_recurrence_and_note_evidence(content, session, users):
    t = tsk.save_task(session, users["control_owner"], title="One-off", control_ids=[control_by_code(session, "KC-ORG-01").id])
    tsk.submit(session, users["control_owner"], t.id, "Done once")
    tsk.approve(session, users["isms_manager"], t.id)
    assert session.scalar(select(func.count(Task.id))) == 1
    e = session.scalars(select(Evidence)).one()
    assert e.kind == "note" and e.valid_until is None


def test_not_relevant_and_validation(content, session, users):
    t = _task(session, users)
    with pytest.raises(ValueError):
        tsk.mark_not_relevant(session, users["isms_manager"], t.id, " ")
    tsk.mark_not_relevant(session, users["isms_manager"], t.id, "No backups in scope")
    assert t.status == "not_relevant"
    with pytest.raises(ValueError, match="frequency"):
        tsk.save_task(session, users["admin"], title="x", frequency="hourly")


def test_generate_from_templates_is_idempotent_and_tag_aware(content, session, users):
    created = tsk.generate_from_templates(session, users["admin"], {"m365"}, users["admin"].id)
    keys = {t.template_key for t in created}
    assert "acc-m365-apps" in keys and "dev-pentest" not in keys and "cld-aws" not in keys
    assert all(t.controls for t in created)
    assert tsk.generate_from_templates(session, users["admin"], {"m365"}) == []
    more = tsk.generate_from_templates(session, users["admin"], {"m365", "develops_software"})
    assert {t.template_key for t in more} == {t["key"] for t in tsk.templates() if t.get("when") == "develops_software"}


def test_task_templates_reference_real_controls(content, session):
    codes = {c.code for c in session.scalars(select(CommonControl))}
    for t in tsk.templates():
        assert set(t["controls"]) <= codes, t["key"]


def test_control_readiness(content, session, users):
    c = control_by_code(session, "KC-TEC-13")
    r = tsk.control_readiness(session, c)
    assert r.status == "not_started" and r.score == 0
    t = _task(session, users, due_date=date.today() - timedelta(days=1))
    r = tsk.control_readiness(session, c)
    assert any(ch["kind"] == "tasks" and not ch["ok"] for ch in r.checks)
    tsk.submit(session, users["control_owner"], t.id, "done")
    tsk.approve(session, users["isms_manager"], t.id)
    c.status = "implemented"
    r = tsk.control_readiness(session, c)
    assert r.status == "ready" and r.score == 100
    c.status = "not_applicable"
    assert tsk.control_readiness(session, c).status == "not_applicable"


# ---- onboarding -------------------------------------------------------------------------------

PROFILE = {"company_name": "Northwind Traders", "industry": "Retail", "size": "11-50", "hosting": ["m365", "cloud_aws"], "data_types": ["customer_personal"], "develops_software": False, "offices": False, "frameworks": ["ISO27001_2022", "SOC2_TSC_2017"], "review_months": 12}


def test_onboarding_builds_a_tailored_isms(db, users):
    with db.session_scope() as s:
        out = onb.complete(s, users["admin"], dict(PROFILE, isms_owner_id=users["isms_manager"].id))
        assert out["frameworks_loaded"] and out["policies_created"] == 15  # 16 templates minus secure development
        assert out["controls_marked_na"] == len(onb.SOFTWARE_CONTROLS) + len(onb.PREMISES_CONTROLS)
        enabled = {f.code for f in s.scalars(select(Framework).where(Framework.enabled.is_(True)))}
        assert enabled == {"ISO27001_2022", "SOC2_TSC_2017"}
        doc = s.scalar(select(PolicyDocument).where(PolicyDocument.code == "POL-001"))
        body = doc.versions[0].body
        assert "Northwind Traders" in body and "{{" not in body and doc.owner_id == users["isms_manager"].id and doc.status == "draft"
        assert s.scalar(select(PolicyDocument).where(PolicyDocument.code == "POL-011")) is None
        tasks = s.scalars(select(Task)).all()
        keys = {t.template_key for t in tasks}
        assert {"cld-aws", "acc-m365-apps", "dat-privacy-ropa"} <= keys and "phy-access" not in keys and "dev-pentest" not in keys
        assert all(t.assignee_id == users["isms_manager"].id for t in tasks)
        assert control_by_code(s, "KC-TEC-25").status == "not_applicable" and "does not develop software" in control_by_code(s, "KC-TEC-25").na_justification
        from keystone.org.service import get_org
        assert "Amazon Web Services" in get_org(s).scope_statement and "Microsoft 365" in get_org(s).scope_statement
    with db.session_scope() as s:
        again = onb.complete(s, users["admin"], PROFILE)
        assert again["policies_created"] == 0 and again["tasks_created"] == 0 and not again["frameworks_loaded"]
        assert onb.state(s)["completed"]


def test_onboarding_validation_and_permission(db, users):
    with db.session_scope() as s:
        with pytest.raises(ValueError, match="framework"):
            onb.complete(s, users["admin"], dict(PROFILE, frameworks=[]))
        with pytest.raises(ValueError, match="hosting"):
            onb.complete(s, users["admin"], dict(PROFILE, hosting=["mainframe"]))
        with pytest.raises(PermissionDenied):
            onb.complete(s, users["risk_owner"], PROFILE)


def test_policy_templates_are_well_formed():
    from keystone.frameworks.loader import CONTENT_DIR, read_yaml
    codes = {c["code"] for c in read_yaml(CONTENT_DIR / "common_controls.yaml")["controls"]}
    seen = set()
    for meta, body in onb.policy_templates():
        assert meta["code"] not in seen and meta["title"] and body.startswith("# ")
        assert set(meta["controls"]) <= codes, meta["code"]
        seen.add(meta["code"])
    assert len(seen) == 16


def test_tasks_api_flow(api, ready_users, content):
    from tests.conftest import api_login
    api_login(api, "controlowner")
    r = api.post("/api/tasks", json={"title": "API task", "frequency": "monthly", "control_ids": [1]})
    tid = r.json()["id"]
    assert api.post(f"/api/tasks/{tid}/attachments", files={"file": ("e.txt", b"evidence", "text/plain")}).status_code == 200
    assert api.post(f"/api/tasks/{tid}/submit", json={"notes": "ok"}).json()["status"] == "in_review"
    assert api.post(f"/api/tasks/{tid}/approve", json={}).status_code == 403
    api_login(api, "ismsmanager")
    assert api.post(f"/api/tasks/{tid}/approve", json={"comment": "fine"}).json()["status"] == "done"
    assert api.get("/api/controls/1/readiness").json()["checks"]
    assert len(api.get("/api/tasks?mine=false&include_closed=false").json()) == 1  # the next monthly occurrence
