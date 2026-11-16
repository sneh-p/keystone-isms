"""Workflow improvements: attention routing, task hand-over, emailed links, incidents that realise risks."""

from datetime import date

import pytest
from sqlalchemy import select

from keystone import demo
from keystone.core import auth
from keystone.core.audit import AuditLog
from keystone.frameworks.models import CommonControl
from keystone.notifications import mailer
from keystone.reporting import dashboard, routing
from keystone.risk.models import Risk
from keystone.tasks.models import Task

from .conftest import PASSWORD, api_login


@pytest.fixture
def demo_db(db):
    with db.session_scope() as s:
        admin = auth.create_user(s, None, username="admin", display_name="Admin", password=demo.DEMO_PASSWORD, email="admin@alpineskihouse.example")
    with db.session_scope(admin) as s:
        demo.seed(s, s.get(auth.User, admin.id))
    return db


def _u(s, name):
    return s.scalar(select(auth.User).where(auth.User.username == name))


def _whats(routed, user):
    return [i["what"] for i in routed.get(user.id, [])]


# ---- routing -----------------------------------------------------------------------------------

def test_every_attention_item_reaches_someone(demo_db):
    """The measured gap: 22 of 29 dashboard items reached nobody. Now each category has a recipient."""
    from keystone.controls import service as ctl
    from keystone.policies import service as pol
    from keystone.risk import service as risk
    from keystone.tprm import service as tprm

    with demo_db.session_scope() as s:
        routed = routing.routed_items(s)
        everything = " | ".join(i["what"] for items in routed.values() for i in items)
        for r in risk.needs_attention(risk.list_risks(s), date.today())["above_appetite_untreated"]:
            assert r.ref in everything
        for key, items in tprm.vendor_attention(s).items():
            for v in items:
                name = getattr(v, "name", None) or s.get(__import__("keystone.tprm.models", fromlist=["Vendor"]).Vendor, v.vendor_id).name
                assert name in everything, key
        for d in pol.policy_attention(s)["acknowledgement_incomplete"]:
            assert d.code in everything
        drafts = pol.policy_attention(s)["never_approved"]
        assert drafts and "draft polic" in everything
        n = len(ctl.control_attention(s)["implemented_without_evidence"])
        assert f"{n} implemented control(s) without evidence and without an owner" in everything


def test_owner_gets_the_specific_item_and_unowned_go_to_managers_once(demo_db):
    with demo_db.session_scope() as s:
        mia, lena, raj = _u(s, "mia.isms"), _u(s, "lena.ctl"), _u(s, "raj.risk")
        routed = routing.routed_items(s)
        assert any("RSK-0002" in w and "risk appetite" in w for w in _whats(routed, raj))
        summaries = [w for w in _whats(routed, mia) if "without an owner" in w]
        assert summaries and not any(w.startswith("Add current evidence") for w in _whats(routed, mia))
        # Give the controls an owner: the owner now gets one item per control, the summary disappears.
        for c in s.scalars(select(CommonControl)):
            c.owner_id = lena.id
        s.flush()
        routed = routing.routed_items(s)
        assert any(w.startswith("Add current evidence for KC-") for w in _whats(routed, lena))
        assert not any("implemented control(s) without evidence" in w for w in _whats(routed, mia))
        # It shows in My tasks too.
        assert any(t["what"].startswith("Add current evidence") for t in dashboard.my_tasks(s, lena))


def test_queues_respect_segregation_of_duties(demo_db):
    from keystone.tprm.models import VendorAssessment

    with demo_db.session_scope() as s:
        routed = routing.routed_items(s)
        a = s.scalar(select(VendorAssessment).where(VendorAssessment.status == "in_review"))
        author = s.get(auth.User, a.created_by_id)
        approvers = [uid for uid, items in routed.items() if any(a.title in i["what"] and i["what"].startswith("Approve") for i in items)]
        assert approvers and author.id not in approvers
        # A completed corrective action is verified by someone other than its owner.
        from keystone.improvement import service as imp

        lena, mia = _u(s, "lena.ctl"), _u(s, "mia.isms")
        nc = imp.raise_nc(s, mia, title="Leaver access not removed", source="internal_audit")
        act = imp.add_action(s, mia, nc.id, "Remove stale accounts weekly", owner_id=lena.id)
        imp.complete_action(s, lena, act.id, "Script deployed")
        routed = routing.routed_items(s)
        check = [uid for uid, items in routed.items() if any("Remove stale accounts" in i["what"] for i in items)]
        assert check and lena.id not in check


def test_employees_and_expired_users_get_no_staff_items(demo_db):
    from datetime import datetime, timedelta

    with demo_db.session_scope() as s:
        omar = _u(s, "omar.audit")
        omar.expires_at = datetime.now() - timedelta(days=1)
        s.flush()
        routed = routing.routed_items(s)
        assert omar.id not in routed
        emp = auth.create_user(s, _u(s, "admin"), username="emp", display_name="Emp", password=PASSWORD, role="employee")
        assert emp.id not in routing.routed_items(s)


# ---- tasks follow control owners --------------------------------------------------------------------

def test_hand_over_tasks_with_owner(api, demo_db):
    with demo_db.session_scope() as s:
        lena, raj = _u(s, "lena.ctl"), _u(s, "raj.risk")
        tasks = [t for t in s.scalars(select(Task).where(Task.status == "todo")) if t.controls]
        single = next(t for t in tasks if len(t.controls) == 1)
        shared = next(t for t in tasks if len(t.controls) > 1)
        cid, sid = single.controls[0].id, single.id
        shared_ids = [c.id for c in shared.controls]
        shared_id = shared.id
        # One of the shared task's controls belongs to someone else.
        s.get(CommonControl, shared_ids[1]).owner_id = raj.id
    api_login(api, "mia.isms", demo.DEMO_PASSWORD)
    r = api.post("/api/controls/bulk", json={"ids": [cid, shared_ids[0]], "owner_id": lena.id, "hand_over_tasks": True})
    assert r.status_code == 200 and r.json()["tasks_moved"] >= 1
    with demo_db.session_scope() as s:
        assert s.get(Task, sid).assignee_id == lena.id
        assert s.get(Task, shared_id).assignee_id != lena.id  # shared with Raj's control: stays put
        assert s.scalars(select(AuditLog).where(AuditLog.entity_type == "Task", AuditLog.entity_id == sid)).first() is not None
    # Without the option, tasks stay.
    with demo_db.session_scope() as s:
        other = next(t for t in s.scalars(select(Task).where(Task.status == "todo")) if len(t.controls) == 1 and t.controls[0].owner_id is None)
        oid, ocid, before = other.id, other.controls[0].id, other.assignee_id
    assert api.patch(f"/api/controls/{ocid}", json={"owner_id": lena.id}).json()["tasks_moved"] == 0
    with demo_db.session_scope() as s:
        assert s.get(Task, oid).assignee_id == before
    assert api.patch(f"/api/controls/{ocid}", json={"owner_id": lena.id, "hand_over_tasks": True}).json()["tasks_moved"] >= 1


# ---- emailed links --------------------------------------------------------------------------------

@pytest.fixture
def mail(monkeypatch, demo_db):
    sent = []
    monkeypatch.setattr(mailer, "send", lambda cfg, msgs: sent.extend(msgs))
    monkeypatch.setattr(mailer, "resolve", lambda host: "203.0.113.10")
    monkeypatch.setenv("KEYSTONE_PUBLIC_URL", "https://isms.example.com")
    from keystone.notifications import service as ntf

    with demo_db.session_scope() as s:
        ntf.update_smtp(s, _u(s, "admin"), host="smtp.example.com", from_address="isms@example.com", enabled=True)
    return sent


def test_invitation_by_email(api, demo_db, mail):
    from keystone.people.models import Person

    with demo_db.session_scope() as s:
        p = s.scalar(select(Person).where(Person.user_id.is_(None), Person.status != "offboarded"))
        pid, email = p.id, p.email
    api_login(api, "mia.isms", demo.DEMO_PASSWORD)
    r = api.post(f"/api/people/{pid}/invite", json={"send_email": True})
    assert r.status_code == 200 and r.json()["emailed_to"] == email
    token = r.json()["path"].split("#token=")[1]
    body = mail[0].get_content()
    assert mail[0]["To"] == email and f"https://isms.example.com/invite#token={token}" in body
    with demo_db.session_scope() as s:
        logs = list(s.scalars(select(AuditLog)))
        assert any(a.action == "email" and email in a.summary for a in logs)
        assert all(token not in (a.summary + str(a.changes or "")) for a in logs)  # never the link
    # Plain copy-the-link still works without a body.
    assert api.post(f"/api/people/{pid}/invite").json()["emailed_to"] is None


def test_failed_email_changes_nothing(api, demo_db, mail, monkeypatch):
    from keystone.people.models import Invitation, Person

    def boom(cfg, msgs):
        raise OSError("connection refused")

    monkeypatch.setattr(mailer, "send", boom)
    with demo_db.session_scope() as s:
        p = s.scalar(select(Person).where(Person.user_id.is_(None), Person.status != "offboarded"))
        pid = p.id
        before = s.query(Invitation).count()
    api_login(api, "mia.isms", demo.DEMO_PASSWORD)
    r = api.post(f"/api/people/{pid}/invite", json={"send_email": True})
    assert r.status_code == 400 and "Nothing was changed" in r.json()["detail"]
    with demo_db.session_scope() as s:
        assert s.query(Invitation).count() == before  # no new token left behind


def test_vendor_and_trust_links_by_email(api, demo_db, mail):
    from keystone.tprm.models import VendorQuestionnaire
    from keystone.trust import service as trust

    with demo_db.session_scope() as s:
        qid = s.scalar(select(VendorQuestionnaire.id).where(VendorQuestionnaire.status == "sent"))
    api_login(api, "mia.isms", demo.DEMO_PASSWORD)
    r = api.post(f"/api/questionnaires/{qid}/portal-link", json={"send_email": True})
    assert r.status_code == 400  # no contact address
    r = api.post(f"/api/questionnaires/{qid}/portal-link", json={"send_email": True, "contact_name": "Ana", "contact_email": "ana@northwind.example"})
    assert r.status_code == 200 and r.json()["emailed_to"] == "ana@northwind.example"
    assert "/vendor-portal#token=" in mail[-1].get_content()
    with demo_db.session_scope() as s:
        st = trust.settings(s)
        st.published = True
        req = trust.request_access(s, st.slug, name="Bo Buyer", email="bo@customer.example", company="Customer Ltd", reason="Due diligence", ip="198.51.100.9")
        rid = req.id
    r = api.post(f"/api/trust-center/requests/{rid}/approve", json={"send_email": True})
    assert r.status_code == 200 and r.json()["emailed_to"] == "bo@customer.example"
    assert "#access=" in mail[-1].get_content() and mail[-1]["To"] == "bo@customer.example"


def test_email_needs_public_url(api, demo_db, mail, monkeypatch):
    from keystone.people.models import Person

    monkeypatch.delenv("KEYSTONE_PUBLIC_URL")
    with demo_db.session_scope() as s:
        pid = s.scalar(select(Person.id).where(Person.user_id.is_(None), Person.status != "offboarded"))
    api_login(api, "mia.isms", demo.DEMO_PASSWORD)
    r = api.post(f"/api/people/{pid}/invite", json={"send_email": True})
    assert r.status_code == 400 and "KEYSTONE_PUBLIC_URL" in r.json()["detail"]


# ---- incidents that realise a risk -------------------------------------------------------------------

def test_incident_linked_to_risk_brings_review_forward(demo_db):
    from keystone.incidents import service as inc

    with demo_db.session_scope() as s:
        mia = _u(s, "mia.isms")
        r = s.scalar(select(Risk).where(Risk.status != "closed", Risk.review_date > date.today()))
        rid, owner = r.id, s.get(auth.User, r.owner_id)
        i = inc.report_incident(s, mia, title="Ransomware on a booking server", category="malware", severity="high", risk_id=rid)
        assert s.get(Risk, rid).review_date == date.today()
        assert any(f"Review risk {r.ref}" in t["what"] for t in dashboard.my_tasks(s, owner))
        assert any("its review is now due" in e.entry for e in i.events)
