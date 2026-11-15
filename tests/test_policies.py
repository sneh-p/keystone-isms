"""Phase 7: policy lifecycle, versions, approval, review, acknowledgement."""

from datetime import date, timedelta

import pytest

from keystone.core.rbac import PermissionDenied
from keystone.core.workflow import InvalidTransition
from keystone.policies import service as pol


@pytest.mark.parametrize("prev,major,new", [(None, True, "1.0"), ("1.0", False, "1.1"), ("1.4", True, "2.0"), ("weird", True, "1.0")])
def test_next_label(prev, major, new):
    assert pol.next_label(prev, major) == new


def test_add_months():
    assert pol.add_months(date(2026, 1, 31), 1) == date(2026, 2, 28)
    assert pol.add_months(date(2026, 11, 15), 12) == date(2027, 11, 15)


def _doc(session, actor, **kw):
    return pol.save_document(session, actor, **{"code": "POL-001", "title": "Information Security Policy", "requires_acknowledgement": True, **kw})


def test_document_validation(users, session):
    _doc(session, users["isms_manager"])
    with pytest.raises(ValueError, match="already used"):
        _doc(session, users["isms_manager"])
    with pytest.raises(ValueError, match="doc_type"):
        _doc(session, users["isms_manager"], code="X", doc_type="memo")
    with pytest.raises(PermissionDenied):
        _doc(session, users["viewer"], code="Y")


def test_full_lifecycle_with_segregation_of_duties(users, session):
    author, approver = users["isms_manager"], users["admin"]
    d = _doc(session, author)
    v1 = pol.start_version(session, author, d.id, body="# Policy\nAll staff must...", change_summary="First issue")
    assert v1.version_label == "1.0" and v1.status == "draft"
    with pytest.raises(ValueError, match="already has a version"):
        pol.start_version(session, author, d.id)
    with pytest.raises(InvalidTransition):
        pol.approve_version(session, approver, v1.id)
    pol.submit_version(session, author, v1.id)
    with pytest.raises(ValueError, match="draft versions"):
        pol.edit_version(session, author, v1.id, body="sneaky change")
    with pytest.raises(ValueError, match="Segregation"):
        pol.approve_version(session, author, v1.id)
    pol.return_version(session, approver, v1.id, "Add scope section")
    assert v1.status == "draft"
    pol.edit_version(session, author, v1.id, body="# Policy\n## Scope\nAll staff must...")
    pol.submit_version(session, author, v1.id)
    pol.approve_version(session, approver, v1.id, "Board approved")
    assert d.status == "approved" and d.current_version_id == v1.id
    assert d.next_review_date == pol.add_months(date.today(), 12)

    v2 = pol.start_version(session, author, d.id, change_summary="Minor wording", major=False)
    assert v2.version_label == "1.1" and v2.body.startswith("# Policy")  # carries forward the text
    pol.submit_version(session, author, v2.id)
    pol.approve_version(session, approver, v2.id)
    assert v1.status == "superseded" and d.current_version_id == v2.id


def test_submit_requires_content(users, session):
    d = _doc(session, users["admin"])
    v = pol.start_version(session, users["admin"], d.id, body="")
    with pytest.raises(ValueError, match="Add the document text"):
        pol.submit_version(session, users["admin"], v.id)


def test_attachment_version(users, session):
    d = _doc(session, users["admin"])
    v = pol.start_version(session, users["admin"], d.id, filename="policy.pdf", data=b"%PDF-1.4 policy")
    assert v.attachment_id
    pol.submit_version(session, users["admin"], v.id)


def _approved(session, users, **kw):
    d = _doc(session, users["isms_manager"], **kw)
    v = pol.start_version(session, users["isms_manager"], d.id, body="text")
    pol.submit_version(session, users["isms_manager"], v.id)
    pol.approve_version(session, users["admin"], v.id)
    return d, v


def test_acknowledgements(users, session):
    d, v = _approved(session, users)
    viewer = users["viewer"]
    assert [x.id for x in pol.pending_for(session, viewer)] == [v.id]
    a1 = pol.acknowledge(session, viewer, v.id)
    assert pol.acknowledge(session, viewer, v.id).id == a1.id  # idempotent
    assert pol.pending_for(session, viewer) == []
    st = pol.ack_status(session, d)
    assert st.acknowledged == 1 and st.total == len(users) and d in pol.policy_attention(session)["acknowledgement_incomplete"]
    # A new version needs fresh acknowledgement
    v2 = pol.start_version(session, users["isms_manager"], d.id, body="v2")
    with pytest.raises(ValueError, match="current approved"):
        pol.acknowledge(session, viewer, v2.id)
    pol.submit_version(session, users["isms_manager"], v2.id)
    pol.approve_version(session, users["admin"], v2.id)
    assert [x.id for x in pol.pending_for(session, viewer)] == [v2.id]


def test_no_ack_required(users, session):
    d, v = _approved(session, users, requires_acknowledgement=False)
    assert pol.ack_status(session, d) is None and pol.pending_for(session, users["viewer"]) == []
    with pytest.raises(ValueError):
        pol.acknowledge(session, users["viewer"], v.id)


def test_review_and_retire(users, session):
    d, _ = _approved(session, users)
    d.next_review_date = date.today() - timedelta(days=1)
    assert d in pol.policy_attention(session)["review_overdue"]
    pol.record_review_no_change(session, users["admin"], d.id)
    assert d not in pol.policy_attention(session)["review_overdue"]
    pol.retire(session, users["admin"], d.id)
    assert d not in pol.documents(session) and pol.pending_for(session, users["viewer"]) == []
    with pytest.raises(ValueError, match="Retired"):
        pol.start_version(session, users["admin"], d.id)


def test_versions_collection_has_no_duplicates(users, session):
    d, v = _approved(session, users)
    pol.start_version(session, users["isms_manager"], d.id, body="v2")
    assert len(d.versions) == 2 and len({x.id for x in d.versions}) == 2
