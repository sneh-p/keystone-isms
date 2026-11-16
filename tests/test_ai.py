"""Phase 8: optional AI (policy assistant, security questionnaires) and the manual mode without it."""

import csv
import io
import json
from types import SimpleNamespace

import pytest
from openpyxl import Workbook, load_workbook
from sqlalchemy import select

from keystone.ai import policy_assistant
from keystone.ai import service as ai
from keystone.ai.models import AiSettings, AiUsage
from keystone.answers import service as sq
from keystone.answers.models import KnowledgeEntry
from keystone.core.audit import AuditLog
from keystone.core.rbac import PermissionDenied
from keystone.policies import service as pol
from tests.conftest import api_login

KEY = "sk-ant-test-0000000000000000"
POLICY_TEXT = "# Access control\n\nAll staff must use multi-factor authentication for remote access.\nAccess rights are reviewed every quarter by system owners."


# ---------------------------------------------------------------- fakes


def message(data, stop="end_turn", fallback=False, raw=None):
    content = []
    if fallback:
        content += [SimpleNamespace(type="text", text='{"partial'), SimpleNamespace(type="fallback")]
    content.append(SimpleNamespace(type="text", text=raw if raw is not None else json.dumps(data)))
    usage = SimpleNamespace(input_tokens=1200, output_tokens=300, cache_read_input_tokens=800, cache_creation_input_tokens=0)
    return SimpleNamespace(content=content, stop_reason=stop, usage=usage, model="claude-opus-5-5")


class FakeClient:
    def __init__(self, responder):
        self.calls = []
        self.responder = responder
        self.beta = SimpleNamespace(messages=SimpleNamespace(stream=self._stream))

    def _stream(self, **params):
        self.calls.append(params)
        result = self.responder(params)
        if isinstance(result, Exception):
            raise result

        class _S:
            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *a):
                return False

            def get_final_message(self_inner):
                return result

        return _S()


@pytest.fixture(autouse=True)
def no_real_client(monkeypatch):
    """Any attempt to build a real client fails the test; no network calls ever."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    def forbidden(key):
        raise AssertionError("the Claude API must not be called here")

    monkeypatch.setattr(ai, "client_factory", forbidden)
    monkeypatch.setattr(sq, "RUN_INLINE", True)


def enable(session, users, responder, monkeypatch):
    fake = FakeClient(responder)
    monkeypatch.setattr(ai, "client_factory", lambda key: fake)
    ai.update_settings(session, users["admin"], enabled=True, api_key=KEY)
    return fake


@pytest.fixture
def policy(session, users):
    d = pol.save_document(session, users["isms_manager"], code="POL-AC", title="Access Control Policy", requires_acknowledgement=False)
    v = pol.start_version(session, users["isms_manager"], d.id, body=POLICY_TEXT)
    pol.submit_version(session, users["isms_manager"], v.id)
    pol.approve_version(session, users["admin"], v.id)
    draft = pol.save_document(session, users["isms_manager"], code="POL-DRAFT", title="Unapproved Policy")
    pol.start_version(session, users["isms_manager"], draft.id, body="SECRET DRAFT TEXT that must not be used as a source.")
    return d


def sheet(rows, title="Security") -> bytes:
    wb = Workbook()
    ws = wb.active
    ws.title = title
    for r in rows:
        ws.append(r)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


QUESTIONNAIRE = [
    ["Acme Corp vendor security questionnaire"],
    [],
    ["Category", "Question", "Vendor response"],
    ["Identity", "Do you enforce multi-factor authentication for remote access?", None],
    [None, "How often are user access rights reviewed?", None],
    ["Physical", "Do you operate your own data centre?", "No, we use cloud hosting."],
    [None, "n/a", None],
]


# ---------------------------------------------------------------- manual mode, no key


def test_unavailable_without_key_or_when_disabled(session, users, monkeypatch):
    assert ai.status(session)["available"] is False
    ai.update_settings(session, users["admin"], enabled=True)
    assert not ai.available(session)  # enabled, no key
    ai.update_settings(session, users["admin"], enabled=False, api_key=KEY)
    assert not ai.available(session)  # key, disabled
    with pytest.raises(ai.AiUnavailable):
        ai.complete_json(session, users["admin"], "x", instructions="i", context=None, prompt="p", schema={})
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    ai.update_settings(session, users["admin"], enabled=True, clear_key=True)
    assert ai.status(session)["key_source"] == "environment" and ai.available(session)


def test_manual_workflow_makes_no_ai_calls(session, users, policy):
    q = sq.create(session, users["control_owner"], title="Acme", filename="acme.xlsx", data=sheet(QUESTIONNAIRE))
    with pytest.raises(ai.AiUnavailable):
        sq.start_ai_draft(session, users["admin"], q.id)
    with pytest.raises(ai.AiUnavailable):
        policy_assistant.propose(session, users["admin"], policy.id, "Add a section on privileged access")
    kb = sq.save_entry(session, users["control_owner"], question="Do you enforce MFA for remote access?", answer="Yes. MFA is required for all remote access.")
    assert sq.fill_from_knowledge_base(session, users["admin"], q.id) == 0  # draft entries are not used
    sq.approve_entry(session, users["admin"], kb.id)
    assert sq.fill_from_knowledge_base(session, users["admin"], q.id) == 0  # below the fill threshold
    sq.save_entry(session, users["admin"], question="Do you enforce multi-factor authentication for remote access?", answer="Yes, for all remote access.")
    e2 = session.scalars(select(KnowledgeEntry).order_by(KnowledgeEntry.id.desc())).first()
    sq.approve_entry(session, users["admin"], e2.id)
    assert sq.fill_from_knowledge_base(session, users["admin"], q.id) == 1
    first = q.items[0]
    assert first.origin == "knowledge" and first.citations[0]["ref"] == f"KB-{e2.id}"
    assert sq.suggestions(session, q.items[1].id) == [] or all(s["score"] >= sq.KB_SUGGEST_THRESHOLD for s in sq.suggestions(session, q.items[1].id))
    sq.edit_item(session, users["control_owner"], q.items[1].id, answer="Quarterly, by system owners.")
    for it in q.items:
        sq.approve_item(session, users["isms_manager"], it.id)
    sq.set_status(session, users["admin"], q.id, "completed")
    data, name = sq.export_xlsx(session, users["viewer"], q.id)
    assert name == "acme - answered.xlsx"
    assert session.scalar(select(AiUsage)) is None


# ---------------------------------------------------------------- settings


def test_settings_validation_and_key_is_write_only(session, users):
    with pytest.raises(PermissionDenied):
        ai.update_settings(session, users["isms_manager"], enabled=True)
    for bad in ({"model": "gpt-4o"}, {"effort": "huge"}, {"api_key": "not-a-key"}):
        with pytest.raises(ValueError):
            ai.update_settings(session, users["admin"], **bad)
    ai.update_settings(session, users["admin"], enabled=True, model="claude-sonnet-5-5", effort="high", api_key=KEY)
    s = session.scalar(select(AiSettings))
    assert s.api_key_enc and KEY not in s.api_key_enc
    assert KEY not in json.dumps(ai.status(session))
    session.flush()
    assert all(KEY not in json.dumps(r.changes or {}) for r in session.scalars(select(AuditLog)))
    assert ai.status(session)["key_source"] == "settings" and ai.status(session)["model"] == "claude-sonnet-5-5"


def test_settings_api_admin_only_and_no_key(api, ready_users):
    api_login(api, "ismsmanager")
    assert api.get("/api/ai/settings").status_code == 403
    assert api.get("/api/ai/status").json()["available"] is False
    api.post("/api/auth/logout")
    api_login(api, "admin")
    r = api.patch("/api/ai/settings", json={"enabled": True, "api_key": KEY, "effort": "low"})
    assert r.status_code == 200 and KEY not in r.text and r.json()["key_source"] == "settings" and r.json()["effort"] == "low"


# ---------------------------------------------------------------- the API call


def test_request_shape_usage_and_audit(session, users, monkeypatch):
    fake = enable(session, users, lambda p: message({"ok": True}), monkeypatch)
    out = ai.complete_json(session, users["admin"], "test_feature", instructions="Be brief.", context="SOURCES", prompt="Hello", schema={"type": "object"})
    assert out == {"ok": True}
    p = fake.calls[0]
    assert p["model"] == "claude-opus-5-5" and p["fallbacks"] == "default" and p["betas"] == ["server-side-fallback-2026-07-01"]
    assert p["output_config"]["effort"] == "medium" and p["output_config"]["format"]["type"] == "json_schema"
    assert p["system"][1] == {"type": "text", "text": "SOURCES", "cache_control": {"type": "ephemeral"}}
    assert "thinking" not in p and "temperature" not in p
    u = session.scalar(select(AiUsage))
    assert (u.feature, u.ok, u.input_tokens, u.output_tokens, u.cache_read_tokens, u.user_id) == ("test_feature", True, 1200, 300, 800, users["admin"].id)
    assert session.scalar(select(AuditLog).where(AuditLog.action == "ai_call")) is not None


def test_fallback_text_refusal_and_bad_json(session, users, monkeypatch):
    replies = iter([message({"v": 2}, fallback=True), message({}, stop="refusal"), message(None, raw="not json"), message({}, stop="max_tokens")])
    enable(session, users, lambda p: next(replies), monkeypatch)
    call = lambda: ai.complete_json(session, users["admin"], "f", instructions="i", context=None, prompt="p", schema={})  # noqa: E731
    assert call() == {"v": 2}  # only the text after the fallback boundary is used
    for match in ("declined", "could not be read", "cut off"):
        with pytest.raises(ValueError, match=match):
            call()
    assert [u.ok for u in session.scalars(select(AiUsage).order_by(AiUsage.id))] == [True, False, False, False]


def test_api_errors_become_friendly_messages(session, users, monkeypatch):
    import anthropic
    import httpx

    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    err = anthropic.AuthenticationError("bad key", response=httpx.Response(401, request=req), body=None)
    enable(session, users, lambda p: err, monkeypatch)
    with pytest.raises(ValueError, match="rejected"):
        ai.complete_json(session, users["admin"], "f", instructions="i", context=None, prompt="p", schema={})
    assert session.scalar(select(AiUsage)).error == "authentication failed"


# ---------------------------------------------------------------- policy assistant


def test_policy_assistant_propose_and_accept(session, users, policy, monkeypatch):
    revised = POLICY_TEXT + "\n\n## Privileged access\n\nAdministrators must use separate admin accounts."
    fake = enable(session, users, lambda p: message({"body": revised, "change_summary": "Added privileged access.", "notes": ["Name the PAM tool"]}), monkeypatch)
    with pytest.raises(PermissionDenied):
        policy_assistant.propose(session, users["viewer"], policy.id, "Add privileged access")
    prop = policy_assistant.propose(session, users["isms_manager"], policy.id, "Add a section on privileged access")
    assert prop["base_body"] == POLICY_TEXT and prop["body"] == revised and prop["notes"] == ["Name the PAM tool"]
    sent = fake.calls[0]["messages"][0]["content"]
    assert POLICY_TEXT in sent and "Add a section on privileged access" in sent
    assert pol.open_version(policy) is None  # nothing saved by a proposal
    res = policy_assistant.accept(session, users["isms_manager"], policy.id, prop["body"], prop["change_summary"])
    v = pol.open_version(policy)
    assert v.id == res["version_id"] and v.status == "draft" and v.body == revised and v.version_label == "1.1"
    assert policy.status == "approved"  # still needs review and approval
    policy_assistant.accept(session, users["isms_manager"], policy.id, revised + "\nMore.", None)
    assert pol.open_version(policy).id == v.id and v.body.endswith("More.")


# ---------------------------------------------------------------- questionnaires


def test_import_xlsx_csv_and_paste(session, users):
    q = sq.create(session, users["admin"], title="Acme", filename="acme.xlsx", data=sheet(QUESTIONNAIRE))
    assert [it.question for it in q.items] == ["Do you enforce multi-factor authentication for remote access?", "How often are user access rights reviewed?", "Do you operate your own data centre?"]
    assert [it.section for it in q.items] == ["Identity", "Identity", "Physical"]
    assert (q.answer_col, q.header_row, q.items[0].row, q.items[0].sheet) == (3, 3, 4, "Security")
    assert q.items[2].answer == "No, we use cloud hosting." and q.items[2].status == "drafted"
    buf = io.StringIO()
    csv.writer(buf).writerows([["ID", "Question"], ["1", "Do you encrypt data at rest?"], ["2", "Is there a security awareness programme?"]])
    c = sq.create(session, users["admin"], title="CSV", filename="q.csv", data=buf.getvalue().encode())
    assert len(c.items) == 2 and c.answer_col is None
    p = sq.create(session, users["admin"], title="Paste", pasted="Do you have a CISO?\n\nshort\nDo you run penetration tests yearly?")
    assert [it.question for it in p.items] == ["Do you have a CISO?", "Do you run penetration tests yearly?"]
    with pytest.raises(ValueError, match="No questions"):
        sq.create(session, users["admin"], title="Empty", filename="e.csv", data=b"a,b\n1,2\n")
    with pytest.raises(PermissionDenied):
        sq.create(session, users["viewer"], title="x", pasted="Do you have a CISO?")


def test_ai_draft_grounding(session, users, policy, monkeypatch):
    q = sq.create(session, users["admin"], title="Acme", filename="acme.xlsx", data=sheet(QUESTIONNAIRE))
    i1, i2, i3 = q.items
    sq.approve_item(session, users["admin"], i3.id)  # an approved answer is never overwritten

    def responder(p):
        return message({"answers": [
            {"item_id": i1.id, "answerable": True, "answer": "Yes. MFA is required for remote access.", "confidence": "high", "note": "",
             "citations": [{"source_id": "POL-AC", "quote": "All staff must use  multi-factor authentication for remote access."}]},
            {"item_id": i2.id, "answerable": True, "answer": "Monthly.", "confidence": "high", "note": "",
             "citations": [{"source_id": "POL-AC", "quote": "Access rights are reviewed monthly."}, {"source_id": "POL-NOPE", "quote": "x"}]},
            {"item_id": i3.id, "answerable": True, "answer": "Overwrite!", "confidence": "high", "note": "", "citations": []},
        ]})

    fake = enable(session, users, responder, monkeypatch)
    sq.start_ai_draft(session, users["control_owner"], q.id, [i1.id, i2.id, i3.id])
    ctx = fake.calls[0]["system"][1]["text"]
    assert 'id="POL-AC"' in ctx and POLICY_TEXT in ctx and "SECRET DRAFT TEXT" not in ctx
    assert "Do you operate your own data centre?" not in fake.calls[0]["messages"][0]["content"]  # approved items are not sent
    assert (i1.status, i1.origin, i1.confidence, i1.citations[0]["ref"]) == ("drafted", "ai", "high", "POL-AC")
    assert i2.confidence == "none" and i2.citations == [] and "could not be found" in i2.note
    assert i3.answer == "No, we use cloud hosting." and i3.status == "approved"
    assert q.job_status == "done" and q.job_progress == 2


def test_ai_draft_unanswerable_and_needs_sources(session, users, monkeypatch):
    q = sq.create(session, users["admin"], title="Acme", pasted="Do you hold ISO 27001 certification?")
    enable(session, users, lambda p: message({"answers": [{"item_id": q.items[0].id, "answerable": False, "answer": "", "confidence": "low", "citations": [], "note": "No certification is mentioned."}]}), monkeypatch)
    with pytest.raises(ValueError, match="no approved policies"):
        sq.start_ai_draft(session, users["admin"], q.id)
    e = sq.save_entry(session, users["admin"], question="Who is the CISO?", answer="Our Head of Security.")
    sq.approve_entry(session, users["admin"], e.id)
    sq.start_ai_draft(session, users["admin"], q.id)
    it = q.items[0]
    assert it.status == "open" and it.confidence == "none" and "do not fully answer" in it.note


def test_export_fills_original_with_approved_answers(session, users):
    q = sq.create(session, users["admin"], title="Acme", filename="acme.xlsx", data=sheet(QUESTIONNAIRE))
    sq.edit_item(session, users["admin"], q.items[0].id, answer="=HYPERLINK(\"http://evil\")")
    sq.approve_item(session, users["admin"], q.items[0].id)
    sq.edit_item(session, users["admin"], q.items[1].id, answer="Draft, not approved")
    data, _ = sq.export_xlsx(session, users["admin"], q.id)
    ws = load_workbook(io.BytesIO(data))["Security"]
    assert ws.cell(row=4, column=3).value == "'=HYPERLINK(\"http://evil\")"  # formula neutralised
    assert ws.cell(row=5, column=3).value in (None, "")
    assert ws.cell(row=1, column=1).value == "Acme Corp vendor security questionnaire"  # the customer's layout is kept
    data, _ = sq.export_xlsx(session, users["admin"], q.id, approved_only=False)
    assert load_workbook(io.BytesIO(data))["Security"].cell(row=5, column=3).value == "Draft, not approved"
    # no answer column in the original: one is added next to the header
    q2 = sq.create(session, users["admin"], title="NoCol", filename="n.xlsx", data=sheet([["Question"], ["Do you encrypt laptops?"]]))
    sq.edit_item(session, users["admin"], q2.items[0].id, answer="Yes")
    sq.approve_item(session, users["admin"], q2.items[0].id)
    ws = load_workbook(io.BytesIO(sq.export_xlsx(session, users["admin"], q2.id)[0])).active
    assert (ws.cell(row=1, column=2).value, ws.cell(row=2, column=2).value) == ("Answer", "Yes")


def test_completion_and_knowledge_base_rules(session, users):
    q = sq.create(session, users["admin"], title="Acme", pasted="Do you encrypt data at rest?")
    it = q.items[0]
    with pytest.raises(ValueError, match="not approved"):
        sq.set_status(session, users["admin"], q.id, "completed")
    with pytest.raises(ValueError, match="Write an answer"):
        sq.approve_item(session, users["admin"], it.id)
    with pytest.raises(PermissionDenied):
        sq.approve_item(session, users["control_owner"], it.id)
    sq.edit_item(session, users["control_owner"], it.id, answer="Yes, AES-256.")
    with pytest.raises(ValueError, match="Only approved"):
        sq.entry_from_item(session, users["admin"], it.id)
    sq.approve_item(session, users["admin"], it.id)
    e = sq.entry_from_item(session, users["admin"], it.id)
    assert e.status == "approved"
    sq.save_entry(session, users["control_owner"], e.id, answer="Yes, AES-256 everywhere.")
    assert e.status == "draft" and e.approved_by_id is None  # changed answers need approval again
    sq.set_status(session, users["admin"], q.id, "completed")
    with pytest.raises(ValueError, match="completed"):
        sq.edit_item(session, users["admin"], it.id, answer="changed")


def test_questionnaire_api_flow(api, ready_users):
    api_login(api, "controlowner")
    r = api.post("/api/security-questionnaires", data={"title": "Acme", "requester": "Acme Corp"}, files={"file": ("acme.xlsx", sheet(QUESTIONNAIRE), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")})
    assert r.status_code == 200, r.text
    q = r.json()
    assert q["progress"]["total"] == 3
    r = api.post(f"/api/security-questionnaires/{q['id']}/ai-draft", json={})
    assert r.status_code == 400 and "not configured" in r.json()["detail"]
    item = q["items"][0]["id"]
    assert api.patch(f"/api/questionnaire-items/{item}", json={"answer": "Yes."}).json()["status"] == "drafted"
    assert api.post(f"/api/questionnaire-items/{item}/approve").status_code == 403
    r = api.get(f"/api/security-questionnaires/{q['id']}/export")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/vnd.openxmlformats")
