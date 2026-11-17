"""The real Anthropic SDK, offline: an httpx MockTransport stands in for the API, so these tests check that the SDK
accepts the parameters Keystone sends, what goes over the wire (prompt caching, structured output, effort, refusal
fallbacks) and that the streamed answer and token usage come back as recorded. No network, no key, no cost."""

from __future__ import annotations

import json

import anthropic
import httpx2 as httpx
import pytest
from sqlalchemy import select

from keystone.ai import policy_assistant, risk_assistant
from keystone.ai import service as ai
from keystone.ai.models import AiUsage

from keystone.policies import service as pol

from .test_ai import KEY, POLICY_TEXT

USAGE = {"input_tokens": 40, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 0}


def _sse(events: list[dict]) -> bytes:
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()


def _stream_body(text: str, usage: dict, stop: str = "end_turn") -> bytes:
    msg = {"id": "msg_offline", "type": "message", "role": "assistant", "model": "claude-opus-5-5", "content": [],
           "stop_reason": None, "stop_sequence": None, "usage": {**USAGE, **usage, "output_tokens": 1}}
    return _sse([
        {"type": "message_start", "message": msg},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text[: len(text) // 2]}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text[len(text) // 2:]}},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None}, "usage": {"output_tokens": usage.get("output_tokens", 50)}},
        {"type": "message_stop"},
    ])


class Wire:
    """Records each request and answers with the next queued (status, body)."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.replies: list[tuple[int, bytes, str]] = []

    def reply(self, data: dict | None = None, usage: dict | None = None, *, stop: str = "end_turn", status: int = 200, raw: bytes | None = None):
        body = raw if raw is not None else _stream_body(json.dumps(data), usage or {}, stop)
        self.replies.append((status, body, "text/event-stream" if status == 200 else "application/json"))

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status, body, ctype = self.replies.pop(0)
        return httpx.Response(status, content=body, headers={"content-type": ctype, "request-id": "req_offline"})

    def body(self, i: int = -1) -> dict:
        return json.loads(self.requests[i].content)


@pytest.fixture
def policy(session, users):
    d = pol.save_document(session, users["isms_manager"], code="POL-AC", title="Access Control Policy", requires_acknowledgement=False)
    v = pol.start_version(session, users["isms_manager"], d.id, body=POLICY_TEXT)
    pol.submit_version(session, users["isms_manager"], v.id)
    pol.approve_version(session, users["admin"], v.id)
    return d


@pytest.fixture
def wire(monkeypatch, session, users):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    w = Wire()

    def factory(key: str):
        assert key == KEY
        return anthropic.Anthropic(api_key=key, max_retries=0, http_client=httpx.Client(transport=httpx.MockTransport(w.handler)))

    monkeypatch.setattr(ai, "client_factory", factory)
    ai.update_settings(session, users["admin"], enabled=True, api_key=KEY, effort="low")
    return w


def test_request_shape_over_the_wire(session, users, wire, policy):
    wire.reply({"body": "", "edits": [{"find": "every quarter", "replace": "every month"}], "change_summary": "Monthly reviews.", "notes": []},
               {"input_tokens": 120, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 60})
    out = policy_assistant.propose(session, users["isms_manager"], policy.id, "Review access monthly")
    assert out["body"] == POLICY_TEXT.replace("every quarter", "every month")  # applied locally from a small edit
    req = wire.requests[-1]
    assert req.url.path == "/v1/messages" and KEY in (req.headers.get("x-api-key", "") + req.headers.get("authorization", ""))
    assert "server-side-fallback-2026-07-01" in req.headers["anthropic-beta"]
    b = wire.body()
    assert b["model"] == "claude-opus-5-5" and b["stream"] is True and b["fallbacks"] == "default"
    assert b["output_config"]["effort"] == "low" and b["output_config"]["format"]["type"] == "json_schema"
    assert b["output_config"]["format"]["schema"]["required"] == ["body", "edits", "change_summary", "notes"]
    # Stable text first, cache breakpoint on the last system block, per-request text only in the user turn.
    assert [("cache_control" in s) for s in b["system"]] == [False, True]
    assert POLICY_TEXT in b["messages"][0]["content"] and POLICY_TEXT not in json.dumps(b["system"])
    assert "thinking" not in b and "temperature" not in b  # adaptive thinking is the model default; sampling params are not sent
    row = session.scalars(select(AiUsage).order_by(AiUsage.id.desc())).first()
    assert (row.ok, row.input_tokens, row.output_tokens) == (True, 120, 60)


def test_cache_reads_and_writes_are_recorded(content, session, users, wire):
    from keystone.assets import service as assets

    assets.save_asset(session, users["admin"], name="Booking platform", asset_type="application", classification="confidential",
                      confidentiality=5, integrity=4, availability=5)
    empty = {"risks": []}
    wire.reply(empty, {"input_tokens": 30, "cache_creation_input_tokens": 4100, "cache_read_input_tokens": 0, "output_tokens": 200})
    wire.reply(empty, {"input_tokens": 35, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 4100, "output_tokens": 180})
    risk_assistant.suggest(session, users["risk_owner"])
    risk_assistant.suggest(session, users["risk_owner"], "payments")
    first, second = wire.body(0), wire.body(1)
    assert first["system"] == second["system"]  # identical cached prefix: the second call reads it from cache
    assert "KC-TEC-05" in second["system"][1]["text"] and "Booking platform" in second["system"][1]["text"]
    assert "payments" in second["messages"][0]["content"] and "KC-TEC-05" not in second["messages"][0]["content"]
    rows = list(session.scalars(select(AiUsage).order_by(AiUsage.id)))[-2:]
    assert [(r.input_tokens, r.cache_write_tokens, r.cache_read_tokens) for r in rows] == [(30, 4100, 0), (35, 0, 4100)]
    u = ai.usage(session)
    assert (u["cache_write_tokens"], u["cache_read_tokens"]) == (4100, 4100)
    assert ai.tokens_this_month(session) == 30 + 4100 + 200 + 35 + 4100 + 180  # the budget counts every token


def test_sdk_errors_and_stop_reasons(session, users, wire, policy):
    wire.reply(raw=json.dumps({"type": "error", "error": {"type": "authentication_error", "message": "invalid x-api-key"}}).encode(), status=401)
    with pytest.raises(ValueError, match="key was rejected"):
        policy_assistant.propose(session, users["isms_manager"], policy.id, "Tidy it")
    wire.reply({"body": "x", "edits": [], "change_summary": "", "notes": []}, stop="max_tokens")
    with pytest.raises(ValueError, match="cut off"):
        policy_assistant.propose(session, users["isms_manager"], policy.id, "Tidy it")
    wire.reply({"body": "", "edits": [{"find": "not in the document", "replace": "x"}], "change_summary": "", "notes": []})
    with pytest.raises(ValueError, match="did not match"):
        policy_assistant.propose(session, users["isms_manager"], policy.id, "Tidy it")
    errors = [r.error for r in session.scalars(select(AiUsage).order_by(AiUsage.id))][-3:]
    assert errors == ["authentication failed", "output limit reached", None]  # the call worked; applying the edit did not
