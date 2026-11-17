"""Round 3 AI features: control narratives and risk suggestions. What is (and isn't) sent, output validation, accepting."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from keystone.ai import control_assistant, risk_assistant
from keystone.ai import service as ai
from keystone.core.rbac import PermissionDenied
from keystone.frameworks.service import control_by_code
from keystone.risk import service as risk

from .test_ai import enable, message


@pytest.fixture(autouse=True)
def no_real_client(monkeypatch):
    """Any attempt to build a real client fails the test; no network calls ever."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    def forbidden(key):
        raise AssertionError("the Claude API must not be called here")

    monkeypatch.setattr(ai, "client_factory", forbidden)


def _prompt(fake) -> str:
    p = fake.calls[-1]
    return json.dumps(p["messages"]) + json.dumps(p.get("system"))


def test_control_narrative_sends_only_the_control_context(content, session, users, monkeypatch):
    from keystone.controls import service as controls
    from keystone.frameworks.models import Requirement

    c = control_by_code(session, "KC-TEC-05")
    req = session.scalars(select(Requirement).where(Requirement.ref == "A.8.5")).first()
    req.licensed_text = "LICENSED ISO WORDING"  # imported official text must never be sent
    controls.add_evidence(session, users["admin"], c.id, title="SECRET EVIDENCE TITLE", kind="note", description="evidence body")
    risk.save_risk(session, users["admin"], title="SECRET RISK", category="technology", owner_id=users["admin"].id)
    fake = enable(session, users, lambda p: message({"implementation_notes": "## Approach\n- MFA via [identity provider]", "evidence_suggestions": ["Conditional Access export"],
                                                    "notes": ["Fill in the identity provider"]}), monkeypatch)
    out = control_assistant.propose(session, users["control_owner"], c.id, "Keep it short")
    assert out["implementation_notes"].startswith("## Approach") and out["evidence_suggestions"] == ["Conditional Access export"]
    sent = _prompt(fake)
    assert "KC-TEC-05" in sent and "A.8.5" in sent and "Keep it short" in sent
    for secret in ("LICENSED ISO WORDING", "SECRET EVIDENCE TITLE", "SECRET RISK"):
        assert secret not in sent
    with pytest.raises(PermissionDenied):
        control_assistant.propose(session, users["viewer"], c.id)
    fake.responder = lambda p: message({"implementation_notes": "", "evidence_suggestions": [], "notes": []})
    with pytest.raises(ValueError, match="could not be used"):
        control_assistant.propose(session, users["control_owner"], c.id)


def test_risk_suggestions_never_send_existing_risks_and_filter_duplicates(content, session, users, monkeypatch):
    from keystone.assets import service as assets

    a = assets.save_asset(session, users["admin"], name="Booking platform", asset_type="application", classification="confidential",
                          confidentiality=5, integrity=4, availability=5, contains_personal_data=True)
    risk.save_risk(session, users["admin"], title="Ransomware encrypts the booking platform", category="technology", owner_id=users["admin"].id)
    suggestions = {"risks": [
        {"title": "Ransomware encrypts booking platform", "category": "technology", "threat": "t", "vulnerability": "v", "consequence": "c",
         "likelihood": 4, "impact": 5, "assets": ["Booking platform"], "controls": ["KC-TEC-13"]},
        {"title": "Card data leaks through the booking site's payment form", "category": "privacy", "threat": "Skimming script", "vulnerability": "No change detection",
         "consequence": "Fines and card brand penalties", "likelihood": 3, "impact": 5, "assets": ["Booking platform", "Made-up asset"], "controls": ["KC-TEC-16", "KC-NOPE-99"]},
    ]}
    fake = enable(session, users, lambda p: message(suggestions), monkeypatch)
    out = risk_assistant.suggest(session, users["risk_owner"], "payments")
    assert [s["title"] for s in out] == ["Card data leaks through the booking site's payment form"]  # the duplicate is dropped locally
    assert out[0]["asset_ids"] == [a.id] and out[0]["controls"] == ["KC-TEC-16"]  # unknown assets and controls are dropped
    sent = _prompt(fake)
    assert "Booking platform" in sent and "payments" in sent and "Ransomware encrypts the booking platform" not in sent
    r = risk_assistant.accept(session, users["risk_owner"], out[0])
    assert r.status == "assessed" and r.inherent_likelihood == 3 and [x.id for x in r.assets] == [a.id]
    fake.responder = lambda p: message({"risks": [{**suggestions["risks"][1], "likelihood": 9}]})
    with pytest.raises(ValueError, match="could not be used"):
        risk_assistant.suggest(session, users["risk_owner"])
    with pytest.raises(PermissionDenied):
        risk_assistant.suggest(session, users["control_owner"])


def test_assistants_do_nothing_when_ai_is_off(content, session, users):
    with pytest.raises(ai.AiUnavailable):
        control_assistant.propose(session, users["control_owner"], control_by_code(session, "KC-TEC-05").id)
    with pytest.raises(ai.AiUnavailable):
        risk_assistant.suggest(session, users["risk_owner"])


def test_policy_edits_apply_only_where_unambiguous():
    from keystone.ai.policy_assistant import Edit, apply_edits

    text = "# Policy\n\nReview access every quarter.\nReview logs every quarter.\n"
    assert apply_edits(text, [Edit(find="Review access every quarter.", replace="Review access every month.")]) == "# Policy\n\nReview access every month.\nReview logs every quarter."
    for edits in ([Edit(find="every quarter", replace="monthly")], [Edit(find="absent", replace="x")]):  # twice, or not at all
        with pytest.raises(ValueError, match="did not match"):
            apply_edits(text, edits)
    # Edits apply in order, so a later edit may target text an earlier one wrote.
    assert apply_edits("a b", [Edit(find="a", replace="c d"), Edit(find="c d b", replace="done")]) == "done"
