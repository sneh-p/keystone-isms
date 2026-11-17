from fastapi import APIRouter, Depends
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.ai import policy_assistant
from keystone.ai import service as ai

from ..deps import get_db, perm
from ..serialize import ser
from .common import In, people_names

router = APIRouter(tags=["ai"])


@router.get("/ai/status")
def status(user=Depends(perm("read")), db: Session = Depends(get_db)):
    # Feature flags for the UI. Never includes the key.
    return ai.status(db)


@router.get("/ai/settings")
def get_settings(user=Depends(perm("ai.manage")), db: Session = Depends(get_db)):
    names = people_names(db)
    u = ai.usage(db)
    return {**ai.status(db), "usage": {**{k: u[k] for k in ("calls", "input_tokens", "cache_write_tokens", "cache_read_tokens", "output_tokens")},
            "rows": [ser(r, ("id", "at", "user_id", "feature", "model", "ok", "input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens", "error"), user=names.get(r.user_id, "system")) for r in u["rows"]]}}


class AiSettingsIn(In):
    enabled: bool | None = None
    model: str | None = None
    effort: str | None = None
    api_key: str | None = Field(None, max_length=500)
    clear_key: bool = False
    max_calls_per_user_hour: int | None = Field(None, ge=1, le=10_000)
    monthly_token_budget: int | None = Field(None, ge=10_000, le=2_000_000_000)


@router.patch("/ai/settings")
def update_settings(body: AiSettingsIn, user=Depends(perm("ai.manage")), db: Session = Depends(get_db)):
    ai.update_settings(db, user, **body.model_dump(exclude_unset=True))
    return get_settings(user, db)


class AssistIn(In):
    instruction: str


@router.post("/ai/policies/{did}/propose")
def propose(did: int, body: AssistIn, user=Depends(perm("policy.write")), db: Session = Depends(get_db)):
    return policy_assistant.propose(db, user, did, body.instruction)


class AcceptIn(In):
    body: str = Field(max_length=500_000)
    change_summary: str | None = None


@router.post("/ai/policies/{did}/accept")
def accept(did: int, body: AcceptIn, user=Depends(perm("policy.write")), db: Session = Depends(get_db)):
    return policy_assistant.accept(db, user, did, body.body, body.change_summary)


# ---- control narratives and risk suggestions (round 3) -----------------------------------------------------------

class NarrativeIn(In):
    instruction: str | None = Field(default=None, max_length=2000)


@router.post("/ai/controls/{cid}/narrative")
def control_narrative(cid: int, body: NarrativeIn, user=Depends(perm("control.write")), db: Session = Depends(get_db)):
    from keystone.ai import control_assistant

    return control_assistant.propose(db, user, cid, body.instruction)


class SuggestIn(In):
    focus: str | None = Field(default=None, max_length=1000)


@router.post("/ai/risks/suggest")
def risk_suggestions(body: SuggestIn, user=Depends(perm("risk.write")), db: Session = Depends(get_db)):
    from keystone.ai import risk_assistant

    return risk_assistant.suggest(db, user, body.focus)


class SuggestionIn(In):
    title: str = Field(min_length=3, max_length=300)
    category: str = Field(max_length=30)
    threat: str | None = Field(default=None, max_length=1000)
    vulnerability: str | None = Field(default=None, max_length=1000)
    consequence: str | None = Field(default=None, max_length=1000)
    likelihood: int | None = Field(default=None, ge=1, le=5)
    impact: int | None = Field(default=None, ge=1, le=5)
    asset_ids: list[int] = Field(default_factory=list, max_length=20)
    control_ids: list[int] = Field(default_factory=list, max_length=10)
    owner_id: int | None = None


@router.post("/ai/risks/accept")
def accept_risk_suggestion(body: SuggestionIn, user=Depends(perm("risk.write")), db: Session = Depends(get_db)):
    from keystone.ai import risk_assistant

    d = body.model_dump()
    r = risk_assistant.accept(db, user, d, d.pop("owner_id"))
    return {"id": r.id, "ref": r.ref}
