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
    return {**ai.status(db), "usage": {"calls": u["calls"], "input_tokens": u["input_tokens"], "output_tokens": u["output_tokens"],
            "rows": [ser(r, ("id", "at", "user_id", "feature", "model", "ok", "input_tokens", "output_tokens", "cache_read_tokens", "error"), user=names.get(r.user_id, "system")) for r in u["rows"]]}}


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
