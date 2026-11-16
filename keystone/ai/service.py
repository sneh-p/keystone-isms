"""Optional Claude API access. Off by default; nothing here runs unless an administrator enables
AI and a key is available (stored encrypted in settings, or ANTHROPIC_API_KEY in the environment).

Every call is recorded in `ai_usage` and the audit log (who, feature, model, tokens). Prompts
contain only the documents the feature needs: never user lists, people records or credentials.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
import os
import re
from typing import Any, Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from keystone.core import secrets as crypto
from keystone.core.audit import log_event
from keystone.core.db import utcnow
from keystone.core.services import authorize

from .models import AiSettings, AiUsage

DEFAULT_MODEL = "claude-opus-5-5"
SUGGESTED_MODELS = ("claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-2")
EFFORTS = ("low", "medium", "high", "xhigh", "max")
# Models that accept server-side refusal fallbacks (a declined request is retried on another model).
_FALLBACK_MODELS = {"claude-opus-5-5", "claude-opus-5", "claude-fable-5-2", "claude-fable-5-1", "claude-sonnet-5-5"}
_FALLBACK_BETA = "server-side-fallback-2026-07-01"
_MODEL_RE = re.compile(r"^claude-[a-z0-9][a-z0-9.\-]{2,60}$")


class AiUnavailable(ValueError):
    """AI is turned off or no key is configured. Features fall back to manual mode."""


class AiLimitReached(ValueError):
    """The per-user rate limit or the monthly token budget is used up (SC-LLM-005)."""


# Tests replace this to supply a fake client; production builds the official SDK client.
def _default_client_factory(api_key: str):
    import anthropic

    return anthropic.Anthropic(api_key=api_key, max_retries=2, timeout=600.0)


client_factory: Callable[[str], Any] = _default_client_factory


def settings(session: Session) -> AiSettings:
    s = session.scalar(select(AiSettings).limit(1))
    if s is None:
        s = AiSettings(enabled=False, model=DEFAULT_MODEL, effort="medium", max_calls_per_user_hour=100, monthly_token_budget=2_000_000)
        session.add(s)
        session.flush()
    return s


def _key(session: Session) -> tuple[str | None, str | None]:
    s = session.scalar(select(AiSettings).limit(1))
    if s is not None and s.api_key_enc:
        return crypto.decrypt(s.api_key_enc), "settings"
    env = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if env:
        return env, "environment"
    return None, None


def status(session: Session) -> dict:
    s = session.scalar(select(AiSettings).limit(1))
    key, source = _key(session)
    enabled = bool(s and s.enabled)
    return {
        "enabled": enabled,
        "key_source": source,
        "available": enabled and key is not None,
        "model": s.model if s else DEFAULT_MODEL,
        "effort": s.effort if s else "medium",
        "max_calls_per_user_hour": s.max_calls_per_user_hour if s else 100,
        "monthly_token_budget": s.monthly_token_budget if s else 2_000_000,
        "tokens_this_month": tokens_this_month(session),
        "suggested_models": list(SUGGESTED_MODELS),
        "efforts": list(EFFORTS),
    }


def available(session: Session) -> bool:
    return status(session)["available"]


def update_settings(session: Session, actor, *, enabled: bool | None = None, model: str | None = None, effort: str | None = None, api_key: str | None = None, clear_key: bool = False,
                    max_calls_per_user_hour: int | None = None, monthly_token_budget: int | None = None) -> AiSettings:
    """The API key is write-only: it is encrypted at rest and never returned."""
    authorize(session, actor, "ai.manage")
    s = settings(session)
    if model is not None:
        model = model.strip()
        if not _MODEL_RE.match(model):
            raise ValueError("Model must be a Claude model ID, for example claude-opus-5-5.")
    if effort is not None and effort not in EFFORTS:
        raise ValueError(f"Effort must be one of {EFFORTS}.")
    if max_calls_per_user_hour is not None and not 1 <= max_calls_per_user_hour <= 10_000:
        raise ValueError("Calls per user per hour must be between 1 and 10,000.")
    if monthly_token_budget is not None and not 10_000 <= monthly_token_budget <= 2_000_000_000:
        raise ValueError("The monthly token budget must be between 10,000 and 2,000,000,000 tokens.")
    if api_key is not None and api_key.strip() and not api_key.strip().startswith("sk-ant-"):
        raise ValueError("That does not look like an Anthropic API key (it should start with sk-ant-).")
    if model is not None:
        s.model = model
    if effort is not None:
        s.effort = effort
    if clear_key:
        s.api_key_enc = None
    elif api_key and api_key.strip():
        s.api_key_enc = crypto.encrypt(api_key.strip())
    if enabled is not None:
        s.enabled = enabled
    if max_calls_per_user_hour is not None:
        s.max_calls_per_user_hour = max_calls_per_user_hour
    if monthly_token_budget is not None:
        s.monthly_token_budget = monthly_token_budget
    session.flush()
    return s


def _month_start() -> datetime:
    now = utcnow()
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def tokens_this_month(session: Session) -> int:
    used = session.scalar(select(func.coalesce(func.sum(AiUsage.input_tokens + AiUsage.cache_read_tokens + AiUsage.output_tokens), 0)).where(AiUsage.at >= _month_start()))
    return int(used or 0)


def check_budget(session: Session) -> None:
    """Refuse any further call once this month's organisation-wide token budget is used."""
    s = settings(session)
    if tokens_this_month(session) >= s.monthly_token_budget:
        raise AiLimitReached("This month's AI token budget is used up. An administrator can raise it under Settings → AI.")


def check_quota(session: Session, actor) -> None:
    """At the start of an AI action: the user's hourly call limit and the monthly budget (SC-LLM-005)."""
    s = settings(session)
    since = utcnow() - timedelta(hours=1)
    calls = session.scalar(select(func.count(AiUsage.id)).where(AiUsage.user_id == getattr(actor, "id", None), AiUsage.at >= since)) or 0
    if calls >= s.max_calls_per_user_hour:
        raise AiLimitReached(f"You have reached the limit of {s.max_calls_per_user_hour} AI calls per hour. Try again later.")
    check_budget(session)


def usage(session: Session, limit: int = 100) -> dict:
    rows = list(session.scalars(select(AiUsage).order_by(AiUsage.at.desc()).limit(limit)))
    totals = session.execute(select(func.count(AiUsage.id), func.coalesce(func.sum(AiUsage.input_tokens), 0), func.coalesce(func.sum(AiUsage.output_tokens), 0))).one()
    return {"rows": rows, "calls": totals[0], "input_tokens": int(totals[1]), "output_tokens": int(totals[2])}


def _record(session: Session, actor, feature: str, model: str, ok: bool, message=None, error: str | None = None) -> None:
    u = getattr(message, "usage", None)
    row = AiUsage(
        user_id=getattr(actor, "id", None), feature=feature, model=getattr(message, "model", None) or model, ok=ok,
        input_tokens=int(getattr(u, "input_tokens", 0) or 0) + int(getattr(u, "cache_creation_input_tokens", 0) or 0),
        output_tokens=int(getattr(u, "output_tokens", 0) or 0),
        cache_read_tokens=int(getattr(u, "cache_read_input_tokens", 0) or 0),
        error=(error or None) and error[:500],
    )
    session.add(row)
    session.flush()
    log_event(session, actor, "ai_call", "AiUsage", row.id, f"{feature} via {row.model}: {'ok' if ok else 'failed'}, {row.input_tokens + row.cache_read_tokens} in / {row.output_tokens} out tokens", {"feature": feature, "ok": ok})


def _final_text(message) -> str:
    """Text of the model that finished the turn (after any server-side fallback boundary)."""
    blocks = list(message.content or [])
    last_fallback = max((i for i, b in enumerate(blocks) if getattr(b, "type", None) == "fallback"), default=-1)
    return "".join(b.text for b in blocks[last_fallback + 1:] if getattr(b, "type", None) == "text")


def complete_json(session: Session, actor, feature: str, *, instructions: str, context: str | None, prompt: str, schema: dict, max_tokens: int = 32000) -> dict:
    """One structured-output request. `instructions` and `context` form the cached system prompt;
    `prompt` is the per-request part. Returns the parsed JSON object."""
    st = status(session)
    if not st["available"]:
        raise AiUnavailable("AI is not configured. An administrator can turn it on under Settings → AI.")
    check_budget(session)  # every call, including each batch of a running job
    key, _ = _key(session)
    if not key:  # status() said available, but the key can be removed in between
        raise AiUnavailable("AI is not configured. An administrator can turn it on under Settings → AI.")
    model, effort = st["model"], st["effort"]
    system: list[dict[str, Any]] = [{"type": "text", "text": instructions}]
    if context:
        system.append({"type": "text", "text": context, "cache_control": {"type": "ephemeral"}})
    params: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
        "output_config": {"effort": effort, "format": {"type": "json_schema", "schema": schema}},
    }
    if model in _FALLBACK_MODELS:
        params["betas"] = [_FALLBACK_BETA]
        params["fallbacks"] = "default"
    import anthropic

    client = client_factory(key)
    try:
        with client.beta.messages.stream(**params) as stream:
            message = stream.get_final_message()
    except anthropic.AuthenticationError as e:
        _record(session, actor, feature, model, False, error="authentication failed")
        raise ValueError("The Anthropic API key was rejected. Check it under Settings → AI.") from e
    except anthropic.PermissionDeniedError as e:
        _record(session, actor, feature, model, False, error="permission denied")
        raise ValueError("The API key is not allowed to use this model.") from e
    except anthropic.NotFoundError as e:
        _record(session, actor, feature, model, False, error="model not found")
        raise ValueError(f"Model {model} was not found. Choose another model under Settings → AI.") from e
    except anthropic.RateLimitError as e:
        _record(session, actor, feature, model, False, error="rate limited")
        raise ValueError("The Claude API is rate limiting requests. Try again in a minute.") from e
    except anthropic.APIStatusError as e:
        _record(session, actor, feature, model, False, error=f"HTTP {e.status_code}")
        raise ValueError(f"The Claude API returned an error (HTTP {e.status_code}). Try again later.") from e
    except anthropic.APIConnectionError as e:
        _record(session, actor, feature, model, False, error="connection error")
        raise ValueError("Could not reach the Claude API. Check the server's network access.") from e

    if message.stop_reason == "refusal":
        _record(session, actor, feature, model, False, message, "refused")
        raise ValueError("Claude declined this request. Edit the input and try again, or work on it manually.")
    if message.stop_reason == "max_tokens":
        _record(session, actor, feature, model, False, message, "output limit reached")
        raise ValueError("The response was too long and was cut off. Try a smaller request.")
    try:
        data = json.loads(_final_text(message))
    except (json.JSONDecodeError, TypeError) as e:
        _record(session, actor, feature, model, False, message, "invalid JSON")
        raise ValueError("Claude returned a response that could not be read. Try again.") from e
    _record(session, actor, feature, model, True, message)
    return data
