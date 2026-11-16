---
type: Secure Coding Standard
title: Input Validation
description: Validate every input that crosses a trust boundary with a strict Pydantic model, and use only the parsed result.
tags: [security, backend, validation]
rule_prefix: SC-VAL
applies_to: ["keystone/**/*.py", "scripts/**/*.py"]
load_when: ["route or handler", "Form or File parameters", "public endpoint", "scheduled job", "parsing an upload or import", "reading env or files", "third-party API response"]
status: stable
verified: { by: human:sneh, at: 2026-11-16T02:55:39Z }
generated: { by: claude/claude-opus-5-5, at: 2026-11-16T00:00:00Z }
stale_after: 2027-05-16T00:00:00Z
---

# Trust boundaries

Treat all of these as untrusted:

- HTTP body, query, path parameters, form fields, headers and cookies (including `/api/public/*`)
- uploaded files and their names: attachments, questionnaires, framework packs, collector `collected.json`
- responses from integrations (GitHub, AWS, websites) and from the Claude API
- environment variables and `config/*.yaml`
- stored data that a user originally wrote (policy text, answers, comments)

# Rules

### SC-VAL-001 — Parse at the boundary with Pydantic
**MUST · critical** · `tests/test_api.py::test_request_bodies_forbid_unknown_fields` · CWE-20 · A05:2025 · ASVS V2

Every JSON body is a subclass of `In` (`keystone/api/routers/common.py`), which sets `extra="forbid"`. Pass only
the parsed model (or `model_dump(exclude_unset=True)`) inward. Never read `await request.json()`,
`request.query_params` or `request.form()` directly in a router.

```python
from pydantic import Field

from .common import In


class RiskIn(In):  # unknown keys are rejected with 422
    title: str = Field(min_length=1, max_length=300)
    inherent_likelihood: int = Field(ge=1, le=5)
    treatment_option: Literal["mitigate", "accept", "transfer", "avoid"] | None = None


@router.post("/risks")
def create(body: RiskIn, user=Depends(perm("risk.write")), db: Session = Depends(get_db)):
    return out(risk.save_risk(db, user, **body.model_dump(exclude_unset=True)))
```

Don't:

```python
@router.post("/risks")
async def create(request: Request, ...):
    data = await request.json()  # unvalidated, unbounded, any keys
```

Uploaded files go through `keystone/core/attachments.py` (allowlist, magic numbers, size) or a schema
(`schemas/collected.schema.json`) before anything else reads them.

### SC-VAL-002 — Allowlist and bound everything
**MUST · high** · CWE-20, CWE-770 · ASVS V2

Use `Literal`, enums and formats, not blocklists. Strings get `max_length`, lists get `max_length`, numbers get a
range. Services re-check business ranges (for example `review_interval_months` 1-36). Validation errors return
400/422 with a message written by us; never echo a whole invalid payload back.

### SC-VAL-003 — Never merge untrusted objects
**MUST · high** · CWE-915, CWE-1321

Never `setattr` every key of a request dict onto a model, and never `Model(**body.model_dump())` for models with
sensitive fields. Use `apply_fields(obj, data, ALLOWED_FIELDS)` from `keystone/core/services.py` with an explicit
allowlist, as every service already does. For dictionaries keyed by user input, validate the keys
(see `_split()` in `keystone/integrations/service.py`).

### SC-VAL-004 — No user-controlled regular expressions
**MUST · high** · Semgrep `sc-val-004-regex-from-input` · CWE-1333

Never build a regex from input (`re.compile(user_value)`); use `re.escape()` if a literal must be matched. Avoid
nested quantifiers such as `(a+)+`, and bound input length before matching.

### SC-VAL-005 — The server decides
**MUST · high** · CWE-602

Validation and permission checks in the web app are for UX only. The API re-validates everything. Never trust
client-computed scores, readiness, totals, roles or permissions; the server computes them.
