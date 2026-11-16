---
type: Secure Coding Standard
title: LLM Features
description: Rules for product features that call Claude - the policy assistant and security-questionnaire drafting - and any future model, retrieval or tool use.
tags: [security, ai, llm, agents]
rule_prefix: SC-LLM
applies_to: ["keystone/ai/**", "keystone/answers/**", "web/src/components/PolicyAssistant.tsx", "web/src/pages/SecurityQuestionnaires.tsx", "**/*prompt*", "**/*llm*", "**/*agent*"]
load_when: ["calling a model API", "building prompts", "choosing documents to send", "giving a model tools", "rendering model output"]
status: stable
verified: { by: human:sneh, at: 2026-11-16T02:55:39Z }
generated: { by: claude/claude-opus-5-5, at: 2026-11-16T00:00:00Z }
stale_after: 2027-05-16T00:00:00Z
sources:
  - { id: llm-top10, resource: "https://genai.owasp.org/llm-top-10/", title: "OWASP Top 10 for LLM Applications 2025" }
  - { id: agentic-top10, resource: "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026", title: "OWASP Top 10 for Agentic Applications 2026" }
---

# Scope

These rules apply when Keystone itself calls a model (`keystone/ai/service.complete_json`). AI is optional and off
by default; every feature must keep working without it. Risk names follow the OWASP LLM and Agentic Top 10
lists.[^llm-top10][^agentic-top10]

# Rules

### SC-LLM-001 — Model output is untrusted input
**MUST · critical** · `tests/test_ai.py` · CWE-1427, CWE-94 · LLM05 Improper Output Handling

Request structured output with a JSON schema, then validate the parsed result with a strict Pydantic model before
using it. Treat it like user input afterwards: it never reaches `eval`, a subprocess, SQL text, file paths, URLs or
HTML without the same controls. Citations are only kept if the quoted text is found in the cited source.

```python
class ProposedRevision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    body: str = Field(min_length=1, max_length=200_000)
    change_summary: str = Field(max_length=1_000)
    notes: list[str] = Field(default_factory=list, max_length=20)

try:
    out = ProposedRevision.model_validate(ai.complete_json(...))
except ValidationError as e:
    raise ValueError("Claude returned a response that could not be used. Try again.") from e
```

### SC-LLM-002 — Assume prompt injection will succeed
**MUST · critical** · CWE-1427 · LLM01 Prompt Injection

Keep untrusted content (customer questions, policy text, uploaded documents) in delimited data sections
(`<question>`, `<source>`, `<current_document>`) in the user turn or the cached context block, never in the
instructions. More importantly, design so that a fully hijacked model can't cause harm: the model has no tools, its
output is a draft, and a person approves every answer and every policy version before it is used or exported.
The control is what the model is able to do, not what the prompt tells it to do.

### SC-LLM-003 — Tools act as the user, with least privilege
**MUST · critical** · CWE-862 · LLM06 Excessive Agency

Keystone gives models no tools today. If tools are added, each tool enforces `authorize()` for the current user in
code, the set of tools is the smallest possible, and anything that writes, sends, deletes or changes permissions
requires explicit human confirmation. The prompt is never the access control.

### SC-LLM-004 — Keep secrets and other people's data out of context
**MUST NOT · critical** · LLM02 Sensitive Information Disclosure, LLM07 System Prompt Leakage

Send only what the feature needs: the document being edited and the organisation profile for the policy
assistant; the questions plus approved policies and approved knowledge-base answers for questionnaires. Never send
credentials, people or user records, risks, incidents, evidence files, audit-log entries or draft policies. The
API key is used only by the SDK client and never appears in prompts, logs or responses.

### SC-LLM-005 — Bound consumption
**MUST · high** · LLM10 Unbounded Consumption

Every call has `max_tokens`, a client timeout and bounded retries. Batches are capped (`BATCH`, `MAX_ITEMS`).
Every call is recorded in `ai_usage` and the audit log with the user and token counts. `check_quota()` enforces a
per-user limit of calls per hour when an AI action starts, and `check_budget()` stops every call, including each batch
of a running job, once the organisation's monthly token budget is used (both set under **Settings → AI**).

### SC-LLM-006 — Render output safely
**MUST · high** · CWE-79

Render model output as plain text or through `Markdown.tsx` (no raw HTML). Images in model or user Markdown are not
loaded: they render as their alt text, and the CSP blocks remote images. Links go through `safeHref()`.

[^llm-top10]: OWASP Top 10 for LLM Applications 2025
[^agentic-top10]: OWASP Top 10 for Agentic Applications 2026
