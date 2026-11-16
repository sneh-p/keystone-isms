---
type: Secure Coding Standard
title: Errors and Logging
description: Fail closed, return safe errors, handle every failure, and record security events in the audit log and logs without leaking secrets.
tags: [security, backend, errors, logging]
rule_prefix: SC-ERR, SC-LOG
applies_to: ["keystone/**/*.py", "scripts/**/*.py", "web/src/**/*.ts", "web/src/**/*.tsx"]
load_when: ["try/except", "exception handler", "threads, async code or scheduled jobs", "logging or audit log", "timeouts or limits", "promises in the web app"]
status: draft
generated: { by: claude/claude-opus-5-5, at: 2026-11-16T00:00:00Z }
stale_after: 2027-05-16T00:00:00Z
---

# Errors

### SC-ERR-001 — Fail closed
**MUST · critical** · CWE-636, CWE-755 · A10:2025 · ASVS V16

If an authorization check, signature or hash verification, validation step, integration check or AI call raises
or times out, the answer is "deny", "error" or "unknown", never "allow" or "pass". This is the repository rule
"unknown is never treated as safe".

```python
# Don't: a crashing provider makes the control look healthy
try:
    outcomes = provider.run(config, secrets)
except Exception:
    outcomes = [Outcome(c.key, "pass", "") for c in provider.checks]

# Do (keystone/integrations/service.py)
except Exception as e:  # noqa: BLE001 - any provider failure becomes an 'error' result, never a pass
    outcomes = [Outcome(c.key, "error", msg) for c in provider.checks]
```

### SC-ERR-002 — Generic errors out, details in logs
**MUST · high** · CWE-209 · ASVS V16

Clients receive a stable status, a message written by us, and for unexpected failures a request ID. They never
receive stack traces, SQL errors, file paths or library versions. Expected errors map in
`keystone/api/app.py` (403, 400, 404, 401); everything else goes to the catch-all handler, which logs the
exception with a request ID and returns `{"detail": "Internal error", "request_id": ...}`.

### SC-ERR-003 — No silent failures
**MUST · high** · ruff `BLE001`, `S110`, `S112`, `E722`; ESLint `@typescript-eslint/no-floating-promises`, `no-misused-promises` · CWE-755 · A10:2025

No bare `except:`, no `except Exception: pass`. A broad `except Exception` is allowed only where the failure is
turned into an explicit result and logged, with a `# noqa: BLE001 - <why>` comment (existing pattern). Background
threads and scheduled jobs record failures (`job_status = "failed"`, `last_status = "error"`). In the web app,
await or explicitly handle every promise.

### SC-ERR-004 — Bound every resource
**MUST · high** · ruff `S113` · CWE-400, CWE-770

Every outbound call has a timeout (httpx `timeout=`, boto3 `Config(connect_timeout, read_timeout)`, the Anthropic
client `timeout=`). Lists that can grow without limit are paginated or capped. Uploads, imports and loops over
input have size limits (`KEYSTONE_MAX_UPLOAD_MB`, `MAX_ITEMS`, row limits).

# Logging

### SC-LOG-001 — Log security events
**MUST · high** · CWE-778 · A09:2025 · ASVS V16

Security events go to the hash-chained audit log (`log_event` in `keystone/core/audit.py`): sign-in success and
failure, permission and role changes, approvals, exports, integration runs and tests, AI calls, Trust Center
grants, NDA signatures and downloads. Row changes to audited models are logged automatically. Each entry records
who, what, the outcome and when; include the client IP where the event comes from the network.

### SC-LOG-002 — Structured, redacted logs
**MUST · critical** · ruff `G004` · CWE-532, CWE-117 · ASVS V16

Use the standard `logging` module with %-style arguments, never f-strings or concatenation of input into the
message. Never log passwords, tokens, session IDs, cookies, authorization headers, API keys or secret values.
Credential columns are listed in each model's `__audit_redact__`.

```python
_LOG = logging.getLogger(__name__)
_LOG.warning("integration %s failed: %s", integration_id, type(err).__name__)   # Do
_LOG.warning(f"login failed for {username} with {password}")                    # Don't
```

### SC-LOG-003 — Don't log bodies by default
**SHOULD · medium** · CWE-532

Keep request and response bodies, uploaded file contents and AI prompts out of logs unless a field allowlist is
applied.
