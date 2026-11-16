---
type: Secure Coding Standard
title: HTTP and Configuration
description: Security headers, CORS, CSRF, request limits, transport security and secure production defaults.
tags: [security, backend, http, configuration]
rule_prefix: SC-CFG
applies_to: ["keystone/api/app.py", "keystone/api/deps.py", "keystone/core/settings.py", "deploy/**", "Dockerfile", "docker-compose.yml", "web/vite.config.ts"]
load_when: ["app or middleware setup", "CORS", "cookies", "headers", "nginx or systemd config", "new setting or feature flag", "production settings"]
status: stable
verified: { by: human:sneh, at: 2026-11-16T02:55:39Z }
generated: { by: claude/claude-opus-5-5, at: 2026-11-16T00:00:00Z }
stale_after: 2027-05-16T00:00:00Z
---

# Rules

### SC-CFG-001 — Security headers on by default
**MUST · high** · `tests/test_api.py::test_security_headers` · CWE-693, CWE-1021 · A02:2025 · ASVS V3

`security_headers()` in `keystone/api/app.py` sets them on every response:

```python
"Content-Security-Policy": "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
                           "script-src 'self'; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'",
"X-Content-Type-Options": "nosniff",
"Referrer-Policy": "same-origin",
"X-Frame-Options": "SAMEORIGIN",
```

`script-src` never gets `'unsafe-inline'` or `'unsafe-eval'` ([SC-XSS-004](/output-encoding-xss.md)).
`style-src 'unsafe-inline'` is needed by the UI library and doesn't allow script. Framing is widened only through
`KEYSTONE_FRAME_ANCESTORS`. Don't remove a header without a registered exception.

### SC-CFG-002 — CORS from an explicit allowlist
**MUST · critical** · CWE-942

The web app and API share one origin, so no CORS middleware is installed. If one is ever needed, configure an
explicit list from validated settings:

```python
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True, allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"])
```

Never use `allow_origins=["*"]` with credentials, never use `allow_origin_regex=".*"`, and never reflect the
request's `Origin`.

### SC-CFG-003 — CSRF protection for cookie-authenticated writes
**MUST · critical** · `tests/test_api.py::test_csrf_required_for_writes` · CWE-352 · ASVS V3

The session cookie is `SameSite=Lax`, and every POST, PUT, PATCH and DELETE needs the `X-CSRF-Token` header
matching the session (`current_session` in `keystone/api/deps.py`). Public write routes (Trust Center requests,
invitation acceptance) carry no session and are rate-limited. GET, HEAD and OPTIONS never change state.

### SC-CFG-004 — Limits everywhere
**MUST · high** · CWE-400, CWE-770

- Upload size: `KEYSTONE_MAX_UPLOAD_MB` in the app, `client_max_body_size` in nginx.
- Rate limits on sign-in (account lockout plus nginx `limit_req`) and public Trust Center requests.
- Item caps on imports (questionnaire rows, collector datasets) and history queries; the evidence list is paged
  (`limit` ≤ 5,000, total in `X-Total-Count`) and the task list returns all open tasks plus a capped history.
- Timeouts on outbound calls ([SC-ERR-004](/errors-and-logging.md)).

### SC-CFG-005 — Production defaults are the safe ones
**MUST · high** · CWE-1188, CWE-489 · A02:2025 · ASVS V13

In production these are off: the interactive API docs (`KEYSTONE_API_DOCS=1` enables them for development),
uvicorn `--reload`, debug logging, Vite source maps (`build.sourcemap: false`) and the demo seed. New settings and
feature flags default to their secure value (AI off, framing same-origin, integrations disabled until configured).

### SC-CFG-006 — HTTPS only
**MUST · high** · CWE-319 · ASVS V12

Serve over TLS (`deploy/nginx/keystone.conf`: TLS 1.2+, HTTP redirected to the configured host). Keystone sends
HSTS on every HTTPS response and marks the session cookie `Secure`. Run uvicorn with `--proxy-headers
--forwarded-allow-ips` set to the real proxy address only, because that controls the client IP used for rate limits
and NDA records. Links Keystone hands out are built from `KEYSTONE_PUBLIC_URL` (or the administrator's browser
origin), never from the request's `Host` header, and the proxy does not forward `Host`. Plain HTTP
(`deploy/nginx/keystone-http.conf`) is acceptable only on a private network for evaluation.
