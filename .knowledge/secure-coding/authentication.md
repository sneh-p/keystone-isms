---
type: Secure Coding Standard
title: Authentication and Sessions
description: Password storage, session cookies, CSRF tokens, invitation and access tokens, brute-force protection and secret comparison.
tags: [security, backend, authentication, sessions]
rule_prefix: SC-AUTHN
applies_to: ["keystone/core/auth.py", "keystone/core/sessions.py", "keystone/api/routers/auth.py", "keystone/api/deps.py", "keystone/people/**", "keystone/trust/**", "**/*session*", "**/*login*", "**/*token*", "**/*password*", "web/src/lib/auth.tsx", "web/src/pages/Auth.tsx"]
load_when: ["login or setup", "passwords", "sessions or cookies", "invitation links", "Trust Center access links", "API keys or tokens", "MFA or SSO"]
status: stable
verified: { by: human:sneh, at: 2026-11-16T02:55:39Z }
generated: { by: claude/claude-opus-5-5, at: 2026-11-16T00:00:00Z }
stale_after: 2027-05-16T00:00:00Z
---

# Rules

### SC-AUTHN-001 — Use the project's auth module; escalate changes
**MUST · critical** · `tests/test_api.py::test_every_route_requires_sign_in` · CWE-287, CWE-306 · A07:2025 · ASVS V6

All authentication goes through `keystone/core/auth.py`, `keystone/core/sessions.py` and the `current_user` /
`perm()` dependencies in `keystone/api/deps.py`. Every route requires a signed-in session except the explicit,
reviewed `PUBLIC` set in `tests/test_api.py` (sign-in, first-run setup, invitation acceptance, the public Trust
Center). Changes to auth flows need human sign-off ([SC-AGT-006](/agent-conduct.md)).

### SC-AUTHN-002 — Hash passwords with Argon2id
**MUST · critical** · CWE-916, CWE-256 · ASVS V6

Passwords are hashed only by `auth.hash_password()` (argon2-cffi `PasswordHasher`, Argon2id) and checked inside
`auth.authenticate()` and `auth.change_password()`. Never hash passwords with MD5 or the SHA family, never store them unsalted or reversibly,
and never log or return a password, even partially. Prefer checking new passwords against a breached-password list
to adding composition rules.

### SC-AUTHN-003 — Lock down session cookies
**MUST · critical** · CWE-384, CWE-614, CWE-1004 · ASVS V7

- The cookie holds a random token (`secrets.token_urlsafe(32)`); only its SHA-256 is stored.
- A new session is created on sign-in. A password change ends every session of that user, including the current
  one, and issues a new session ID and CSRF token (`tests/test_api.py::test_password_change_rotates_the_session`).
  Sessions are destroyed on sign-out, when a user is disabled or offboarded, and when their role changes
  (`sessions.destroy_all_for`).
- Idle and absolute timeouts are both enforced server-side.
- The cookie is `HttpOnly`, `SameSite=Lax`, `Path=/`, and `Secure` whenever the request arrived over HTTPS.

```python
response.set_cookie(COOKIE, token, httponly=True, samesite="lax", secure=secure, path="/", max_age=sessions.ABSOLUTE_HOURS * 3600)
```

### SC-AUTHN-004 — Verify signed tokens fully; never just decode
**MUST · critical** · Semgrep `sc-authn-004-jwt-decode-unverified` · CWE-347 · ASVS V9

Keystone uses opaque session tokens, not JWTs. If JWTs are introduced (for example OIDC single sign-on), verify
the signature with pinned algorithms, issuer, audience and expiry, and never feed `verify_signature=False` or
unverified claims into a decision:

```python
claims = jwt.decode(token, key, algorithms=["RS256"], audience=settings.oidc_audience, issuer=settings.oidc_issuer,
                    options={"require": ["exp", "sub"]})
```

### SC-AUTHN-005 — Throttle, and give nothing away
**MUST · high** · CWE-307, CWE-204

Sign-in locks an account after five failures (`auth.authenticate`) and nginx rate-limits `/api/auth/login` per IP;
public Trust Center requests are rate-limited per IP in the app. Unknown user, wrong password, disabled and locked
accounts return the same message, and verification runs against a dummy hash so timing is similar.

### SC-AUTHN-006 — Compare secrets in constant time
**MUST · high** · CWE-208

```python
import hmac

ok = bool(supplied) and hmac.compare_digest(ws.csrf_token, supplied)
```

Look tokens up by their hash (`WHERE token_hash = :h`), which avoids comparing secrets in Python at all.

### SC-AUTHN-007 — Store tokens like passwords
**MUST · high** · CWE-312 · ASVS V6

Session tokens, invitation tokens and Trust Center access tokens are stored as SHA-256 hashes, expire, and are
single-use where that applies (invitations). Generate them as described in [SC-CRY-002](/cryptography.md). Never
put them in logs, the audit log, URL paths or query strings: links carry them after `#` (`/invite#token=…`,
`/trust/<slug>#access=…`), and the browser sends them in the `X-Invite-Token` / `X-Trust-Access` header
([SC-CRY-005](/cryptography.md)).
