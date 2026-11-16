---
type: Secure Coding Standard
title: Secrets Management
description: Keep credentials out of source, history, logs, the web bundle and prompts; load them from the environment or encrypted storage.
tags: [security, secrets, configuration]
rule_prefix: SC-SEC
applies_to: ["**/*"]
load_when: ["API key, password, token or connection string", "settings or environment variables", "integration credentials", "Dockerfile, compose or CI", "web environment variables", "test fixtures"]
status: stable
verified: { by: human:sneh, at: 2026-11-16T02:55:39Z }
generated: { by: claude/claude-opus-5-5, at: 2026-11-16T00:00:00Z }
stale_after: 2027-05-16T00:00:00Z
---

# Rules

### SC-SEC-001 — No secrets in the repository
**MUST NOT · critical** · gitleaks, ruff `S105`, `S106`, `S107` · CWE-798, CWE-540 · ASVS V13

Never put credentials, keys, tokens or password-bearing connection strings in source, tests, fixtures, docs,
comments, Dockerfiles, compose files, CI YAML or examples. Use obvious placeholders such as `<DATABASE_URL>`.
Test values must not look like real credentials: no real-format API keys, use clearly fake values such as
`test-key-not-a-secret`, and keep demo passwords in `keystone/demo.py` only for the fictional demo.

### SC-SEC-002 — One settings module, no secret fallbacks
**MUST · high** · CWE-1188

Runtime configuration is read in `keystone/core/settings.py` (and `keystone/core/secrets.py` for the encryption
key). A secret has no hard-coded default:

```python
# Do: fail at start-up when the key can't be loaded
key = os.environ.get("KEYSTONE_SECRET_KEY") or _load_or_create_key_file(data_dir / "secret.key")  # generated, 0600

# Don't
key = os.environ.get("KEYSTONE_SECRET_KEY", "dev-secret")
```

A default secret becomes the production secret the day the variable goes missing.

### SC-SEC-003 — Secrets never leave through side channels
**MUST NOT · critical** · CWE-532, CWE-209

Never put secrets in logs, the audit log, API responses, error messages, exports or LLM prompts. Credential
columns are encrypted (`secret_enc`, `api_key_enc`), write-only in the API (only "is set" is returned), and listed in
`__audit_redact__` so the audit log records only that they changed. See [Errors and Logging](/errors-and-logging.md).

### SC-SEC-004 — The web bundle is public
**MUST NOT · critical** · CWE-200

Browser code receives only non-secret values; only `VITE_`-prefixed variables reach the bundle, and none may hold
a secret. Calls that need a credential (integrations, the Claude API) go through the backend.

### SC-SEC-005 — Keep env files and data out of git
**MUST · high**

`.env*`, `data/`, `output/`, `*.db` and `secret.key` are git-ignored. Real values come from the environment,
the deployment platform or the encrypted settings in the database.

### SC-SEC-006 — Exposed means compromised
**MUST · critical**

Rotate any secret that was committed, logged, pasted into a ticket or chat, or sent to a third party. Removing it
from the code doesn't remove it from git history or logs. For `secret.key`, rotation means re-entering every
integration and AI credential.
