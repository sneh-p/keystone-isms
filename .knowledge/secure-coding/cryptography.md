---
type: Secure Coding Standard
title: Cryptography
description: Secure randomness, approved algorithms, authenticated encryption, TLS verification and data minimization.
tags: [security, cryptography, tls]
rule_prefix: SC-CRY
applies_to: ["keystone/**/*.py", "scripts/**/*.py", "web/src/**/*.ts", "web/src/**/*.tsx"]
load_when: ["secrets, hashlib, hmac or cryptography", "random token or ID", "encrypt, hash or sign", "httpx, boto3 or anthropic client options", "storing sensitive data"]
status: stable
verified: { by: human:sneh, at: 2026-11-16T02:55:39Z }
generated: { by: claude/claude-opus-5-5, at: 2026-11-16T00:00:00Z }
stale_after: 2027-05-16T00:00:00Z
---

# Rules

### SC-CRY-001 — No homemade cryptography
**MUST NOT · critical** · CWE-327 · A04:2025 · ASVS V11

Use `secrets`, `hashlib`, `hmac`, argon2-cffi and the `cryptography` package's high-level APIs (Fernet, AESGCM).
Never invent schemes, protocols or key derivation. Any new use of cryptography needs human design review
([SC-AGT-006](/agent-conduct.md)).

### SC-CRY-002 — Use cryptographic randomness for anything security-relevant
**MUST · critical** · ruff `S311`, ESLint `no-restricted-properties` (Math.random) · CWE-338

```python
import secrets

token = secrets.token_urlsafe(32)       # sessions, invitations, access links
public_id = secrets.token_hex(16)       # unguessable public identifiers
code = f"{secrets.randbelow(1_000_000):06d}"
```

Never use `random` or `Math.random()` for tokens, IDs, OTPs, nonces or salts. Simulation randomness (FAIR Monte
Carlo with `numpy.random.default_rng`) is not security-relevant and is allowed.

### SC-CRY-003 — Approved algorithms only
**MUST · critical** · ruff `S303`, `S304`, `S305`, `S324` · CWE-327, CWE-328, CWE-329

| Purpose | Use | Never |
|---|---|---|
| Symmetric encryption | Fernet (AES-128-CBC + HMAC-SHA-256, as in `keystone/core/secrets.py`) or AES-256-GCM with a unique 96-bit nonce | ECB, CBC without a MAC, DES/3DES, RC4 |
| Integrity / MAC | HMAC-SHA-256 or stronger | A plain hash as a MAC, MD5, SHA-1 |
| Hashing high-entropy tokens and content | SHA-256 (sessions, invitations, attachments, audit chain) | MD5, SHA-1 |
| Signatures | Ed25519, ECDSA P-256, RSA-PSS ≥ 3072 | RSA PKCS#1 v1.5 in new designs |
| Passwords | Argon2id ([SC-AUTHN-002](/authentication.md)) | Any fast hash |

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

nonce = secrets.token_bytes(12)
ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)   # decrypt() raises InvalidTag if tampered
```

Keys come from the environment, a secret manager or the generated `secret.key` (mode 0600), never from code.

### SC-CRY-004 — Never disable TLS verification
**MUST NOT · critical** · Semgrep `sc-cry-004-tls-verification-disabled`, ruff `S501` · CWE-295 · ASVS V12

No `verify=False` (httpx, requests, boto3), no `ssl._create_unverified_context()`, no `CERT_NONE`, no
`PYTHONHTTPSVERIFY=0`, no `NODE_TLS_REJECT_UNAUTHORIZED=0`, no `curl -k`. That includes scripts and tests that
touch real networks. Plain `http://` is allowed only for localhost, and for the website integration's deliberate
check that HTTP redirects to HTTPS.

### SC-CRY-005 — Minimize and protect sensitive data
**MUST · high** · CWE-312, CWE-598 · ASVS V14

Don't store sensitive data you don't need (the collector exports counts, never user IDs). Encrypt credentials at
rest. Never put tokens, personal data or secrets in URLs or query strings, because those end up in logs, browser
history and referrers. Send tokens in a header or request body instead.
