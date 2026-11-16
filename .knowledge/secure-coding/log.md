# Secure Coding Standard Update Log

## 2026-11-16
* **Initialization**: Adapted the "Secure Coding Standard for Coding Agents" (TypeScript/Node edition) to
  Keystone ISMS: Python 3 / FastAPI / Pydantic / SQLAlchemy backend, React + TypeScript web app, PowerShell
  collector. Rule IDs and enforcement design kept; code examples and tool configs changed. All concepts drafted
  as `status: draft`. Pending AppSec review and `verified` sign-off.

## 2026-11-16 (sign-off)
* **AppSec sign-off**: all concepts reviewed and approved by human:sneh; `status: stable` with `verified` recorded.
  Code Owner team set to `@Sneh/appsec`.
* **Baseline confirmed**: the Semgrep baseline commit (`request-host-used` in `deploy/nginx/keystone-proxy.conf`), the
  `ruff.toml` per-file-ignores for tests and the demo password, and the scanner exclusions listed in
  `docs/secure-coding-adoption.md` are accepted until the listed escalations are fixed.

## 2026-11-16 (review findings and escalations)
* **Approved by human:sneh** ("all is approved"): fixes from the rule-by-rule review and the five escalations.
  Concept text updated to match: SC-VAL-002 (default bounds in `In`), SC-AUTHN-003 (session rotation on password
  change), SC-AUTHN-007 / SC-CRY-005 (tokens only in fragments and headers), SC-SSRF-002 (IP pinning, bodies not
  read), SC-LLM-005 (rate limit and budget), SC-CFG-004 / SC-CFG-006 (bounded lists, HTTPS config, HSTS, no Host
  header), SC-ERR-004 (evidence refreshed, not duplicated). Semgrep baseline removed: no baselined findings remain.
