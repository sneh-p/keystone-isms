# Secure coding standard: adoption report (2026-11-16)

This records the first run of the gates against the repository ("Run the gates against current main first") and
how each finding was triaged. It is the "adoption report" that `.knowledge/secure-coding/verification.md` and the
Semgrep baseline refer to.

## Fixed in the adoption change

| Rule | Finding | Fix |
|---|---|---|
| SC-FILE-003, SC-FILE-004 | Uploaded questionnaires (.xlsx) were parsed by openpyxl with no zip-bomb or path checks and without defusedxml | `keystone/core/safe_files.py` (`check_zip`, `require_defused_xml`); `defusedxml` added; tests in `tests/test_safe_files.py`, including an XXE workbook |
| SC-SSRF-001, SC-VAL-002 | AWS region not validated (boto3 builds endpoint host names from it); GitHub organisation only rejected `/` | Strict allowlist patterns, GitHub client refuses redirects; tests added |
| SC-ERR-004 | AWS calls relied on boto3's default timeouts | Explicit connect/read timeouts and bounded retries |
| SC-LLM-001 | Claude output was used as a loose dict | Strict Pydantic models validate policy revisions and drafted answers before use |
| SC-LLM-006, SC-XSS-002 | Markdown rendered remote images and links without a scheme check | `Markdown.tsx` shows image alt text only and links via `safeHref()` |
| SC-XSS-005 | Post-sign-in navigation used router state unchecked | `safeRedirectPath()` with Vitest tests |
| SC-ERR-002 | Unexpected errors fell through to the framework default | Catch-all handler: generic message plus request ID, details only in the log |
| SC-CFG-005 | Interactive API docs and the OpenAPI schema were public | Off unless `KEYSTONE_API_DOCS=1` |
| SC-ERR-003 | Five unhandled promises in the web app | Awaited or given rejection handlers |
| SC-AGT-001 | Four undocumented ESLint disable comments (react-hooks) | Code restructured so no suppression is needed |
| SC-DEP-003 | Python dependencies unpinned (`>=` ranges, no lockfile) | Hash-locked `requirements.lock`; Docker and CI install with `--require-hashes` |
| SC-DEP-004 | npm install scripts enabled | `web/.npmrc`: `ignore-scripts`, `save-exact`, `min-release-age=7` |
| SC-DEP-005 | 2 critical and 1 high npm advisories (Vitest 2 and its nested Vite/tinypool, dev tooling) | Vitest upgraded to 5.1.0 after SC-DEP-002 checks |
| — | `assert` used for a runtime check in `keystone/core/db.py` (stripped under `python -O`) | Explicit check |

## Needs a human decision (SC-AGT-006 escalations)

| Rule | Finding | Recommended fix |
|---|---|---|
| SC-CRY-005 | Trust Center access tokens travel in API URL paths (`/api/public/trust/<slug>/access/<token>`), so they reach proxy and server access logs | Send the token in a header (for example `X-Trust-Access`) or a POST body; keep it out of URLs |
| SC-CFG-006 / Semgrep `request-host-used` (baselined) | Invitation and Trust Center links are built from `request.base_url`, which comes from the forwarded `Host` header (nginx passes `$http_host`) | Add a `KEYSTONE_PUBLIC_URL` setting for links; restrict `server_name` in nginx |
| SC-SSRF-002 | The website integration resolves and checks the host, re-validates redirects and has timeouts, but does not connect to the validated IP (DNS rebinding) and does not cap the response size | Pin the connection to the validated address or route through an egress proxy; cap the body size |
| SC-LLM-005 | AI calls have token limits, timeouts and per-user accounting, but no per-user rate limit or cost budget | Hourly per-user limit and a monthly token budget in **Settings → AI** |
| SC-CFG-006 | The evaluation server is served over plain HTTP on port 80 | TLS at the proxy before real use (see the admin guide) |

## Baseline decisions to confirm (AppSec)

- `.semgrep/baseline-commit` holds back the one Semgrep registry finding present at adoption
  (`request-host-used` in `deploy/nginx/keystone-proxy.conf`, above).
- `ruff.toml` `per-file-ignores`: pytest asserts, fake test passwords and the e2e server launch in `tests/`; the
  fictional demo password in `keystone/demo.py`.
- `.semgrepignore` and the suppression check exclude the standard's own text, the lint configs, the Semgrep rule
  tests and `tests/test_check_suppressions.py`, which contain suppression keywords by design.

## Tracked moderate advisories (npm, SC-DEP-005 medium)

| Package | Why it stays | Revisit when |
|---|---|---|
| `minimatch` via `typescript-eslint` 8.72.2 (lint tooling only) | No typescript-eslint 8.x allows the fixed version; forcing it with `overrides` is not allowed | typescript-eslint ships a fix |
| `react-router` / `react-router-dom` 6 | The advisory affects server-side rendering hydration; this app renders only in the browser. The fix is a major upgrade to v7 | Planned React Router 7 upgrade |

## Gates not yet running everywhere

- **secrets (gitleaks)**: not installed in the development environment, so the gate fails there. CI installs a
  checksum-verified release.
- **npm `min-release-age`**: enforced only by npm 11.10 or later. CI installs npm 11.21.2; the development
  environment has npm 9.2, which ignores the setting. The deps-check gate runs `npm audit` and
  `npm audit signatures` through a pinned npm 11.21.2 because npm 9.2 can't verify the registry's rotated keys.
- **Python type checking**: no mypy gate yet.

## Before switching it on

1. AppSec reviews each concept, replaces `@your-org/appsec` in `.github/CODEOWNERS`, adds
   `verified: { by: human:<id>, at: <timestamp> }`, sets `status: stable`, and records it in `log.md`.
2. Branch protection: make `security-check` a required status check and require Code Owner review on `main`.
3. Confirm or change the baseline decisions above, and schedule the escalations.
4. ASVS mappings are chapter-level; verify them against ASVS 5.0 before audit use.
