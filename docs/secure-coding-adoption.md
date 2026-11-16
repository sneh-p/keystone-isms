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

## Escalations (approved by human:sneh and fixed, 2026-11-16)

| Rule | Finding | Fix |
|---|---|---|
| SC-CRY-005, SC-AUTHN-007 | Trust Center access tokens (and invitation tokens) travelled in URL paths and queries, reaching access logs | Links carry tokens after `#`; the browser sends them in `X-Trust-Access` / `X-Invite-Token`; documents download through the browser with the header. Old links still work in the browser |
| SC-CFG-006 / Semgrep `request-host-used` | Invitation and Trust Center links were built from the forwarded `Host` header | `KEYSTONE_PUBLIC_URL` (else the administrator's browser origin); nginx no longer forwards `Host`. The Semgrep baseline was removed |
| SC-SSRF-002 | Website integration: no protection against DNS rebinding, no response size cap | Resolve once, require globally routable addresses, connect to that IP with the original host name for `Host` and TLS; bodies never read |
| SC-LLM-005 | No per-user rate limit or cost budget for AI calls | Calls per user per hour (at the start of an AI action) and a monthly token budget (before every call), under **Settings → AI** |
| SC-CFG-006 | Plain HTTP only | HTTPS production config (`deploy/nginx/keystone.conf`), HSTS on HTTPS responses; the HTTP config is marked for private-network evaluation only |

## Rule-by-rule review (2026-11-16)

Checked what the scanners can't see. Holding: every write path checks a permission; an employee is refused on all
staff read routes; no raw SQL, shell, `eval` or weak randomness; logs use parameters and no secrets; role changes end
sessions; downloads are attachments with `nosniff`.

| Rule | Finding | Fix |
|---|---|---|
| SC-VAL-002 | 180 strings, 13 lists, 10 objects and 51 numbers in request bodies had no bound | Default bounds in `In`; explicit limits on long text and all form fields |
| SC-AUTHN-003 | A password change kept the current session ID (and the rule text said otherwise) | Every session ends and a new session ID and CSRF token are issued |
| SC-AUTHZ-005 | No test kept employees out of read routes | `test_employee_is_refused_on_every_staff_read_route` |
| SC-ERR-004, SC-CFG-004 | Unbounded lists; integration runs added an evidence row per control on every run | Evidence refreshed instead of duplicated; evidence list paged; task history capped |
| — (bug) | Employees couldn't download policies attached as files | `GET /api/portal/policies/{id}/document`: current approved acknowledgement policies only |
| SC-AUTHZ-001 | `answers.draft_batch` relied on its caller's permission check | Checks `questionnaire.write` itself |
| SC-SEC-001 | Test API key used the real key prefix format | Obviously fake value |

## Baseline decisions (confirmed by AppSec, human:sneh, 2026-11-16)

The Semgrep baseline has since been removed (the finding it held back is fixed).

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

## Switching it on

1. Done 2026-11-16: AppSec (human:sneh) signed off every concept (`status: stable`, `verified` recorded in each file
   and in `log.md`); Code Owner team is `@Sneh/appsec`.
2. Branch protection (when the repository is on GitHub): make `security-check` a required status check and
   require Code Owner review on `main`.
3. Done 2026-11-16: baseline decisions confirmed and all escalations fixed.
4. ASVS mappings are chapter-level; verify them against ASVS 5.0 before audit use.
