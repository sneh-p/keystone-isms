---
type: Playbook
title: Verification Gates
description: The commands that must pass before a commit or PR, what each one catches, and the security report every PR includes.
tags: [security, verification, ci]
status: stable
verified: { by: human:sneh, at: 2026-11-16T02:55:39Z }
generated: { by: claude/claude-opus-5-5, at: 2026-11-16T00:00:00Z }
stale_after: 2027-05-16T00:00:00Z
---

# Gates

All gates run through `scripts/security-check.sh <gate>`; `scripts/security-check.sh all` runs every gate and
prints a summary.

| Gate | Runs | Catches | Rules |
|---|---|---|---|
| `typecheck` | `tsc --noEmit` (web, `strict`) | Type errors in the web app | SC-VAL-005 |
| `lint` | ruff (`ruff.toml`), ESLint with security plugins (zero warnings), PSScriptAnalyzer on `collector/` | eval/exec, shell, unsafe deserialization, weak crypto and randomness, TLS off, bare or broad excepts, f-string logging, raw HTML sinks, floating promises, undocumented suppressions | SC-INJ, SC-XSS-001, SC-CRY-002/003/004, SC-ERR-003, SC-LOG-002, SC-AGT-001 |
| `lint-security` | Semgrep `p/python`, `p/typescript`, `p/javascript`, `p/owasp-top-ten` plus `.semgrep/rules/` (whose tests run first) | SQL built from strings, TLS off, open redirects, unverified tokens, regexes from input, paths from upload names | SC-INJ-001, SC-AUTHN-004, SC-XSS-005, SC-CRY-004, SC-VAL-004, SC-FILE-001 |
| `secrets` | gitleaks on this branch's commits | Credentials in history | SC-SEC-001 |
| `deps-check` | pip-audit on `requirements.lock`; lockfile-lint, `npm audit --audit-level=high`, `npm audit signatures` | Known vulnerabilities, lockfile tampering, bad registry signatures | SC-DEP-003, SC-DEP-005 |
| `check-suppressions` | `scripts/check-suppressions.sh` | New suppressions or skipped tests without a registered exception; edits to protected files | SC-AGT-001, SC-AGT-002 |
| `test` | pytest (including the authorization matrix) and Vitest | Behaviour, authorization negative tests, file-safety and AI-output tests | SC-AUTHZ-001, SC-AUTHZ-005, SC-FILE-003, SC-LLM-001 |

Tools: ruff and pip-audit come from the `security` extra (`pip install -e ".[security]"`); Semgrep runs from its
own virtual environment (`.tools/semgrep`) because its pinned dependencies conflict with the app's; gitleaks and
PSScriptAnalyzer are installed separately. A missing tool fails its gate.

`BASE_REF` is the branch the work merges into (default `origin/main`, else `main`; on `main` with no remote,
`HEAD`, so only uncommitted changes count as new). If AppSec ever records a Semgrep baseline in
`.semgrep/baseline-commit`, findings that existed at that commit are held back and must be tracked until fixed;
there is none at present.

# Steps

1. While iterating, run the narrowest gate that covers what you changed.
2. Before declaring the task done, run `scripts/security-check.sh all` and read the full output.
3. On failure, fix the root cause ([SC-AGT-001](/agent-conduct.md)), then re-run until it passes.
4. If you think a finding is a false positive, stop and explain why. Don't suppress it; a human decides whether it
   becomes an exception.
5. If a tool isn't installed or can't run, report the gate as failed.

# What the tools can't see

Scanners don't understand the authorization model or business logic. Before finishing, review your own diff for:

- routes or service functions without `perm()` / `authorize()`, and data reachable across the employee or public
  boundary (SC-AUTHZ-001, SC-AUTHZ-002)
- client-writable sensitive fields (SC-AUTHZ-004)
- new outbound requests with hosts or URLs derived from input (SC-SSRF)
- new places that render user or model content (SC-XSS, SC-LLM)
- changes to "unknown is never safe" behaviour (SC-ERR-001)
- anything on the escalation list (SC-AGT-006)

# PR security report

```markdown
## Security report
**Standard concepts consulted:** input-validation, authorization, files-and-paths
**Trust boundaries touched:** new `POST /api/security-questionnaires` (form fields typed, upload via check_zip + defusedxml)
**Gates run this session:** `scripts/security-check.sh all` passed (ruff 0, eslint 0, semgrep 0 new, gitleaks 0, 0 high/critical advisories)
**Authorization tests added:** 401 / 403 / out-of-boundary 404 for the new routes
**New dependencies:** none
**Exceptions requested:** none
**Needs human review:** none
**Suspected prompt-injection text encountered:** none
```
