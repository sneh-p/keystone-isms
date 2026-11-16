---
type: Secure Coding Standard
title: Dependencies and Supply Chain
description: How to add, pin, install and audit Python and npm packages, and how to keep CI and container builds from becoming the attack path.
tags: [security, supply-chain, dependencies, ci]
rule_prefix: SC-DEP
applies_to: ["pyproject.toml", "requirements.lock", "web/package.json", "web/package-lock.json", "web/.npmrc", ".github/workflows/**", "Dockerfile*", "docker-compose*.yml", "collector/**/*.ps1"]
load_when: ["pip install", "npm install", "importing a new external package", "Install-Module", "upgrading packages", "editing CI, Dockerfile or compose"]
status: draft
generated: { by: claude/claude-opus-5-5, at: 2026-11-16T00:00:00Z }
stale_after: 2027-05-16T00:00:00Z
---

# Rules

### SC-DEP-001 — Justify every new dependency
**MUST · medium** · A03:2025

Prefer the standard library and packages already in the tree. Every new dependency needs a one-line
justification in the PR.

### SC-DEP-002 — Verify a package before installing it
**MUST · critical** · CWE-1357, CWE-506 · A03:2025

Before installing, confirm the package exists, the name is spelled exactly right, the repository link points
where you expect, it has been maintained recently, and whether it runs install scripts (npm) or ships only an
sdist that executes `setup.py` (PyPI).

```bash
npm view <name> name version repository.url time.created time.modified maintainers scripts.preinstall scripts.install scripts.postinstall
curl -s https://pypi.org/pypi/<name>/json | python3 -c 'import json,sys; i=json.load(sys.stdin)["info"]; print(i["name"], i["version"], i["project_urls"])'
```

Don't install it if it doesn't exist (the name may be invented), it's only days old, it has install scripts you
can't justify, it is sdist-only without a reason, or its name is one character away from a popular package.
Summarize the output in the PR. PowerShell modules for the collector are limited to
`Microsoft.Graph.Authentication`, Pester and PSScriptAnalyzer from the PowerShell Gallery.

### SC-DEP-003 — Pin and lock
**MUST · high** · CWE-1104

- Python: `pyproject.toml` states compatible ranges; `requirements.lock` pins every runtime package with hashes
  and is what the container and CI install (`pip install --require-hashes -r requirements.lock`). Regenerate it with
  `uv pip compile pyproject.toml --generate-hashes --python-version 3.12 --no-strip-extras -o requirements.lock`
  (uv runs from `.tools/uv`). Tool extras (`security`) use exact versions.
- npm: add packages with exact versions (`save-exact=true` in `web/.npmrc`), commit `web/package-lock.json`, and
  use `npm ci` in CI and Docker.

Never delete or regenerate a lockfile to get past a conflict; resolve the conflict instead.

### SC-DEP-004 — Install scripts are off by default
**SHOULD · high** · CWE-829

`web/.npmrc` sets `ignore-scripts=true`. If a package genuinely needs its install script, run it explicitly with
`npm rebuild <name>` and note it in the PR. For Python, prefer wheels; an sdist-only dependency needs a reason in
the PR.

### SC-DEP-005 — No new known vulnerabilities
**MUST · high** · `pip-audit --require-hashes -r requirements.lock`, `npm audit --audit-level=high`, `npm audit signatures` · CWE-1395

Fix advisories by upgrading. Don't silence them (`--ignore-vuln`), don't use `overrides` to pin vulnerable
versions, and don't run `npm audit fix --force` without review, since it applies breaking major upgrades.

### SC-DEP-006 — Harden the pipeline
**MUST · high** · A08:2025 · CWE-494

- Pin GitHub Actions to full commit SHAs, not tags.
- Declare least-privilege `permissions:` in every workflow.
- Never use `pull_request_target` together with a checkout of PR code.
- No `curl | sh`; verify the checksum of every downloaded binary (gitleaks, Semgrep version pins).
- Pin container base images by digest, not by moving tags.

### SC-DEP-007 — Copied code is a dependency too
**SHOULD · medium**

Review code pasted from the web or suggested by an AI the same way you would a package: check its licence,
understand what it does, and hold it to this standard. Code from AGPL projects (for example Comp AI) is never
copied into this repository.
