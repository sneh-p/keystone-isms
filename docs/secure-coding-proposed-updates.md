# Updates to the secure coding standard after sign-off (applied)

The standard in `.knowledge/secure-coding/` and `AGENTS.md` are protected files: agents may not edit them, and
`scripts/check-suppressions.sh` blocks commits that do. Since sign-off on 2026-11-16, features approved by AppSec
(human:sneh) changed facts the standard states. The rules still hold; some descriptions and examples no longer match the
code. Below is each outdated passage and proposed replacement text. After review, apply them in one change with a
`log.md` entry and re-record `verified` on the changed concepts.

Prepared and, on approval by human:sneh ("Apply them"), applied on 2026-11-16; recorded in `.knowledge/secure-coding/log.md`.
The passages below are kept as the record of what changed and why.

## authentication.md

**SC-AUTHN-001**: the list of public routes.

> Every route requires a signed-in session except the explicit, reviewed `PUBLIC` set in `tests/test_api.py` (sign-in,
> first-run setup, invitation acceptance, the public Trust Center).

Proposed:

> Every route requires a signed-in session except the explicit, reviewed `PUBLIC` set in `tests/test_api.py` (sign-in,
> first-run setup, invitation acceptance, the public Trust Center, the vendor portal, and the single sign-on start and
> callback redirects).

**SC-AUTHN-004**: add how OIDC is done here (the rule already anticipates it).

> Single sign-on (`keystone/sso/service.py`) follows this: Authlib/joserfc, RS256 only, issuer, audience, expiry, iat,
> sub and nonce required; Entra tokens must carry the configured tenant; state and nonce are single-use, expire after 10
> minutes and are bound to the browser by an HttpOnly cookie; accounts are found by issuer and subject.

**SC-AUTHN-007**: add vendor portal tokens and SSO login state.

> Session tokens, invitation tokens, Trust Center access tokens and vendor portal tokens are stored as SHA-256 hashes,
> expire (vendor portal links only when staff set an expiry, an accepted decision), and are single-use where that
> applies (invitations, SSO login state). … links carry them after `#` (`/invite#token=…`, `/trust/<slug>#access=…`,
> `/vendor-portal#token=…`), and the browser sends them in the `X-Invite-Token` / `X-Trust-Access` / `X-Vendor-Token`
> header.

## authorization.md

**SC-AUTHZ-006**: the list of read-only integration identities.

> Integration credentials are read-only (GitHub fine-grained read, AWS `SecurityAudit`, read-only API roles for the
> attack surface sources: Microsoft 365 application read permissions, CrowdStrike Hosts read, SentinelOne Viewer, Sophos
> Service Principal ReadOnly, read-only RMM and scanner users), the collector uses a read-only Entra role, …

Also worth a sentence under object-level checks: stored files are served by `GET /attachments/{id}` only through the
record they belong to (`DOWNLOAD_PERMISSION` in `keystone/core/attachments.py`).

## outbound-requests.md

**SC-SSRF-001**: name the shared client and the vendor-domain rule.

> Attack surface connectors go through `keystone/integrations/http.py`: each declares exact vendor hosts, or the vendor's
> domain for customer-specific consoles (for example `*.sentinelone.net`, `*.central.sophos.com`); pagination links
> returned by an API are checked against the same rule.

**SC-SSRF-002**: other admin-chosen hosts besides the website integration.

> Three features reach hosts an administrator chooses: the website integration, the SMTP relay
> (`keystone/notifications/mailer.py`) and self-hosted RMM servers (N-central, ConnectWise Automate). All resolve once,
> require public addresses and connect to the validated IP. An internal SMTP relay or RMM server is allowed only when
> the server operator lists its name in `KEYSTONE_SMTP_PRIVATE_HOSTS` or `KEYSTONE_INTEGRATION_PRIVATE_HOSTS`, never from
> the web UI; loopback, link-local and metadata addresses are refused even then.

The last sentence of SC-SSRF-002 ("reuse this code rather than hand-rolling a new fetcher") should point to
`keystone/integrations/http.py`, which reuses the website integration's validation and pinning.

**SC-SSRF-003**: the current text is literally inaccurate.

> Credentials are sent only to the fixed hosts in SC-SSRF-001.

Proposed:

> Credentials are sent only to hosts the connector's policy allows (SC-SSRF-001). Where an administrator chooses the host
> (SMTP relay, self-hosted RMM servers), the stored credential is bound to that host: changing the host discards it, so
> it can't be redirected to a host it wasn't entered for.

## secrets.md

**SC-SEC-006**: rotation of `secret.key`.

> For `secret.key`, rotation means re-entering every integration, attack surface source, SMTP, single sign-on and AI
> credential.

## http-and-config.md

**SC-CFG-003**: public write routes.

> Public write routes (Trust Center requests, invitation acceptance, the vendor portal) carry no session, are
> rate-limited, and are authorised by a token in a request header.

**SC-CFG-004** could mention the new limits: CSV import 1,000 rows, bulk changes 500 records, vendor uploads 10 MB and
20 files, audit pack 500 MB, connector responses 50 MB and page caps, calendar 100 days.

## files-and-paths.md

**SC-FILE-002**: add scanning and in-app viewing.

> - Files from outside the company (vendor portal uploads) are scanned by ClamAV before storage, and refused when the
>   scanner can't give a clean verdict (`keystone/core/antivirus.py`).
> - The document viewer never serves files inline: it fetches the bytes and builds a Blob with a type it chooses (PDF,
>   images, plain text); HTML and SVG are never rendered.

## agent-conduct.md and AGENTS.md

The stop-and-ask item "let the app call Microsoft Graph" was decided for one case on 2026-11-16. Proposed wording:

> - change what the collector reads, or let the app call Microsoft Graph beyond the read-only Microsoft 365 attack
>   surface source (decided 2026-11-16)

`AGENTS.md` has the same item ("letting the app call Microsoft Graph"); the same change applies there. Nothing else in
`AGENTS.md` or `CLAUDE.md` is outdated.

---

# Round 3 (2026-11-17): proposed updates, not yet applied

Round 3 was approved by human:sneh ("Implement all other recommendations. I approve all changes"). The concepts below
describe facts that round 3 changed. As before, these files are protected: the text here is a proposal for AppSec to
apply (or reject) in one change with a `log.md` entry.

## Decision needed: SC-LLM-004 and two AI features that were not built

The round 3 plan included four AI features. Two conflict with **SC-LLM-004** (MUST NOT · critical): *"Never send
credentials, people or user records, risks, incidents, evidence files, audit-log entries or draft policies."*

- **Evidence review** (Claude judges whether an evidence item supports its control) needs the evidence content.
- **Audit-prep assistant** (questions answered from Keystone's own records, with citations) needs controls, evidence,
  risks, findings and nonconformities in the prompt.

Following AGENTS.md ("if this standard conflicts with a task instruction, stop and explain the conflict"), these two
were **not built**. The two that fit the rule were: control narratives and risk suggestions (contexts in the admin
guide). If AppSec wants the other two, a proposed amendment:

> SC-LLM-004 … Never send credentials, people or user records, incidents or audit-log entries. **Evidence and risk
> records may be sent only by the evidence review and audit-prep features, only for records the user can read, only
> when an administrator has turned that feature on separately under Settings → AI (off by default), and never
> evidence files of the types listed in SC-FILE-002 as external uploads.** Draft policies are never sent.

Plus a DPIA-style note in `docs/design-decisions.md` on sending ISMS records to Anthropic, and tests that each feature's
prompt contains only readable records.

## Facts that changed (wording proposals)

**authentication.md**
- SC-AUTHN-001: add to the public routes "the SCIM 2.0 endpoints (`/api/scim/v2/*`, authorised by a provisioning
  token)".
- SC-AUTHN-004: "Single sign-on supports Microsoft Entra ID, Google and Okta (Okta-hosted domains only)."
- SC-AUTHN-007: add "SCIM provisioning tokens and personal API tokens (`kst_`) are stored as SHA-256 hashes, shown
  once, expire (API tokens within a year), and can be revoked; API tokens act as their owner, read scope allows only
  GET/HEAD, and they are refused for `/api/auth`, `/api/tokens`, `/api/users`, `/api/settings/*` and `/api/scim`."

**authorization.md**
- New permissions: `privacy.write`, `continuity.write`, `access_review.manage` (added; no role lost a permission).
- SC-AUTHZ-006 (read-only integrations): add the cloud posture sources (AWS Security Hub read-only policy, Defender for
  Cloud Security Reader, Google SCC Findings Viewer) and HR systems; and an exception paragraph: "Ticketing connectors
  (Jira, ServiceNow, ConnectWise PSA, Autotask) write, but only to create tickets; they never edit, comment, transition
  or close."
- SCIM can't see or change administrator accounts and never changes roles.

**outbound-requests.md**
- SC-SSRF-001 host list: `www.cisa.gov`, `epss.empiricalsecurity.com`, `crt.sh`, `management.azure.com`,
  `oauth2.googleapis.com`, `securitycenter.googleapis.com`, `*.atlassian.net`, `*.service-now.com`, ConnectWise cloud
  API hosts, `*.autotask.net`, `api.bamboohr.com`, `api.personio.de`, `api.hibob.com`, `hooks.slack.com`, Teams
  Workflow hosts, Okta-hosted domains.
- SC-SSRF-002 (admin-chosen hosts): add outbound webhooks and self-hosted ConnectWise PSA; and the external attack
  surface scan, which only probes hosts under a domain verified by a DNS TXT record.

**files-and-paths.md**
- SC-FILE-003: "Backups (`keystone/ops/backup.py`) are read member by member against an allowlist of names, checked
  against the manifest's SHA-256 before anything is written, and attachments are written only under their own
  verified hash; restore is a command-line operation into an empty database."

**secrets.md**
- SC-SEC-006 (rotation of `secret.key`): add ticketing, cloud posture, HR, outbound destination URLs and webhook signing
  secrets; and note that backups deliberately exclude the key.

**dependencies.md**
- Note the round 3 additions and their reasons: psycopg (PostgreSQL), dnspython (TXT/SPF/DMARC/CAA lookups), reportlab
  (policy and board PDFs; brings pillow and charset-normalizer), mypy (type gate, security extra).

**verification.md**
- `typecheck` now runs mypy (settings in `pyproject.toml`) as well as tsc.

## Configuration agents (2026-11-17)

- **Lint gate coverage for the agents.** `scripts/security-check.sh lint` runs PSScriptAnalyzer on `./collector`
  only. The new Windows agent in `agents/windows` was checked by hand (`Invoke-ScriptAnalyzer -Path ./agents/windows
  -Recurse`, no findings at any severity), and its Pester tests (`tests/agents`) pass. Proposed: add `./agents` to the
  PSScriptAnalyzer step and run `Invoke-Pester ./tests/agents` in the gate. Add shellcheck for `agents/linux` when it
  is available. `scripts/security-check.sh` is a protected file, so this needs a human to apply it.
- **A stored device credential.** The original spec says no tokens or secrets on disk. That was written for the
  collector, and a scheduled agent needs a stored credential. See feature-security-designs.md §5b for how the device
  token is limited, and confirm the deviation.
