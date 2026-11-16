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
