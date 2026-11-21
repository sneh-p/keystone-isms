# Design decisions and deviations

This records choices made while building Keystone where the original specifications were
silent, ambiguous, or conflicted with how Microsoft Graph or the standards actually work.

## Scope

- **From "Vendor Exposure Map for an MSP" to "Keystone ISMS for one organisation".** The
  original spec targeted an MSP collecting client tenants over GDAP and feeding VendorFAIR. The
  project was renamed and widened to a full ISMS for a single organisation. The exposure map
  became part of third-party risk; "client tenants" became the organisation's own Entra tenants
  (main tenant and subsidiaries). GDAP, PIM and Autotask wording became optional (a generic
  change or ticket reference). The `collected.json` schema did not change.
- **VendorFAIR.** No VendorFAIR code existed, so Keystone contains its own FAIR engine, vendor
  register and vendor assessments; the exposure module's suggestions target those.

## Framework content

- Only NIST CSF 2.0 ships with full text (public domain). ISO/IEC 27001, the AICPA TSC and CIS
  Controls are copyrighted (CIS under CC BY-NC-ND), so Keystone ships identifiers with short
  titles in its own words, and an import for licensed official text that is stored only in the
  database. A loader check rejects restricted packs with long text or a `licensed_text` field.
- The common control set is the ISMS clauses (14 controls) plus one control per Annex A control
  (93), plus 11 privacy and 10 AI governance controls added in round 3: 128 in total. Every leaf requirement of all
  twelve frameworks is mapped (tested). Privacy controls also serve ISO 27001 A.5.34; AI governance controls have no
  ISO 27001 counterpart and map only to ISO 42001 (the test allows exactly that). The crosswalk is original work and
  labelled as a starting point.
- **Round 3 packs.** EU legislation (NIS2, DORA, GDPR) may be reused, but the packs still carry short summaries at
  article level, so all non-public-domain packs follow one rule: titles of 80 characters or fewer, no descriptions.
  ISO/IEC 27701 uses the 2019 numbering because most certificates still reference it; the 2025 edition restructures
  the standard and will need its own pack. PCI DSS is listed at the x.y level; the x.y.z defined-approach
  requirements can be imported from a licensed copy. Packs new to an existing installation are added switched off at
  start-up (`loader.sync_bundled`), so an upgrade never changes what an organisation reports against.

## Microsoft Graph realities (collector)

- **Third-party credentials are mostly invisible.** A multi-tenant vendor app's secrets live in
  the vendor's tenant. The collector reads app-registration credentials (internal apps) and
  credentials on service principals in the tenant. A credential on a *third-party* service
  principal is flagged (rule C4) as a possible persistence technique.
- **No `$batch`.** Graph JSON batching is a POST, which the GET-only rule forbids, so per-app
  `appRoleAssignments` calls are made one by one (Microsoft-owned apps are skipped).
- **Write-scope detection** also matches `AccessAsUser` (e.g. `Directory.AccessAsUser.All`).
- **The `credentials` dataset is `null` if either of its two endpoints fails**, so a partial
  credential list is never mistaken for a complete one. The two consent-policy endpoints are
  independent, so each can be `null` on its own.
- Graph's `principalId` on app role assignments (the client app) is exported as
  `servicePrincipalId`, so no `principalId` key appears anywhere in the output.
- **P1 detection** requires `AAD_PREMIUM`/`AAD_PREMIUM_P2` with provisioning status `Success`
  on an enabled SKU. Without P1, the sign-in report is not queried and its status is
  `unavailable_license`.
- **Absent from a successful sign-in report** counts as dormant (decided with the user), with
  the reason "No sign-in recorded". Dormancy is `null` only when the report itself was
  unavailable.
- Managed identities (null owner) are classified `internal`. Other null owners are `unknown`
  and flagged for review. They are never assumed to be Microsoft.

## Exposure rules

- Added fallback **R8** (Low) for apps that match no rule (e.g. SSO-only apps). R6 reads
  "delegated **high or above**" so that user-consented critical permissions on verified apps
  are not left unscored.
- Additional critical permissions beyond the seed list are marked `# added` in
  `config/permission_tiers.yaml`.
- Every matching rule is recorded as a reason; the first sets the level. R0 (incomplete data) is
  a modifier and never lowers the level.
- `user_consent_count` is the largest per-resource count, a lower bound on distinct users,
  because the collector deliberately exports counts rather than user IDs.
- Integration depth: any app-only permission is "Tenant-wide application access", with rule ID1
  for high or critical permissions and ID1b for lower tiers, since app-only access is
  tenant-wide by nature.
- Control-strength suggestions start from the assessment's current range, or from
  `control_strength_default` in `config/fair_suggestions.yaml` when it has none.

## Platform

- **Web app (v2).** The Streamlit UI was replaced by a React single-page app (Vite, TypeScript,
  Tailwind, Radix primitives) over a FastAPI API. The API routers are thin: every rule still
  lives in the `keystone/<module>/service.py` functions, which check permissions themselves, so
  the API and the services can't disagree. A test fails if a write route has no declared
  permission, and an authorisation matrix checks every write route against every role.
- **Sessions.** Server-side sessions in the database; the browser holds only a random token in
  an `HttpOnly`, `SameSite=Lax` cookie (`Secure` over HTTPS) and the database stores its hash.
  Unsafe requests need a CSRF header matching the session. Sessions have an idle and an
  absolute timeout; disabling a user or offboarding a person ends their sessions. Reloading
  the page no longer signs you out.
- **Workflows inspired by Comp AI.** Onboarding, evidence tasks, the employee portal, the Trust
  Center, integrations and security questionnaires follow the product ideas of the open-source
  Comp AI platform. Comp AI is AGPL-3.0, so nothing was copied: the code, templates, training
  text and task library are written for Keystone.
- **Control readiness** combines approved linked policies, current evidence, no overdue tasks
  and no failing or erroring integration checks. Only implemented controls that are ready are
  shown as passing on the Trust Center; unknown is never shown as passing.
- **Integrations** are read-only and pull-based on an in-process scheduler (APScheduler). The
  Entra integration derives its checks from the imported collector snapshots and doesn't call Microsoft Graph; only
  the Microsoft 365 attack surface source does (read-only, see below). Credentials are Fernet-encrypted and write-only.
- **Email** is used for the daily notification digest only (custom SMTP relay, TLS required, IP-pinned,
  public relays unless the operator allowlists an internal one). Invitation and Trust Center links are still shown
  to copy rather than emailed.
- **Notifications** are derived: an hourly job turns the same rules as "My tasks" (within 14 days) into inbox items
  per user, deduplicated by a hash of the item, and resolves items that no longer apply.
- **Vendor portal links don't expire by default** (organisation decision, 2026-11-16). Mitigations: one link per
  questionnaire (a new one revokes the old), revocation, optional expiry, read-only after submission, rate limits,
  and all vendor actions audited.
- **File downloads by number** (`GET /api/attachments/{id}`) are checked against the record a file belongs to
  (`DOWNLOAD_PERMISSION` in `keystone/core/attachments.py`): evidence, task, policy, customer-questionnaire and
  vendor-portal files need `read`; gated Trust Center documents need `trust.manage`; employees' device screenshots,
  files a vendor removed and unlinked files are never served there. Refusals look like a missing file (404). A test
  fails if a new kind of upload appears without being classified.
- **Document viewer** keeps SC-FILE-002 (files are always served as attachments): the browser fetches the bytes and
  shows PDFs, images and text from a Blob whose type Keystone sets; other types download. Office files are not
  previewed (that would need server-side conversion).
- **SSO account matching**: by (issuer, subject) once linked; the first sign-in links a pre-created account by email
  (Entra: single tenant only; Google: verified email). Automatic accounts only for approved domains, Employee or
  Viewer role. Authlib 1.9.5 / joserfc 1.8.0; provider endpoints fixed in code, no discovery fetch.
- **No device agent.** The employee portal's device checks are self-attested with an optional screenshot and expire
  after a set period. Device posture reported by your own tools (RMM, EDR, Intune) comes in through attack surface
  management instead; Keystone ships no agent of its own.
- **Dashboard trends** come from a `metric_snapshots` table: one row per day (a scheduled job, idempotent per day),
  shown weekly (the last snapshot of each of the previous 11 weeks plus today's live values). Snapshots are derived
  data, so they are not audited. The demo seeds 11 weeks of fictional history.
- **Bulk changes** go through the same service function as a single edit, once per record, inside one transaction:
  each record is audited, and one refusal rolls back the lot. Bulk status can't be "not applicable", which needs a
  reason per control.
- **CSV import without file upload.** The browser reads and parses the CSV and sends the rows as JSON (at most 1,000,
  bounded like every request body), so the server never stores or parses a file. Columns come from a fixed list per
  register (unknown columns are refused), values are converted strictly, and each row is saved through the
  register's service. A preview runs the import in a separate transaction that is always rolled back, so it applies
  the real rules (including duplicates within the file) and saves nothing; the import itself is all or nothing.
- SQLite by default; PostgreSQL is supported and the whole test suite runs against it
  (`scripts/test-postgres.sh`). Migrations are applied at start-up. The audit-log immutability triggers exist for
  SQLite and PostgreSQL; on PostgreSQL a statement-level trigger also refuses `TRUNCATE`, which skips row triggers.
- **Backups are Keystone's own format, not a database dump.** A gzip'd tar of every table as JSON lines plus the
  stored files, with a SHA-256 per part in a manifest. Chosen over `sqlite3 .backup` / `pg_dump` because the same file
  restores into either database (so it doubles as the SQLite → PostgreSQL migration path), needs no database client
  tools in the image, and can be verified end to end: every nightly backup is restored into a scratch SQLite database
  and the audit log's hash chain is re-checked before it counts as verified. Values are decoded by column type, so
  user JSON can never be mistaken for an encoded value. Restore is command-line only, into an empty database, from the
  same schema revision; archives are read member by member against an allowlist of names, never extracted by the
  names they contain. The encryption key is left out on purpose (a backup plus its key decrypts every stored
  credential). Limit: tables are held in memory during backup and restore (attachments are streamed), which is fine
  for an ISMS's size but not for gigabytes of rows.
- **Vulnerability prioritisation uses whole public files.** KEV is a 2 MB JSON catalogue; EPSS publishes a ~3 MB
  gzip'd CSV of every CVE daily. Downloading both whole (instead of querying the EPSS API per CVE) means no third party
  learns the organisation's vulnerabilities, at the cost of a few MB a day. The EPSS file is decompressed with a 200 MB
  cap and only scores for CVEs Keystone has seen are stored. Priority and fix-by are stored on each vulnerability and
  recomputed after each import, feed refresh or policy change, so lists and the dashboard don't recompute them per
  request. The rules (P1 KEV, P2 EPSS ≥ threshold or exploit on critical/high, P3 critical/high, P4 rest) are
  deliberately simple and shown in the app; they are a starting point, not SSVC.
- **External attack surface is passive and ownership-gated.** A domain is enumerated only while a Keystone-generated
  TXT record is published, re-checked before every scan, so the feature can't be pointed at someone else's estate.
  Discovery is certificate transparency (crt.sh) and DNS through the server's resolver (dnspython; no DNS-over-HTTPS
  provider sees the queries). Probing reuses the website check: ports 443 and 80, public addresses only, pinned
  connections. No port scanning, by decision: it's noisy, often against hosting providers' terms, and better done by a
  dedicated scanner that can feed Keystone through the vulnerability connectors. Dangling-CNAME detection requires a
  definite NXDOMAIN, so providers that answer NODATA for missing names produce no alert (false negatives over false
  positives). Results are derived data; domains (and their verification) are audited.
- **Ticketing writes, narrowly.** The four ticketing connectors are the only ones that write to another system, and
  they only create tickets and read status: no updates, comments, transitions or closing, so a compromised Keystone
  can at worst create tickets. Ticket text is built server-side from the record (never request text), incidents send
  no details, and the link back is to Keystone, so the ticket system doesn't become a second copy of sensitive data.
  Status flows one way: a closed ticket notifies the person who raised it but never closes the Keystone record, which
  keeps verification in Keystone. Automatic tickets are capped per run to avoid flooding a service desk.
- **Privacy records minimise themselves.** Data subject requests are the one register that exists to hold a
  private individual's details, so those fields are redacted in the hash-chained audit log (which can never be edited
  later) and cleared from the record a year after closing by a daily job; the request remains as proof it was
  handled. The breach log doesn't duplicate incidents: it adds an Article 33(5) assessment to each incident involving
  personal data, and takes deadlines and notification dates from the incident.
- **Continuity tests produce evidence.** A recorded test is compared with each process's RTO and RPO, can't be marked
  passed if an objective was missed, and files evidence on KC-ORG-29/30, so "tested within the year" is visible on the
  controls without a separate upload.
- **Policy e-signatures are simple electronic signatures, bound to content.** A typed name (checked against the
  account's name) plus time, IP and browser, and the SHA-256 of `code, version, text, attached file hash`. This is
  what most ISMS evidence needs (who accepted which exact text, when); it is not a qualified or advanced electronic
  signature under eIDAS. The fingerprint is stored at approval and checked again at each acknowledgement, so text
  changed directly in the database can't collect new signatures, and the PDF prints the fingerprint so a paper copy
  can be matched to its version. Versions approved before round 3 have no stored fingerprint; their PDF shows the
  current one.
- **PDFs with ReportLab.** ReportLab (BSD, pure-Python wheel) renders the PDF; its Paragraph markup is applied only
  after escaping, so policy text can't add links, images or fonts. Markdown is rendered as headings, lists and
  paragraphs, enough for policies; tables and code blocks print as text.
- **HR sync proposes, people decide.** The HR system is the source for who works here and their dates, but it never
  completes offboarding or deactivates an account: leavers move to offboarding and the people managers are notified.
  Account deactivation stays with an administrator, the identity provider (SCIM) or an access review. Only work fields
  are requested from HR systems.
- **Access reviews never touch other systems.** Revocations of Keystone accounts are one administrator click; for
  everything else the campaign produces a task listing the decisions. Reviewer assignment uses the People register's
  manager links, so it stays correct as HR sync updates them; items about the reviewer go to someone else.
- **Connector client decoding bug (found 2026-11-16).** The shared client rebuilt responses from already-decompressed
  bytes but kept `Content-Encoding`, so any real API that gzips its responses failed with `DecodingError`. Mocked
  connector tests never sent compressed responses; a regression test now does. This affected every attack surface
  connector against live tenants, which is a reason those connectors still need validating with real read-only keys.
- **Scheduled jobs report their outcome.** An APScheduler listener records each run in `job_status`; two failures in
  a row, a failed or incomplete backup, or no verified backup in 26 hours raise an administrator notification (and an
  email when SMTP is set up), once per problem per day. Only the exception type is stored and shown.
- The Docker image has not been built in the development environment (Docker was unavailable).
  The container layout was checked by running the app from a copy of exactly the files the
  Dockerfile copies.

## Attack surface management

- **Keystone calls Microsoft APIs directly (read-only) for attack surface management** (decision human:sneh,
  2026-11-16). This reverses the original rule that only the PowerShell collector talks to Microsoft Graph; the Entra
  exposure module still uses the collector. Fixed hosts: login.microsoftonline.com, graph.microsoft.com,
  api.securitycenter.microsoft.com. Application permissions are read-only; Keystone makes no changes.
- **Connectors are built from vendor documentation, not tested against live tenants.** Each states how its field
  mapping was verified (`mapping_note`): Microsoft, CrowdStrike, SentinelOne, Sophos, Datto, N-central, Tenable and
  Qualys from the vendors' API references; NinjaOne's patch and anti-malware fields, ConnectWise Automate's computer
  fields and Rapid7 InsightVM's v4 schema partly from community libraries and third-party integrations (Rapid7's
  published schema couldn't be retrieved). Test connection lists the field names a real API returns so mappings can be
  confirmed or corrected with a read-only key.
- **Null is not compliant.** A property no tool reports is "no data"; baselines choose whether that counts as a gap
  (coverage baselines do). Partial or failed runs never retire devices, vulnerabilities, accounts or settings.
- **Matching** uses the source's own id, then serial (placeholder serials ignored), Entra device id, then a host name
  only when exactly one device has it, so two devices sharing a name aren't merged.
- Inventory data (devices, accounts, vulnerabilities, settings) is derived and refreshed each run, so it isn't audited
  row by row; baselines, exceptions and findings are.

## AI features

- **Optional and off by default.** Without a key, questionnaires are answered by hand or from
  the knowledge base (fuzzy matching: strict for automatic filling, lenient for suggestions).
  Tests check that no API client is created when AI is off.
- **Claude API** through the official Anthropic SDK, model `claude-opus-5-5` by default with a
  configurable effort level. Responses use structured outputs (a JSON schema), and the
  server-side refusal fallback is enabled for models that support it. Long requests stream.
- **Grounding.** Questionnaire answers may use only approved policy text and approved
  knowledge-base answers, sent as tagged source documents in a cached system prompt. Each
  citation must quote its source; Keystone checks every quote against the source text
  (ignoring case and whitespace) and discards quotes it can't find. An answer left without a
  verified source gets confidence "none" and a warning. Approved answers are never sent or
  overwritten. Questions are treated as untrusted input, and the model has no tools.
- **Human approval.** AI output is a draft: policy revisions become a draft version that still
  needs review and approval (segregation of duties applies), and questionnaire answers need an
  approver before they are exported.
- **Accounting.** Every call, including failures and refusals, is stored with user, feature,
  model and token counts and written to the audit log.
- **Token efficiency (reviewed 2026-11-17).** The prompts are Keystone's own; nothing is taken from
  Comp AI, which is AGPL-3.0. Changes made, none of which lowers answer quality:
  - Each request has three parts in a fixed order. First the instructions, then the stable
    reference material marked as the cache breakpoint, then only the per-request text in the
    user turn. For risk suggestions, the control catalogue, assets and suppliers (a few thousand
    tokens) moved out of the user turn into the cached part. Asking again with a different focus
    now reads them from cache at a tenth of the input price. Questionnaire batches run one after
    another against the same cached sources, so batches 2 onwards read them from cache.
  - Policy revisions come back as exact find/replace edits instead of the whole document, so
    adding one section to a long policy costs a few hundred output tokens, not several thousand.
    Each `find` must occur exactly once in the current text; otherwise the whole proposal is
    rejected and nothing is applied. A first draft, or a rewrite of most of the document,
    still returns the full text.
  - Output shapes are tighter: questionnaire answers are one to three sentences with no restated
    question, control narratives stay under 300 words, and risk fields are one sentence each.
  - Cache writes and cache reads are recorded separately (`ai_usage.cache_write_tokens`,
    `cache_read_tokens`). Settings → AI shows the share of input served from cache. The monthly
    budget counts all four token kinds.
  - `tests/test_ai_sdk.py` runs the real SDK against a mocked transport, so the exact wire format
    is tested offline: cache_control, output_config with effort and JSON schema, the fallback
    beta, streaming, usage and errors.
- **Token efficiency: not changed, proposals only.** These trade quality for cost and should be
  measured against an eval on real questionnaires and policies before anyone changes them:
  - A lower effort level per feature, for example `low` for questionnaire answers, which are
    extraction from given sources.
  - A smaller model for questionnaire answers, for example `claude-sonnet-5-5` or
    `claude-haiku-5-5`.
  - The Batch API for large questionnaires, at half the price but with results arriving up to
    hours later.
  Today one model and one effort level apply to every feature (Settings → AI).

## Secure coding standard

- The "Secure Coding Standard for Coding Agents" assumes TypeScript on Node with zod and pino. Keystone's backend is
  Python, so the bundle keeps the structure, rule IDs, OKF v0.2 trust fields and enforcement design, and changes the
  examples and tools: Pydantic models (`In`, `extra="forbid"`) instead of zod, the standard `logging` module and the
  audit log instead of pino, ruff's bandit rules plus Semgrep instead of the TypeScript ESLint security rules, and
  pip-audit with a hash-locked `requirements.lock` next to `npm audit`. The web app keeps the ESLint controls.
- `npm run` scripts became `scripts/security-check.sh <gate>`, because the repository root is a Python project.
- Single-organisation tenancy: "cross-tenant 404" tests become out-of-boundary tests (employee portal and public
  Trust Center), alongside the existing route-level 401 and 403 matrix.
- The web app does not enable typescript-eslint's `no-unsafe-*` rules: the browser is not the trust boundary here,
  the API validates every input. Promise, eval and HTML-sink rules are enabled.
- Python has no static type gate yet (no mypy); adding one is tracked separately.
- Semgrep findings that existed when the standard was adopted are held back by `.semgrep/baseline-commit` and listed
  in the adoption report; new findings fail the gate.
- Semgrep runs from its own virtual environment, because it pins OpenTelemetry versions that conflict with FastAPI.

## Deleting records (round 4)

- Records can be deleted only when they were created in error: nothing depends on them, and nothing about them was
  approved, accepted, signed, notified or verified. Each register's rules are in `keystone/core/deletion.py`.
  Otherwise the refusal names the reason and the alternative (close, retire, terminate, mark not relevant).
- Deleting needs the same permission as editing the register. The audit log is never changed: audited models log the
  deletion with the last values, and an explicit entry names who deleted what.
- Comments and ticket links on the record go with it. Ids in other records' JSON lists are removed, and optional
  links are cleared.

## Guided tour (round 5)

- **Stored per user on the server**, not in the browser, so the tour opens once per person rather than once per
  device. A tour has a version: bumping it in `keystone/collab/service.py` (`TOURS`) shows it again to everyone.
- **Not audited.** Whether someone finished or skipped the tour is a user-interface preference, not an ISMS record,
  so it isn't written to the audit log (like saved views).
- **"portal" permission.** Every role holds it, employees included; the service reads and writes only the caller's
  own row, so there is no route by which one user can see or change another's tour state.
- **Accessible by construction.** The card is a labelled modal dialog: the app underneath is `inert`, keys are handled
  on the document so Escape works wherever focus is, focus returns where it was, and the steps adapt to the sections a
  role can see and to phones. The e2e suite runs axe on the open tour.
- **Not shown over the setup wizard**, which a new administrator lands in; it starts once the wizard is done.

## Logic security review (round 6)

A review of how workflows and approvals can be got round, beyond who may call what. Each finding has a test in
`tests/test_logic_security.py` that failed before the fix.

| Finding | Fix |
|---|---|
| A risk accepted at a low level kept its acceptance (with no time limit below appetite) after its rating was raised | The acceptance lapses when the risk rises above the accepted level; the risk returns to *assessed* |
| Segregation of duties over time: hand a risk to someone else, accept it, take it back | Whoever accepted a risk can't become its owner while the acceptance stands |
| A recovered incident could be closed as a "false positive", skipping root cause, lessons and the regulator-notification check | Only an incident still in triage and never contained can close as false positive or duplicate |
| Corrective-action verification checked only the owner, so whoever completed an action (or any unowned one) could verify it | `completed_by_id` is recorded (migration 0044); owner and completer can't verify |
| Whoever answered an auditor's evidence request could accept it, and requests could be accepted with nothing provided | `provided_by_id` is recorded (migration 0044); only provided requests can be accepted, not by whoever answered |
| An active vendor could go back to prospective and then be terminated without the offboarding checklist | Active and offboarding vendors can't go back to prospective |
| A Trust Center access link's duration was unbounded (a century-long link, or a server error) | 1 to 365 days, like the default in the settings (SC-VAL-002) |

Reviewed and left as they are: the control owner check on control tests is also a point-in-time check (owner changes
are audit-logged; an owner round-trip shows in the history); customer-questionnaire answers can be approved by whoever
drafted them (a small team often has one person answering; every approval is logged); employees can retake a training
quiz until they pass (each attempt is recorded); a continuity test can be recorded as passed without per-process
recovery times (tabletop exercises have none).

## Managing training (round 7)

- **Built-in and your own modules side by side.** Keystone's six modules stay files in `content/training/` and can't
  be edited in the app, so an upgrade can improve them without overwriting anyone's text. Organisations write their
  own (`training_modules`) or start from a copy of a built-in one. A copy keeps the built-in module's passes until it
  gets a new version, so copying alone doesn't make everyone retake it.
- **Versions decide retakes.** Saving a module keeps its version (corrections don't send people back); ticking "new
  version" raises it and earlier passes stop counting. Passes are training records, so a module someone has taken can
  only be switched off, not deleted.
- **On/off lives with the assignment** (`training_assignments.active`, migration 0045): one place for who, when and
  whether, for built-in and own modules alike.
- **Quiz answers never leave the server.** The portal's module endpoint strips them (`public_module`); only people
  with the people-management permission can read a module with its answers, for editing.
- **Training done elsewhere counts per person**, not per account, so contractors without a portal account show as
  trained in the matrix. A record names the module and version it covers and is valid until a date (a year by
  default, at most three).
- **Certificates are personal data.** Only PDF, PNG and JPG, stored through the same checks as other uploads (type
  by content, size limit, content-addressed storage), and only people with the people-management permission can
  download them (`DOWNLOAD_PERMISSION["ExternalTraining"]`). The upload was approved as part of the feature request.

## Security expansion, batch 1 (round 8)

- **Declared registers.** Obligations, changes, policy exceptions, background checks, confidentiality agreements,
  sites, visitors and physical checks are declared in `keystone/registers/spec.py` (fields, permissions, workflow) and
  share one table, one API and one page. The server validates every value against the declaration: unknown fields
  are refused, text is bounded, choices are allowlisted, links must point at records that exist (SC-VAL-001/002).
  Each register has its own read and write permission, checked in the service; routes only require a signed-in staff
  user (SC-AUTHZ-001). Numbering is per register (CHG-0001).
- **Workflow steps** name their permission; approvals (changes, policy exceptions) refuse whoever raised the record
  (segregation of duties) and the page shows them a note instead of the buttons. Closed records can't be edited, and
  a record can be deleted only while nothing was decided on it.
- **Need-to-know registers** (background checks, confidentiality agreements, the visitor log) are readable only with
  the people-management or asset-management permission, take no comments and stay off the shared calendar.
- **No new permissions.** The registers reuse existing ones: org.write for obligations, task.write and task.approve
  for changes, risk.accept for policy exceptions, people.write and asset.write for people and physical security.
- **Reports from the portal** need only the portal permission (every role); reporters see their own reports and the
  reply, never the incident. Triage needs incident.write. "Clicked or entered a password" is flagged first.
- **The leaver access check is read-only**: it lists leavers with active accounts and accounts with nobody behind
  them; deactivating stays a deliberate step in Users or the source system. Marking an account "expected" records why.
- **The exceptions register is a view**, not a copy: it reads risk acceptances, attack surface and configuration
  exceptions and policy exceptions where they live, so it can't drift from them.

## Security expansion, batch 2 (round 8)

- **Alert inbox: a new way in, approved with the request.** `POST /api/inbound/alerts` takes alerts from your tools.
  Each source has its own token (`kalt_…`, shown once, stored as a SHA-256 hash, rotatable, can be turned off);
  requests are rate-limited per address and per source and capped at 64 KB, and the body is a strict Pydantic model
  (allowlisted severity and category, links https only). Nothing is ever sent back to the tools. Repeats (same id,
  or same title, host and account within a day) are counted rather than stored again.
- **Alerts are linked by host name** to an asset (or a device the attack surface tools link to one) and its owner,
  who is notified of high and critical alerts; incident handlers are notified too. Handling needs incident.write;
  sources need integration.manage.
- **Pentest findings** get a fix-by date from their severity, and a retest can't be done by whoever marked the
  finding fixed (a register step that checks the previous step's author). Retests need the audit permission.
- **Application security** (applications, threat models, release sign-offs), **certificates and keys** and **backup
  jobs** are declared registers. A key's rotation never erases a certificate's expiry; public certificates from the
  internet-facing checks are added and refreshed by the daily scan.
- **Indicators** are measured every day alongside the dashboard figures; equal amber and red thresholds are allowed
  (one is already too many). An indicator turning red notifies its owner, or the ISMS managers.
- **Maturity** uses Keystone's own NIST CSF 2.0 content for the categories, so it works whether or not the
  framework is turned on; final assessments can't change, and the next one starts as a copy.

## Security expansion, batch 3 (round 8)

All new connections and the upload below were approved with the request (SC-AGT-006).

- **Phishing simulations stay harmless by construction.** Templates are Keystone's own YAML (`content/phishing/`);
  there is no template editor and no user-supplied HTML. The landing page (`/phish`, public) explains the warning signs
  and has no form: it never asks for a password or anything else. The link token is 24 random bytes, kept only as a
  SHA-256 hash, sent in the URL fragment (so it isn't in server or proxy logs) and removed from the address bar once
  read; the click endpoint is rate-limited per address and gives the same "not found" for every bad token. Emails go
  only to the organisation's own active users with a portal account, through the organisation's own relay, never to
  anyone else. Someone other than whoever prepared a campaign launches it. Individual results need people.write and
  are labelled for support, not blame; a portal report of a suspicious email during a campaign counts as reporting it.
- **Look-alike domains** reuse the crt.sh access the attack surface discovery already has, and send only the
  organisation's own verified domain names (as a `%name%` pattern). Matching is local: the name contained in another
  domain, or one or two edits away (optimal string alignment). Deciding "threat" needs a note of what is being done.
- **Supplier breach news** downloads Have I Been Pwned's whole public breach list (no key, no per-vendor query) and
  matches vendors' web addresses locally, so no outside party learns who the vendors are. Only matches added in the
  last 30 days notify, so the first run doesn't flood owners with old breaches.
- **On-call** pages in Keystone, by email and through the existing chat/webhook events; there is no SMS or phone
  provider (no new third party holding staff phone numbers). Only the person paged can acknowledge, which stops the
  escalation for the whole call; unanswered pages go to the next member, then the ISMS managers. Members must be able
  to handle incidents. Critical incidents and critical alerts page; nothing else does, to keep pages meaningful.
- **DMARC upload** accepts .xml, .xml.gz or .zip up to 10 MB, at most 5 entries and 50 MB decompressed (checked while
  decompressing, so a zip bomb stops early), .xml entries only, parsed with defusedxml with DTDs forbidden. Only the
  figures are stored; the file isn't kept. Upload needs integration.manage.

## Integrations and agents, batch A (round 9)

Approved with the request: the macOS agent, the hourly check-in endpoint, agent hashes, enrolment key limits, optional
key pinning, the signed Windows agent, and asking tools what a key may do (SC-AGT-006).

- **Raw results as evidence.** A passing check's outcome (summary and details, never settings or credentials) is
  filed as a JSON attachment on its evidence, at most once a day per check, through the normal attachment store
  (content-addressed, SHA-256 checked on read). Old files stay linked to the evidence as its history.
- **Change alerts.** A check that passed and now fails opens one task for its control's owner (or notifies the people
  who manage integrations when no control has an owner). A check that changed between pass and fail four or more
  times in its last ten results is "flapping": it gets a note instead of a new task each time.
- **Health.** Failed runs in a row and the last successful run are kept on the integration. After three failures in a
  row the ISMS managers (org.write) are told; credential expiry dates are entered by hand (no tool reports them
  reliably) and reminded two weeks ahead.
- **Is the key read-only?** Asked of the tool only where it tells a key about itself: GitHub's scope header (classic
  tokens), the IAM user's attached policies (SecurityAudit allows reading them), and the application roles in a
  Microsoft access token. The token's claims are read for display only; nothing is authorised by them. Anything
  else is "unknown", never "read-only".
- **Agents still receive no code.** The new check-in answers only "is a report due". Keystone does not update agents:
  a server that could push code to root-level agents would turn a Keystone compromise into a fleet compromise.
- **Integrity is a tripwire, not a guarantee.** The agent's self-reported hash catches changed scripts, not a
  determined administrator on the host, who could fake it; the documentation says so.
- **Signed Windows agent.** A signed copy in the data directory is served only when, without its signature block, it
  equals the shipped script, so the signing route can't be used to hand out a different agent.
- **Pinning** is optional and always in addition to normal TLS validation (SC-CRY-004). Linux and macOS use curl's
  `--pinnedpubkey`; Windows PowerShell 5.1 has no call that returns a certificate's SubjectPublicKeyInfo, so the agent
  walks the certificate's DER fields to find it. The walk is tested against .NET's own export for RSA and ECDSA keys,
  and any parsing error rejects the connection. PowerShell 7 refuses to pin rather than silently not pinning.
- **macOS agent** mirrors the Linux agent's limits. Its deny list adds the local directory (password hashes),
  keychains and home folders; a test fails if the server refuses a path an agent doesn't.
- **Coverage** matches agent hosts to attack surface devices by short host name. Assets are linked automatically only
  when exactly one asset has the name, and only on a host's first report (or its first from agent 1.2), so a link an
  administrator removed isn't put back.

## Integrations and agents, batch B (round 9)

- **Checks from attack surface sources.** Sources that only collected inventory can now also run pass/fail control
  checks, worked out from what the run collected (no extra calls, except Microsoft's Conditional Access policies,
  which need the optional Policy.Read.All). Missing data is "unknown", never a pass. They file evidence and raise
  change alerts like any other check.
- **Microsoft 365**: MFA for every enabled member account (guests excluded), phishing-resistant methods for
  administrators (from the registration report's methods: FIDO2, passkeys, Windows Hello, platform credentials,
  certificate MFA), legacy sign-in blocked by an enabled policy for all users, Secure Score's audit log search control,
  Secure Score not falling by more than 5 points over the history Microsoft returns, Intune compliance.
- **AWS and GitHub**: everything new is covered by the credentials the guides already create (SecurityAudit; the
  GitHub token gains Code scanning alerts and Members, read-only), and where GitHub refuses a read the check is
  "unknown" with the permission it needs.
- **Jamf Pro and Kandji** read device lists only. Kandji's FileVault state needs one call per device, so it is read for
  up to 1,000 devices and reported as unknown above that. Phones and tablets aren't counted in the encryption check.
- **More agent settings** detect known products by service or process name. An unknown product reports "none found",
  so the endpoint security rule says so in its description and can be turned off for hosts with an unlisted product.
- **Software vulnerabilities from Keystone's own data** (decided by human:sneh, 2026-11-21: download OSV, match
  locally). Agents report source packages for dpkg (OSV indexes Debian and Ubuntu by source package) and
  epoch:version-release for rpm. Keystone downloads each distribution's whole OSV archive when its ETag changes,
  streams it to disk within a 2 GB cap, and reads entries one by one in memory (entry, count and total limits; nothing
  extracted). Version ordering follows dpkg and rpm. Only advisories with a fixed version are matched, so findings are
  actionable; duplicates of the same CVE from different advisories are recorded once. Results go through the normal
  attack surface ingestion, so KEV/EPSS priorities, fix-by dates, tickets and closing on upgrade all apply. Windows and
  Mac software is inventory only: there is no comparable public source.
- **Report size.** Agent reports may be up to 1 MB (was 256 KB) to fit a software list of up to 5,000 entries; entries
  are validated and anything malformed is dropped, not stored.

