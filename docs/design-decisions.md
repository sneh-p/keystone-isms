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
  (93): 107 in total. Every leaf requirement of all four frameworks is mapped (tested). The
  crosswalk is original work and labelled as a starting point.

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
  Entra integration derives its checks from the imported collector snapshots, so the app still
  never connects to Microsoft Graph. Credentials are Fernet-encrypted and write-only.
- **Email** is not sent: invitation and Trust Center links are shown to copy. An SMTP hook is
  on the roadmap.
- **No device agent.** Device checks are self-attested by employees with an optional
  screenshot, and expire after a set period.
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
- SQLite by default; models avoid SQLite-only types so PostgreSQL works. Migrations are applied
  at start-up. The audit-log immutability triggers exist for SQLite and PostgreSQL.
- The Docker image has not been built in the development environment (Docker was unavailable).
  The container layout was checked by running the app from a copy of exactly the files the
  Dockerfile copies.

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
