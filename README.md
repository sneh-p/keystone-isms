# Keystone ISMS

An information security management system (ISMS) for one organisation, built around a single set of **128 common
controls** mapped to **ISO/IEC 27001:2022, NIST CSF 2.0, SOC 2, CIS Controls v8.1, NIS2, DORA, GDPR, ISO/IEC 27701,
ISO/IEC 42001, PCI DSS 4.0.1, Cyber Essentials and the Essential Eight**. Implement and evidence a control once and it
counts towards every framework. Keystone covers the whole cycle: setting up the ISMS, risk, controls and
evidence, policies, people, suppliers, incidents, audits and management review, plus a public Trust Center and
**attack surface management** fed by your RMM, EDR, vulnerability scanner and Microsoft 365.

![Overview dashboard](docs/screenshots/01-dashboard.png)

All screenshots show the fictional demo organisation, Alpine Ski House.

## Contents

- [What it does](#what-it-does)
- [Screenshots](#screenshots)
- [Quick start](#quick-start)
- [Attack surface management](#attack-surface-management)
- [Privacy and business continuity](#privacy-and-business-continuity)
- [Identity](#identity)
- [Policy signatures and PDFs](#policy-signatures-and-pdfs)
- [Ticketing](#ticketing)
- [Integrations](#integrations)
- [Security model](#security-model)
- [Configuration](#configuration)
- [Framework content and licensing](#framework-content-and-licensing)
- [Secure coding standard](#secure-coding-standard)
- [Development](#development)
- [Documentation](#documentation)

## What it does

| Area | What you get |
|---|---|
| **Setup** | A wizard that loads frameworks, writes the ISMS scope, drafts 16 policies from templates, schedules evidence tasks and marks clearly irrelevant controls not applicable |
| **Overview** | Next steps worked out from real gaps, headline figures with 12-week trends, framework readiness, risk heat map, "needs attention" and your own tasks |
| **Frameworks and controls** | Readiness per framework, control owners, implementation, review cycles, audit readiness, evidence with expiry, Statement of Applicability (versioned, approved, Excel/Word export), bulk changes and saved filter views |
| **Tasks and calendar** | Recurring evidence tasks with independent approval that file evidence on their controls; tasks follow control owners; a calendar of every test, review, renewal and audit; a workload view per person |
| **Risk** | Asset register, risk register with a configurable 5×5 matrix and appetite, treatment actions, time-limited acceptance, **FAIR Monte Carlo** quantification, a library of 24 common scenarios, incidents that bring a risk's review forward |
| **Attack surface** | Devices, accounts, vulnerabilities and tenant settings from your tools, checked against baselines you set; findings, exceptions and alerts ([details](#attack-surface-management)) |
| **Third parties** | Vendor register with tiering, questionnaires with scoring, a **vendor self-service portal** with virus-scanned uploads, FAIR vendor assessments with approval |
| **Entra exposure** | Read-only PowerShell collector and importer for third-party apps in Entra ID: exposure scoring, vendor matching, FAIR suggestions, snapshot comparison, remediation candidates |
| **Policies** | Versioned documents, approval by someone other than the author, review cycle, staff acceptance tracking, an optional AI policy assistant |
| **People and portal** | People directory, invitations (copy or email), an employee portal for policies, training with quizzes and a device checklist, offboarding |
| **Incidents and improvement** | Incident timeline with regulator-notification deadlines; nonconformities with corrective actions and effectiveness checks; internal audits with an **auditor workspace** (expiring auditor accounts, evidence request list, audit pack ZIP, in-app document viewer); management review with ISO 9.3.2 inputs compiled automatically |
| **Trust Center** | A public page with "frameworks we align to", certifications, passing controls, policies, subprocessors and FAQs; gated documents behind access requests, NDA and expiring links |
| **Customer questionnaires** | Import a customer's spreadsheet, answer from approved policies and a knowledge base (optionally drafted by AI with verified quotes), approve each answer, export into their file |
| **Working together** | Notifications (in-app and a daily email digest) routed to the owner of each record; comments with @mentions; a one-page board summary |
| **Sign-in** | Local accounts or **single sign-on** with Microsoft Entra ID or Google; optional "SSO required" with administrators as break-glass |
| **Assurance** | Seven roles, segregation of duties throughout, an append-only hash-chained audit log, register exports and CSV imports |

## Screenshots

### Setting up and running the ISMS

| | |
|---|---|
| ![Setup wizard](docs/screenshots/02-onboarding.png) **Setup wizard**: describe the company and Keystone drafts policies, tasks and the scope | ![Frameworks](docs/screenshots/03-frameworks.png) **Frameworks**: readiness for ISO 27001, NIST CSF, SOC 2 and CIS |
| ![Controls](docs/screenshots/04-controls.png) **Controls**: readiness and evidence columns, filters, bulk owner and status changes | ![Tasks](docs/screenshots/05-tasks-board.png) **Tasks**: board grouped by month, filters by person, framework, control and due date |
| ![Calendar](docs/screenshots/06-calendar.png) **Calendar**: tests, reviews, renewals and audits by date | ![Workload](docs/screenshots/18-workload.png) **Workload**: open, overdue and owned work per person |
| ![Policies](docs/screenshots/15-policies.png) **Policies**: versions, approval, acceptance | ![Notifications](docs/screenshots/19-notifications.png) **Notifications**: everything flagged goes to the person who owns it |

### Risk and attack surface

| | |
|---|---|
| ![Risk register](docs/screenshots/07-risk-register.png) **Risk register** with heat map and appetite | ![FAIR](docs/screenshots/08-risk-fair.png) **FAIR quantification** with a loss exceedance curve |
| ![Risk library](docs/screenshots/09-risk-library.png) **Risk library**: 24 scenarios with ratings and treating controls | ![Attack surface](docs/screenshots/10-attack-surface.png) **Attack surface**: coverage and compliance per baseline |
| ![Findings](docs/screenshots/11-attack-surface-findings.png) **Findings**: gaps against baselines, with exceptions | ![Device](docs/screenshots/12-attack-surface-device.png) **Device detail**: what each tool reports, findings, vulnerabilities |
| ![Entra exposure](docs/screenshots/20-entra-exposure.png) **Entra exposure**: third-party app permissions | ![Integrations](docs/screenshots/13-integrations.png) **Integrations**: control checks and attack surface sources |

### Suppliers, audits and assurance

| | |
|---|---|
| ![Vendors](docs/screenshots/14-vendors.png) **Vendors**: tiering, DPAs, assessments | ![Vendor portal](docs/screenshots/26-vendor-portal.png) **Vendor portal**: the vendor answers and uploads documents |
| ![Audit](docs/screenshots/16-audit-requests.png) **Auditor workspace**: evidence requests, discussion, audit pack | ![Improvement](docs/screenshots/17-improvement.png) **Nonconformities** and corrective actions |
| ![Customer questionnaires](docs/screenshots/22-customer-questionnaires.png) **Customer questionnaires** answered from approved content | ![Audit log](docs/screenshots/24-audit-log.png) **Audit log**: hash-chained, append-only, verified |

### Trust, people and sign-in

| | |
|---|---|
| ![Public Trust Center](docs/screenshots/25-public-trust-center.png) **Public Trust Center** | ![Trust Center settings](docs/screenshots/21-trust-center-admin.png) **Trust Center admin**: access requests, NDA, documents |
| ![Employee portal](docs/screenshots/27-employee-portal.png) **Employee portal**: policies, training, device checks | ![SSO](docs/screenshots/23-sso-settings.png) **Single sign-on**: Microsoft Entra ID and Google |
| ![Dark mode](docs/screenshots/28-dark-mode.png) **Dark mode** | ![Phone](docs/screenshots/29-phone.png) **Phones**: cards instead of tables |

## Quick start

Needs Python 3.12 and Node.js 22.

```bash
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock && .venv/bin/pip install --no-deps -e ".[test]"
(cd web && npm ci && npm run build)        # Node.js 22
.venv/bin/uvicorn keystone.api.app:create_app --factory --port 8000
```

Open http://localhost:8000, create the first administrator, and the setup wizard takes you through the rest.

### Demo

```bash
KEYSTONE_DATA_DIR=./demo-data .venv/bin/python scripts/seed_demo.py
KEYSTONE_DATA_DIR=./demo-data .venv/bin/uvicorn keystone.api.app:create_app --factory --port 8000
```

Sign in as `admin` / `Demo-Password-2026!`. The demo organisation, Alpine Ski House, is fictional. Other demo users
(same password): `mia.isms` (ISMS manager), `raj.risk` (risk owner), `lena.ctl` (control owner), `omar.audit`
(auditor, expires after 90 days), `sam.view` (viewer) and `nina.weber@alpineskihouse.example` (employee, portal only).
The demo includes risks, incidents, audits, policies, tasks, vendors, Entra exposure data, people, a published Trust
Center (`/trust/alpine-ski-house`), a customer questionnaire, 11 weeks of trend history and attack surface data.

### Docker

```bash
docker compose up -d --build               # Keystone + ClamAV + nginx on http://localhost/ (SQLite)
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d --build   # with PostgreSQL
```

The image is a multi-stage build (Node builds the web app, Python runs it), and every image is pinned by digest. Run
it behind a reverse proxy that terminates TLS; nginx and systemd configs are in `deploy/`. Keystone backs itself up
nightly and test-restores each backup; copy the backups off the host and keep the encryption key separately. See
[docs/admin-guide.md](docs/admin-guide.md).

## Attack surface management

**Risk → Attack surface** brings together what your tools know and compares it with what you require.

1. **Connect sources** (read-only) under Integrations: RMM, EDR, vulnerability scanners, Microsoft 365, and cloud
   posture from AWS Security Hub, Microsoft Defender for Cloud and Google Security Command Center. Tools without an
   API can be imported from CSV.
2. **Set baselines**: "Add recommended baselines" creates 17, for example *every workstation and server has an EDR
   agent*, *disk encryption on*, *critical vulnerabilities fixed within 7 days*, *no vulnerabilities with a known
   exploit*, *MFA registered for every enabled account*, *no accounts unused for 90 days*, *Secure Score settings meet
   their targets*. Adjust scope, severity and linked controls, or write your own.
3. **Keystone matches devices across tools** (serial number, Entra device ID, then host name) and works out coverage,
   so a device the RMM manages but no EDR agent reports becomes a finding.
4. **Vulnerabilities are put in fix order**: known exploited (CISA KEV) first, then likely to be exploited (FIRST
   EPSS), then by severity, each with a fix-by date from deadlines you set. Both feeds are downloaded whole, so no one
   learns which vulnerabilities you have.
5. **Internet-facing domains** you prove you own (a DNS TXT record) are checked passively every day: SPF, DMARC and
   CAA, host names from certificate transparency, dangling CNAMEs, internal addresses in public DNS, and HTTPS
   (TLS version, certificate expiry, redirect, HSTS). No port scanning.
6. **Findings** open and close by themselves. New critical and high findings notify the device or account owner (or
   the ISMS managers when nobody owns it); critical ones are also emailed. A baseline that everything meets files
   evidence on its controls. **Exceptions** need risk-acceptance rights, a reason and an end date within a year, and
   can't be approved for your own device.

Data a tool doesn't report is "no data", never compliant; failed or partial runs never retire anything.

## Privacy and business continuity

**Privacy**: records of processing (Article 30), DPIAs with an independent decision, data subject requests with legal
deadlines and automatic removal of requesters' details after closing, and a breach log built on incidents.
**Business continuity**: business impact analysis with RTO/RPO/MTPD, continuity plans, and tests whose results are
checked against the objectives and filed as evidence.

## Identity

Sign in with **Microsoft Entra ID, Google or Okta**; provision and deprovision accounts with **SCIM 2.0**; keep People
in step with **BambooHR, Personio or HiBob** (joiners onboarded, leavers moved to offboarding); and run **access review
campaigns** where managers confirm or revoke each account, with the result filed as evidence.

## Policy signatures and PDFs

Policy approvals and staff acknowledgements are **electronic signatures**: a typed full name, time, IP and browser,
bound to a SHA-256 fingerprint of the exact version. Every version exports as a **versioned PDF** with its approval,
version history and fingerprint, optionally with the acknowledgement register.

## Reports

The **board summary** (PDF or Word), every register as Excel, and the Statement of Applicability per framework.
Reports can be **emailed on a schedule** to chosen Keystone users.

## Chat and webhooks

Important events (incidents, critical findings, known-exploited vulnerabilities, internet-facing issues, system
problems, policy approvals, completed access reviews) go to **Slack**, **Microsoft Teams** or your own systems as
**HMAC-signed webhooks**, with retries.

## Ticketing

Open a ticket in **Jira, ServiceNow, ConnectWise PSA or Autotask** from a vulnerability, finding, task or
nonconformity, and see when it's closed. Keystone only creates tickets and reads their status. Optionally, it opens
tickets automatically for known-exploited vulnerabilities.

## Integrations

| Kind | Sources |
|---|---|
| Control checks (pass/fail, file evidence) | Website/TLS, GitHub, AWS, Entra ID (from collector snapshots) |
| Microsoft 365 | Entra ID accounts and MFA registration, Intune compliance and encryption, Defender for Endpoint health and vulnerabilities, Secure Score |
| EDR | CrowdStrike Falcon, SentinelOne, Sophos Central (and Microsoft Defender above) |
| RMM | NinjaOne, Datto RMM, N-able N-central, ConnectWise Automate |
| Vulnerability management | Tenable, Qualys VMDR, Rapid7 InsightVM (and Defender Vulnerability Management above) |
| Email | Any SMTP relay (STARTTLS or TLS) for digests, invitations, vendor links and Trust Center access |
| Sign-in | Microsoft Entra ID and Google (OIDC) |
| AI (optional) | Claude API for the policy assistant and questionnaire drafting |

Every connector is read-only, with step-by-step setup and a **Test connection** dry run that saves nothing. For attack
surface sources the dry run also lists the field names the API returned, so a mapping can be confirmed against your
tenant. Connectors were built from vendor documentation; each records how its field mapping was verified (see
[docs/design-decisions.md](docs/design-decisions.md)).

## Security model

- **Accounts and sessions**: argon2id passwords, lockout after 5 failures, forced change for admin-created accounts;
  server-side sessions in an `HttpOnly`, `SameSite` cookie (`Secure` over HTTPS), CSRF header on every change, idle and
  absolute timeouts; sessions end on sign-out, password change, role change or disabling. Accounts can expire (auditors
  must).
- **Single sign-on**: authorization code with PKCE, state and nonce bound to the browser; ID tokens verified with
  pinned RS256, issuer, audience, expiry and nonce; Entra single-tenant only; Google verified emails only; accounts are
  linked by the provider's subject, not by email.
- **Roles**: `admin`, `isms_manager`, `risk_owner`, `control_owner`, `auditor`, `viewer`, `employee` (portal only).
  Every service function checks a permission; a test checks every write route against every role, and another checks
  that employees can't read staff routes.
- **Segregation of duties**: nobody approves their own policy, task, vendor assessment, corrective action, risk
  acceptance or attack surface exception, and internal auditors don't audit controls they own.
- **Audit log**: every change to an ISMS record, every sign-in and export, chained with SHA-256; database triggers
  refuse UPDATE and DELETE.
- **Files**: allowlisted types checked by content, size limits, content-addressed storage, integrity check on
  download, always served as attachments; downloads by number are checked against the record they belong to; vendor
  uploads are virus-scanned by ClamAV and refused if the scanner is down; archives and XML are opened defensively.
- **Outbound connections**: HTTPS only; fixed vendor hosts or vendor domains; self-hosted servers and SMTP relays must
  be public unless the operator allowlists them; connections pinned to the checked address; no redirects; credentials
  bound to the host they were entered for and never echoed in errors.
- **Tokens and links**: invitation, Trust Center and vendor portal tokens live in the URL fragment, travel in headers
  and are stored as hashes; emailed links are built from `KEYSTONE_PUBLIC_URL`, never from the request.
- **Secrets**: integration, SMTP, SSO and AI credentials are encrypted at rest and write-only.
- **AI**: off unless an administrator enables it; only the documents a feature needs are sent; usage is capped and
  logged; output is always a draft that a person approves.

## Configuration

| Setting | Where |
|---|---|
| Data directory (database, attachments, secret key) | `KEYSTONE_DATA_DIR` (default `./data`) |
| Database (SQLite default, PostgreSQL supported) | `KEYSTONE_DB_URL`, password via `KEYSTONE_DB_PASSWORD_FILE` |
| Nightly backups | `KEYSTONE_BACKUP_DIR` (default `<data dir>/backups`), `KEYSTONE_BACKUP_KEEP` (default 14) |
| Public address for links and SSO redirects | `KEYSTONE_PUBLIC_URL` (needed for SSO and emailed links) |
| Idle session timeout | `KEYSTONE_SESSION_TIMEOUT_MINUTES` (default 30) |
| Upload limit | `KEYSTONE_MAX_UPLOAD_MB` (default 25) |
| Encryption key for stored credentials | `KEYSTONE_SECRET_KEY` (default: generated in the data dir) |
| Internal SMTP relays allowed | `KEYSTONE_SMTP_PRIVATE_HOSTS` |
| Internal self-hosted tools allowed (N-central, Automate) | `KEYSTONE_INTEGRATION_PRIVATE_HOSTS` |
| ClamAV for vendor uploads | `KEYSTONE_CLAMD_SOCKET` (default `/var/run/clamav/clamd.ctl`) or `KEYSTONE_CLAMD_TCP` |
| Framing (CSP `frame-ancestors`) | `KEYSTONE_FRAME_ANCESTORS` (default `'self'`) |
| Scheduler on this instance | `KEYSTONE_DISABLE_SCHEDULER=1` to turn it off |
| Interactive API docs (`/api/docs`) | `KEYSTONE_API_DOCS=1` (default off) |
| AI (optional) | **Settings → AI**, or `ANTHROPIC_API_KEY` |
| Email, single sign-on | **Settings → Email**, **Settings → Single sign-on** |
| Risk matrix, appetite, review intervals | `config/risk_matrix.yaml` |
| Vendor tiering | `config/tprm.yaml` |
| Incident deadlines | `config/incidents.yaml` |
| Entra exposure rules | `config/permission_tiers.yaml`, `config/exposure_rules.yaml`, `config/fair_suggestions.yaml` |

Shipped values are **calibration starting points**, labelled as such in the app.

## Framework content and licensing

| Framework | In this repository |
|---|---|
| NIST CSF 2.0 | Full text (US Government work, public domain) |
| ISO/IEC 27001:2022 | Identifiers with **short titles written by Keystone** |
| SOC 2 Trust Services Criteria | Identifiers with **Keystone-written summaries** |
| CIS Controls v8.1 | Safeguard identifiers with **Keystone-written titles** (CIS's CC BY-NC-ND licence forbids derivatives) |
| NIS2, DORA, GDPR | Article-level obligations with **Keystone-written summaries** (EU legislation) |
| ISO/IEC 27701 (2019 numbering), ISO/IEC 42001:2023 | Identifiers with **Keystone-written titles** |
| PCI DSS 4.0.1 | Requirement identifiers (x.y) with **Keystone-written titles** |
| Cyber Essentials, Essential Eight | Control themes and maturity levels with **Keystone-written summaries** |

If you hold a licence for a standard, import its official wording under **Frameworks → Content management**; it is
stored only in your database. The crosswalk, policy templates, task library, training, risk library and questionnaire
templates are original Keystone work. Verify the crosswalk against the source documents before relying on it for
certification. Workflows inspired by the open-source Comp AI platform were re-implemented; no AGPL code or text was
copied.

## Secure coding standard

Changes by people or coding agents follow the standard in [`.knowledge/secure-coding/`](.knowledge/secure-coding/index.md):
rules with stable IDs (`SC-INJ-001`, `SC-AUTHZ-005`, …) adapted to this stack. [AGENTS.md](AGENTS.md) explains how to
load it, and `scripts/security-check.sh all` runs the gates: typecheck (mypy and tsc), ruff and ESLint, Semgrep, gitleaks, pip-audit
and npm audit, the suppression check and the tests. CI runs the same gates, and `.github/CODEOWNERS` requires AppSec
review (`@Sneh/appsec`) for the standard and its controls. New outside connections, uploads and authentication changes
are decided by AppSec first; the decisions are recorded in
[docs/feature-security-designs.md](docs/feature-security-designs.md).

## Development

```bash
.venv/bin/python -m pytest tests/ -q                     # Python (≈545 tests) on SQLite
KEYSTONE_TEST_PG_URL=postgresql+psycopg://…/keystone_test scripts/test-postgres.sh   # the same suite on PostgreSQL
(cd web && npm run typecheck && npm run lint && npm test)  # web app
scripts/security-check.sh all                            # every security gate (see AGENTS.md)
KEYSTONE_E2E=1 .venv/bin/python -m pytest tests/e2e      # browser journeys incl. a WCAG 2.1 AA check (pip install -e ".[e2e]")
pwsh -c "Invoke-Pester ./tests/collector"                # PowerShell collector
```

Run the API with `--reload` and the web app with `npm run dev` (Vite proxies `/api` to port 8000). Schema changes need
an Alembic migration; `tests/test_migrations.py` fails if migrations and models drift apart, and upgrades every
revision on a database that has data in it.

**Stack**: FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, APScheduler, SQLite or PostgreSQL; React 18, React Router 7,
TypeScript, Vite, Tailwind, Radix, TanStack Query; PowerShell 7 for the Entra collector.

## Documentation

| Document | For |
|---|---|
| [docs/user-guide.md](docs/user-guide.md) | Everyday use, screen by screen |
| [docs/admin-guide.md](docs/admin-guide.md) | Installing, hardening, roles, SSO, email, ClamAV, integrations, backups and restore, system health |
| [docs/roadmap.md](docs/roadmap.md) | Round 3 roadmap and progress |
| [docs/design-decisions.md](docs/design-decisions.md) | Why things work the way they do, and known limits |
| [docs/feature-security-designs.md](docs/feature-security-designs.md) | Security designs and AppSec decisions for features that add outside access |
| [docs/workflow-analysis.md](docs/workflow-analysis.md) | Workflow analysis and the improvements made |
| [docs/ux-assessment.md](docs/ux-assessment.md) | UI/UX assessment and what changed |
| [docs/secure-coding-adoption.md](docs/secure-coding-adoption.md) | How the secure coding standard was adopted |
| [docs/secure-coding-proposed-updates.md](docs/secure-coding-proposed-updates.md) | Record of the updates made to the secure coding standard after sign-off |
| [collector/README.md](collector/README.md) | The read-only Entra exposure collector |
