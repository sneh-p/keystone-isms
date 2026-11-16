# Keystone ISMS

An information security management system (ISMS) for a single organisation. It is built around
one set of **common controls** that is mapped to **ISO/IEC 27001:2022, NIST CSF 2.0, SOC 2 and
CIS Controls v8.1**. You implement and evidence a control once, and it counts towards every
framework.

| Area | What you get |
|---|---|
| **Governance** | Organisation context, ISMS scope with approval, interested parties, ISMS roles, security objectives (ISO 27001 clauses 4 to 6) |
| **Frameworks** | Four frameworks, 107 common controls and a crosswalk that covers every requirement; import of licensed official text |
| **Risk** | Asset inventory; risk register with a configurable 5×5 matrix, appetite, treatment actions, time-limited acceptance with segregation of duties, and **FAIR Monte Carlo** quantification |
| **Controls** | Implementation status, owners, review cycle, evidence (files, links, notes) with expiry, and a **Statement of Applicability** per framework, versioned, approved and exported to Excel or Word |
| **Third parties** | Vendor register with tiering, questionnaires with scoring, **FAIR vendor assessments** with approval |
| **Entra exposure** | Read-only PowerShell collector plus importer for third-party apps in Entra ID. Scores app exposure, matches apps to vendors, suggests FAIR inputs, compares snapshots and lists remediation candidates |
| **Policies** | Versioned documents, approval workflow with segregation of duties, review cycle, staff acknowledgements |
| **Operations** | Incident register with an append-only timeline, regulator-notification deadlines and lessons learned |
| **Improvement** | Nonconformities with root cause, corrective actions and effectiveness checks; internal audits; management review with ISO 9.3.2 inputs compiled automatically |
| **Onboarding & tasks** | A setup wizard that loads frameworks, writes the scope, drafts 16 policies and creates evidence tasks; recurring tasks with independent approval that file evidence on their controls; **control readiness** |
| **People & portal** | People directory, invitation links, an employee portal for policy acknowledgement, security training with quizzes and a device checklist; offboarding |
| **Trust Center** | A public page with frameworks, passing controls, policies, subprocessors and FAQs; gated documents behind access requests, NDA click-through and expiring links |
| **Integrations** | Read-only, scheduled checks (website/TLS, GitHub, AWS, Entra) that file evidence when they pass |
| **Security questionnaires** | Import a customer's spreadsheet, answer from approved policies and a knowledge base, approve each answer, export into the customer's own file |
| **AI (optional)** | Claude-powered policy assistant and questionnaire drafting with verified source quotes. Off by default; everything works without it |
| **Assurance** | Local accounts (argon2id), seven roles, an **append-only, hash-chained audit log** of every change, register exports |

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[test]"
(cd web && npm ci && npm run build)        # Node.js 22
.venv/bin/uvicorn keystone.api.app:create_app --factory --port 8000
```

Open http://localhost:8000, create the first administrator, and the **onboarding wizard**
takes you through the rest: frameworks, scope, draft policies and evidence tasks.

### Demo

```bash
KEYSTONE_DATA_DIR=./demo-data .venv/bin/python scripts/seed_demo.py
KEYSTONE_DATA_DIR=./demo-data .venv/bin/uvicorn keystone.api.app:create_app --factory --port 8000
```

Sign in as `admin` / `Demo-Password-2026!`. The demo organisation, Alpine Ski House, is
fictional and includes risks, incidents, an audit, policies, tasks, vendors, two Entra tenants'
exposure data, people, a published Trust Center (`/trust/alpine-ski-house`) and a security
questionnaire. Other demo users (same password): `mia.isms` (ISMS manager), `raj.risk` (risk
owner), `lena.ctl` (control owner), `omar.audit` (auditor), `sam.view` (viewer) and
`nina.weber@alpineskihouse.example` (employee, portal only).

### Docker

```bash
docker compose up -d --build               # Keystone + nginx on http://localhost/
```

The image is a multi-stage build (Node builds the web app, Python runs it). Run it behind a
reverse proxy that terminates TLS. Ready nginx and systemd configs are in `deploy/`. See
[docs/admin-guide.md](docs/admin-guide.md).

## Framework content and licensing

| Framework | In this repository |
|---|---|
| NIST CSF 2.0 | Full text (US Government work, public domain) |
| ISO/IEC 27001:2022 | Clause and Annex A identifiers with **short titles written by Keystone** |
| SOC 2 Trust Services Criteria | Criteria identifiers with **Keystone-written summaries** |
| CIS Controls v8.1 | Safeguard identifiers with **Keystone-written titles** (CIS's CC BY-NC-ND licence forbids derivatives) |

If you own a licence for a standard, import its official wording under **Frameworks → Content
management** (CSV `ref,text`, YAML or JSON). That text is stored only in your database. Tests
stop restricted packs from containing long or official text.

The crosswalk is original Keystone work and a **starting point**: verify it against the source
documents before relying on it for certification.

## Security model

- **Accounts**: argon2id password hashes, a 12-character complexity policy, lockout after 5
  failures, forced password change for accounts an admin creates, and idle session timeout.
- **Sessions**: server-side, with an `HttpOnly`, `SameSite` cookie (`Secure` over HTTPS), a CSRF
  header on every change, idle and absolute timeouts, and security headers including a strict
  Content Security Policy.
- **Roles**: `admin`, `isms_manager`, `risk_owner`, `control_owner`, `auditor` (read and record
  findings), `viewer` and `employee` (portal only). Every service function checks a permission,
  and a test checks every API write route against every role.
- **Segregation of duties**: risk owners can't accept their own risks; policy authors can't
  approve their own versions; vendor assessment authors can't approve their own; corrective
  action owners can't verify their own actions; internal auditors can't audit controls they own;
  task assignees can't approve their own tasks.
- **Audit log**: every insert, update and delete of an ISMS record is written automatically.
  Logins and exports are logged too. Each row is chained with SHA-256, and database triggers
  refuse UPDATE and DELETE. The Audit log page verifies the chain.
- **Uploads**: allowlisted types, magic-number checks, a size limit, sanitised names,
  content-addressed storage and an integrity check on download.
- **Exports**: spreadsheet cells are protected against formula injection.
- **Entra data**: the collector is GET-only and exports no user identifiers or secrets. The app
  never connects to Graph. See [collector/README.md](collector/README.md).
- **Secrets**: integration and AI credentials are encrypted at rest and write-only.
- **Trust Center**: public endpoints expose only published items, are rate-limited and use
  hashed, expiring access tokens.
- **AI**: off unless an administrator enables it. Only the documents a feature needs are sent;
  every call is logged; AI output is always a draft that a person approves.

## Configuration

| Setting | Where |
|---|---|
| Data directory (database, attachments, secret key) | `KEYSTONE_DATA_DIR` (default `./data`) |
| Database URL (SQLite default, PostgreSQL supported) | `KEYSTONE_DB_URL` |
| Idle session timeout | `KEYSTONE_SESSION_TIMEOUT_MINUTES` (default 30) |
| Upload limit | `KEYSTONE_MAX_UPLOAD_MB` (default 25) |
| Encryption key for stored credentials | `KEYSTONE_SECRET_KEY` (default: generated in the data dir) |
| AI (optional) | **Settings → AI**, or `ANTHROPIC_API_KEY` |
| Framing (CSP `frame-ancestors`) | `KEYSTONE_FRAME_ANCESTORS` (default `'self'`) |
| Risk matrix, appetite, review intervals | `config/risk_matrix.yaml` |
| Vendor tiering | `config/tprm.yaml` |
| Incident notification deadline and containment targets | `config/incidents.yaml` |
| Entra permission tiers, exposure rules, FAIR suggestion ranges | `config/permission_tiers.yaml`, `config/exposure_rules.yaml`, `config/fair_suggestions.yaml` |

All shipped values are **calibration starting points**. The UI labels them as such.

## Development

```bash
.venv/bin/python -m pytest tests/ -v                     # Python (≈500 tests)
(cd web && npm run typecheck && npm run lint)            # web app
KEYSTONE_E2E=1 .venv/bin/python -m pytest tests/e2e      # browser journeys (pip install -e ".[e2e]")
pwsh -c "Invoke-Pester ./tests/collector"                # PowerShell collector (22 tests)
```

Run the API with `--reload` and the web app with `npm run dev` (Vite proxies `/api` to port
8000). Schema changes need an Alembic migration (`alembic revision --autogenerate -m "..."`).
`tests/test_migrations.py` fails if the migrations and models drift apart. SQLAlchemy warnings
fail the test suite.

```
keystone/api/         FastAPI app, sessions/CSRF, one thin router per module
keystone/core/        database, accounts, roles, audit log, attachments, secrets, workflow
keystone/<module>/    models.py + service.py per module (org, frameworks, assets, risk, controls,
                      tprm, tprm/exposure, policies, incidents, improvement, audits, reporting,
                      onboarding, tasks, people, trust, integrations, answers, ai)
web/                  React app (Vite, TypeScript, Tailwind)
content/              framework packs, crosswalk, policy templates, task library, training
config/               tunable rules and thresholds
collector/            PowerShell Entra collector
migrations/           Alembic
deploy/               nginx, systemd
tests/                pytest (+ tests/e2e browser tests) and Pester; fixtures are fictional
```

Never commit real organisational data: `output/`, `data/`, `*.db` and `.env` are git-ignored,
and test fixtures use `.example` domains.

## Roadmap

- [x] Project structure, core platform, accounts, roles, audit log
- [x] Framework library and crosswalk (ISO 27001, NIST CSF 2.0, SOC 2, CIS v8.1)
- [x] Assets and risk register (qualitative and FAIR)
- [x] Controls, Statement of Applicability, evidence
- [x] Third-party risk management
- [x] Vendor exposure map (Entra ID collector and importer)
- [x] Policy management
- [x] Incidents, nonconformities and corrective actions
- [x] Internal audits and management review
- [x] Dashboards and reports
- [x] Documentation and packaging
- [x] v2: React web app over a FastAPI API
- [x] Onboarding wizard, evidence tasks and control readiness
- [x] People, employee portal, training and device checks
- [x] Trust Center
- [x] Integrations with scheduled checks
- [x] Optional AI: policy assistant and security questionnaires
- [ ] Next: single sign-on (OIDC / Entra ID), email delivery for invitations and reminders,
  Exchange Online application access policies in the exposure map, more integrations

See [docs/design-decisions.md](docs/design-decisions.md) for decisions and deviations from the
original specifications.
