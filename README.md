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
| **Assurance** | Local accounts (argon2id), six roles, an **append-only, hash-chained audit log** of every change, register exports |

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[test]"
.venv/bin/streamlit run app.py
```

Open http://localhost:8501, create the first administrator, then:

1. **Frameworks**: load the bundled frameworks and common controls.
2. **Organisation & scope**: describe the organisation and approve the ISMS scope.
3. Add **users**, then work through assets, risks, controls and vendors.

### Demo

```bash
KEYSTONE_DATA_DIR=./demo-data .venv/bin/python scripts/seed_demo.py
KEYSTONE_DATA_DIR=./demo-data .venv/bin/streamlit run app.py
```

Sign in as `admin` / `Demo-Password-2026!`. The demo organisation, Alpine Ski House, is
fictional and includes risks, incidents, an audit, policies, vendors and two Entra tenants'
exposure data. Other demo users (same password): `mia.isms` (ISMS manager), `raj.risk`
(risk owner), `lena.ctl` (control owner), `omar.audit` (auditor) and `sam.view` (viewer).

### Docker

```bash
docker build -t keystone-isms .
docker run -p 8501:8501 -v keystone-data:/data keystone-isms
```

Run it behind a reverse proxy that terminates TLS. See [docs/admin-guide.md](docs/admin-guide.md).

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
- **Roles**: `admin`, `isms_manager`, `risk_owner`, `control_owner`, `auditor` (read and record
  findings) and `viewer`. Every service function checks a permission. Pages a role cannot use
  are not even registered in its navigation.
- **Segregation of duties**: risk owners can't accept their own risks; policy authors can't
  approve their own versions; vendor assessment authors can't approve their own; corrective
  action owners can't verify their own actions; internal auditors can't audit controls they own.
- **Audit log**: every insert, update and delete of an ISMS record is written automatically.
  Logins and exports are logged too. Each row is chained with SHA-256, and database triggers
  refuse UPDATE and DELETE. The Audit log page verifies the chain.
- **Uploads**: allowlisted types, magic-number checks, a size limit, sanitised names,
  content-addressed storage and an integrity check on download.
- **Exports**: spreadsheet cells are protected against formula injection.
- **Entra data**: the collector is GET-only and exports no user identifiers or secrets. The app
  never connects to Graph. See [collector/README.md](collector/README.md).

## Configuration

| Setting | Where |
|---|---|
| Data directory (database, attachments) | `KEYSTONE_DATA_DIR` (default `./data`) |
| Database URL (SQLite default, PostgreSQL supported) | `KEYSTONE_DB_URL` |
| Idle session timeout | `KEYSTONE_SESSION_TIMEOUT_MINUTES` (default 30) |
| Upload limit | `KEYSTONE_MAX_UPLOAD_MB` (default 25) |
| Risk matrix, appetite, review intervals | `config/risk_matrix.yaml` |
| Vendor tiering | `config/tprm.yaml` |
| Incident notification deadline and containment targets | `config/incidents.yaml` |
| Entra permission tiers, exposure rules, FAIR suggestion ranges | `config/permission_tiers.yaml`, `config/exposure_rules.yaml`, `config/fair_suggestions.yaml` |

All shipped values are **calibration starting points**. The UI labels them as such.

## Development

```bash
.venv/bin/python -m pytest tests/ -v                 # Python (≈380 tests)
pwsh -c "Invoke-Pester ./tests/collector"            # PowerShell collector (22 tests)
pwsh -c "Invoke-ScriptAnalyzer -Path ./collector -Recurse -Severity Error,Warning"
```

Schema changes need an Alembic migration (`alembic revision --autogenerate -m "..."`).
`tests/test_migrations.py` fails if the migrations and models drift apart. SQLAlchemy warnings
fail the test suite.

```
app.py                Streamlit entry: login, first-run setup, role-based navigation
pages/                one thin page per screen
keystone/core/        database, accounts, roles, audit log, attachments, workflow, migrations
keystone/<module>/    models.py + service.py per module (org, frameworks, assets, risk, controls,
                      tprm, tprm/exposure, policies, incidents, improvement, audits, reporting)
content/              framework packs, common controls, crosswalk, questionnaire template
config/               tunable rules and thresholds
collector/            PowerShell Entra collector
schemas/              collected.json schema
migrations/           Alembic
tests/                pytest + Pester; fixtures are fictional
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
- [ ] Next: single sign-on (OIDC / Entra ID), email reminders, Exchange Online application
  access policies in the exposure map, a scheduled collector (needs its own security review)

See [docs/design-decisions.md](docs/design-decisions.md) for decisions and deviations from the
original specifications.
