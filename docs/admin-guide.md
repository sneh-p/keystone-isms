# Administrator guide

## Installing

For a complete, step-by-step installation on a new Ubuntu server (systemd, nginx, Let's Encrypt and ClamAV), follow
[Deploy on a fresh server](../README.md#deploy-on-a-fresh-server) in the README. This section is the reference.

**Python** 3.12 (the hashed lockfile is resolved for 3.12; the Docker image uses it) and **Node.js** 22 (to build the web app once):

```bash
python3 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements.lock && .venv/bin/pip install --no-deps -e .
(cd web && npm ci && npm run build)
KEYSTONE_DATA_DIR=/srv/keystone .venv/bin/uvicorn keystone.api.app:create_app --factory --host 127.0.0.1 --port 8000
```

**Docker** (multi-stage: Node builds the web app, a slim Python image runs it):

```bash
docker compose up -d --build      # Keystone, ClamAV and nginx on port 80; SQLite in the keystone-data volume
# PostgreSQL instead of SQLite (the password is a Docker secret file; see the comments in the file):
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d --build
# or the image alone:
docker build -t keystone-isms .
docker run -d --name keystone -p 127.0.0.1:8000:8000 -v keystone-data:/data keystone-isms
```

On start, Keystone runs its database migrations (Alembic) automatically. The first visitor
sees a setup screen to create the first administrator, followed by the onboarding wizard. Do
this straight away after deploying.

The compose files pin every image by digest; when you update a tag, update its digest with it. ClamAV needs about
2 GB of memory and a few minutes on first start; until it is healthy, vendor uploads are refused.

One process serves everything: the web app, the API under `/api` (interactive docs at `/api/docs` only
when `KEYSTONE_API_DOCS=1`), the public Trust Center under `/trust/<slug>`, and a background scheduler that
runs integration checks every 15 minutes, records the dashboard's daily figures (for its trend lines), takes the
nightly backup and checks the system's health every hour. Run **one** instance per database, or set
`KEYSTONE_DISABLE_SCHEDULER=1` on all but one.

`GET /api/health` answers `{"status": "ok"}` while the database is reachable and 503 when it isn't: point load
balancers and uptime monitors at it. It reveals nothing else; details are under **Settings → System health**.

### Database: SQLite or PostgreSQL

SQLite (the default) suits most single-organisation installs. For PostgreSQL 14 or later, set
`KEYSTONE_DB_URL=postgresql+psycopg://keystone@db-host:5432/keystone` and put the password in a file named by
`KEYSTONE_DB_PASSWORD_FILE` (or in the URL, if you must). The driver (psycopg) is already in the lockfile. The
database user needs to own its database: migrations create tables, and the audit log's protection is a trigger that
refuses `UPDATE`, `DELETE` and `TRUNCATE`. The whole test suite runs against PostgreSQL with
`scripts/test-postgres.sh` (a throwaway database whose name ends in `_test`).

To move from SQLite to PostgreSQL (or back): take a backup, point Keystone at the new, empty database, and restore
the backup into it (see **Backups**).

### Behind nginx (HTTPS)

`deploy/nginx/keystone.conf` serves Keystone over HTTPS only (TLS 1.2+, HTTP redirected to your host name) and
keeps uvicorn on `127.0.0.1:8000`. It rate-limits the sign-in endpoint, allows uploads up to the upload limit and
gives AI drafting and integration runs up to five minutes. It does not forward the client's `Host` header:
Keystone builds the links it hands out (invitations, Trust Center access) from `KEYSTONE_PUBLIC_URL`.

```bash
sudo apt-get install nginx certbot
sudo cp deploy/nginx/keystone-proxy.conf /etc/nginx/snippets/keystone-proxy.conf
sudo cp deploy/nginx/keystone.conf /etc/nginx/sites-available/keystone.conf   # replace isms.example.com
sudo certbot certonly --webroot -w /var/www/html -d isms.example.com
sudo ln -s /etc/nginx/sites-available/keystone.conf /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default && sudo nginx -t && sudo systemctl reload nginx
```

Run Keystone itself with `deploy/systemd/keystone.service`, which passes `--proxy-headers` so Keystone sees real
client addresses (used for Trust Center rate limits and NDA records); set `KEYSTONE_PUBLIC_URL` there. Behind
HTTPS the session cookie is marked `Secure` and responses carry HSTS. `deploy/nginx/keystone-http.conf` serves
plain HTTP for evaluation on a private network only.

## Hardening checklist

- [ ] Put Keystone behind a reverse proxy (nginx, Caddy, Traefik) that **terminates TLS**, and
      bind uvicorn to `127.0.0.1` or a private network.
- [ ] Restrict who can reach the site: VPN, IP allowlist or an identity-aware proxy. If the
      Trust Center is public, allow `/trust/*`, `/api/public/*` and `/assets/*` from anywhere
      and keep everything else restricted. Vendors using the vendor portal also need
      `/vendor-portal`; people accepting invitations need `/invite`. If you run phishing
      simulations, staff need `/phish` and `/api/public/phish` (and `/assets/*`) from wherever they read email.
- [ ] Set `KEYSTONE_PUBLIC_URL` to the address people use, so emailed links and single sign-on
      redirects are right.
- [ ] Prefer single sign-on (**Settings → Single sign-on**) and consider **Require single sign-on**,
      keeping a small number of administrators with strong passwords as the emergency route.
- [ ] Put the data directory on an **encrypted** volume. It holds the database, every uploaded
      file and `secret.key`, which encrypts integration, email, single sign-on and AI credentials.
- [ ] Back up the data directory (see below) and test a restore.
- [ ] Set `KEYSTONE_SESSION_TIMEOUT_MINUTES` to match your policy.
- [ ] Review `config/*.yaml`. The shipped values are calibration starting points.
- [ ] Give people the least-privileged role that fits their work. Keep two administrators.
- [ ] Give integrations and attack surface sources read-only credentials only (see **Integrations**
      and **Attack surface management**).
- [ ] Give external auditors the Auditor role with an expiry date.
- [ ] If vendors upload documents, run ClamAV (see **Virus scanning**); without it their uploads are refused.
- [ ] Use an SMTP relay that supports TLS for email (**Settings → Email**).

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `KEYSTONE_DATA_DIR` | `./data` | Database (SQLite), attachments and `secret.key` |
| `KEYSTONE_DB_URL` | SQLite in the data dir | e.g. `postgresql+psycopg://keystone@db/keystone` |
| `KEYSTONE_DB_PASSWORD_FILE` | unset | File holding the database password (for example a Docker secret), added to `KEYSTONE_DB_URL` |
| `KEYSTONE_DSR_REDACT_DAYS` | 365 | Days after a data subject request is closed before the requester's name, contact details and request text are removed |
| `KEYSTONE_BACKUP_DIR` | `<data dir>/backups` | Where nightly backups are written. Use a different disk or volume, and copy them off the host |
| `KEYSTONE_BACKUP_KEEP` | 14 | How many backups to keep; older ones Keystone wrote are deleted |
| `KEYSTONE_BACKUP_DISABLE` | unset | Set to `1` when backups are taken another way (for example managed PostgreSQL snapshots plus a file backup) |
| `KEYSTONE_SESSION_TIMEOUT_MINUTES` | 30 | Idle sign-out |
| `KEYSTONE_MAX_UPLOAD_MB` | 25 | Per-file upload limit |
| `KEYSTONE_SECRET_KEY` | generated in the data dir | Fernet key that encrypts integration, email (SMTP), single sign-on and AI credentials. Set it to keep the key out of the data volume |
| `KEYSTONE_FRAME_ANCESTORS` | `'self'` | Who may embed Keystone in a frame (CSP source list), e.g. `https://intranet.example` |
| `KEYSTONE_DISABLE_SCHEDULER` | unset | Set to `1` to stop this instance running scheduled jobs (integration checks, backups, alerts) |
| `ANTHROPIC_API_KEY` | unset | Optional key for AI features, used when no key is stored under **Settings → AI** |
| `KEYSTONE_PUBLIC_URL` | unset | Public address for links Keystone hands out, e.g. `https://isms.example.com`. When unset, links use the address the administrator's browser is on |
| `KEYSTONE_API_DOCS` | unset | Set to `1` to serve the interactive API docs and OpenAPI schema (development only) |
| `KEYSTONE_SMTP_PRIVATE_HOSTS` | unset | Comma-separated host names of internal SMTP relays Keystone may connect to. Without it, only relays with public addresses are allowed |
| `KEYSTONE_CLAMD_SOCKET` | `/var/run/clamav/clamd.ctl` | ClamAV daemon socket used to scan vendor uploads |
| `KEYSTONE_INTEGRATION_PRIVATE_HOSTS` | unset | Comma-separated host names of self-hosted tools inside your network (N-central, ConnectWise Automate, Jamf Pro, firewalls read over their API) that connectors may reach. Without it, only public addresses are allowed |
| `KEYSTONE_EXTRA_CA_FILE` | unset | A PEM file of your own certificate authorities that connectors trust in addition to the public ones, for internal servers such as firewalls. Certificates are always verified; there is no way to turn verification off |
| `KEYSTONE_CLAMD_TCP` | unset | `host:port` of a ClamAV daemon (for example a ClamAV container), used instead of the socket |

Don't put secrets in the repository. Pass database credentials through the environment.

## Users and roles

Two permissions were added in round 3: `privacy.write` (records of processing, DPIAs, data subject requests, breach
assessments) for administrators and ISMS managers, and `continuity.write` (business impact analysis, plans, tests) for
administrators, ISMS managers and risk owners. Data subject requests are visible only with `privacy.write`; deciding a
DPIA needs `risk.accept` and must be someone other than its author.


| Role | Can |
|---|---|
| `admin` | Everything, including managing users and AI settings |
| `isms_manager` | Everything except managing users and AI settings: approve policies, tasks and questionnaire answers, accept risks, approve vendor assessments, verify corrective actions, run management reviews, manage the Trust Center and integrations |
| `risk_owner` | Assets, risks, evidence, incidents, nonconformities |
| `control_owner` | Control implementation, evidence, incidents, nonconformities |
| `auditor` | Read everything (including the audit log), record audit findings and run the evidence request list. Auditor accounts must have an expiry date |
| `viewer` | Read, and acknowledge policies |
| `employee` | Only the employee portal: their policies, training and device checklist. No ISMS records |

Control owners can also draft security-questionnaire answers. Only administrators can change
AI settings.

Users created by an admin must change their password at first sign-in. Five wrong passwords
lock an account for 15 minutes. An admin can reset a password (the user must then change it),
change a role or disable an account. Changing a role or disabling an account signs the user out
everywhere. Accounts are never deleted, so the audit trail stays intact.

Any account can have an **expiry date** (**Users → Expiry**); auditor accounts must have one. After
it passes, sign-in fails with the usual "Invalid username or password" and open sessions stop
working at their next request.

## Single sign-on (Microsoft Entra ID, Google, Okta)

**Settings → Single sign-on.** `KEYSTONE_PUBLIC_URL` must be set: the provider sends people back
to `<KEYSTONE_PUBLIC_URL>/api/auth/oidc/<entra|google|okta>/callback`, shown on the page to copy.

- **Entra ID:** register a single-tenant app (web platform) with that redirect URI and create a
  client secret. Enter the directory (tenant) ID, client ID and secret. Only accounts from that
  tenant can sign in (`common` and other multi-tenant endpoints are refused).
- **Google:** create an OAuth client (web application) with that redirect URI. Only verified
  email addresses are accepted.
- **Okta:** create an OIDC web app integration with that sign-in redirect URI and the `email` scope, and enter your
  Okta domain (for example `yourcompany.okta.com`; Okta-hosted domains only), client ID and secret. Keystone uses the
  org authorization server, requires a verified email, and drops the stored secret if the domain changes.

Accounts: create the user under **Users** with the email they use at the provider (tick "single
sign-on only" if they shouldn't have a password). Their first SSO sign-in links the account; from
then on Keystone recognises them by the provider's user ID only. If the account had a temporary
password, it stops working. Optionally list **approved domains** and turn on automatic accounts:
anyone from those domains who signs in gets an account with the Employee or Viewer role (never
more). For Google, approved domains must be Google Workspace domains (checked with the `hd` claim).

The client secret is encrypted and write-only. Each SSO sign-in and each refusal is in the audit log.

**Require single sign-on** turns password sign-in off for everyone except administrators, who keep their password as
the emergency route if the provider is down; keep administrators few and their passwords strong. It can only be turned
on while a provider is on, and the last provider can't be turned off while it applies.

## HR systems (BambooHR, Personio, HiBob)

**Integrations → HR systems** keeps **People** in step with your HR system, read-only. Keystone reads only work data:
name, work email, job title, department, employment type, start and end dates and manager. No salaries, home
addresses or personal contact details.

| System | Keystone needs |
|---|---|
| BambooHR | Company subdomain and an API key created by a user whose access level can view only those fields |
| Personio | API credentials (client ID and secret) with read access to those employee attributes only |
| HiBob | A service user (ID and token) whose permission group can view only About, Work and lifecycle status |

Each run (daily by default) matches people by the HR system's id, then by work email. New joiners are added as
onboarding; name, title, department, type, dates and manager follow the HR system. Someone whose end date has passed,
or who is marked inactive or terminated, moves to **offboarding** (which opens the offboarding checklist), and everyone
who manages people is notified. Keystone never completes offboarding or deactivates accounts by itself. People the HR
system doesn't list (often contractors) are left alone. Changes are audited as `hr:<integration name>`. The field
mappings come from each vendor's documentation: use **Test connection** first.

## Access reviews

**Trust and people → Access reviews** runs recertification campaigns (permission `access_review.manage`, held by
administrators and ISMS managers). A campaign lists every active Keystone account with its role, and optionally every
enabled account reported by connected identity sources (Attack surface identities, with administrator flag and last
sign-in). Each account goes to the person's manager from **People**, otherwise to the campaign owner; nobody reviews
their own access. Reviewers see their items in My tasks and decide **keep**, **revoke** or **change** (with a reason).

An administrator applies a revoke of a Keystone account with **Deactivate account** (sessions end immediately). For
accounts in other systems, and for changes, completing the campaign creates a task for the owner listing what to do:
Keystone doesn't change other systems. Completing also files evidence on KC-ORG-18 (access rights) and KC-TEC-02
(privileged access).

## Provisioning (SCIM 2.0)

**Settings → Provisioning** lets an identity provider create, update and deactivate accounts. Create a token (choose
the role new accounts get: Employee or Viewer, and an expiry), then in the identity provider enter the **tenant URL**
shown on the page (`<KEYSTONE_PUBLIC_URL>/api/scim/v2`) and the token as the secret. In Entra ID that's Enterprise
applications → your Keystone app → Provisioning (automatic); in Okta, the app's Provisioning tab (SCIM 2.0, header
bearer token, push new users, profile updates and deactivation).

- Provisioned accounts sign in with single sign-on only (no password). SCIM never changes roles: give other roles
  under Users.
- Administrators are invisible to SCIM: an identity provider can't list, change or deactivate them, so they stay the
  emergency route.
- Removing or unassigning a user in the identity provider deactivates the account (sessions end at once); accounts
  are never deleted, so the audit log keeps their history. Every SCIM change is logged as `scim:<token label>`.
- Users only (no groups or bulk operations). Supported filters: `userName`, `externalId` and `emails.value` equal to
  a value. Tokens are stored hashed, shown once, and can be revoked at any time.

## Email (notification digests)

**Settings → Email.** Enter the SMTP relay (port 587 STARTTLS, 465 TLS, or 25/2525), sender and,
if needed, user name and password, then **Send test message**. Keystone always encrypts the
connection and checks the certificate. It connects only to relays with public addresses unless
the relay's name is in `KEYSTONE_SMTP_PRIVATE_HOSTS`. The password is encrypted, write-only and
tied to the host: changing the host removes it. Each user with an email address gets one digest
a day (after the hour you choose, UTC) listing unread items from their inbox; they can turn it
off under **My account**.

## Virus scanning (vendor uploads)

Files vendors upload through the vendor portal are scanned by ClamAV before they are stored. If
the scanner can't be reached, vendor uploads are refused (the vendor is asked to try later) and
the questionnaire shows "Virus scanner unavailable". On Debian/Ubuntu:

```bash
apt-get install clamav-daemon clamav-freshclam   # freshclam keeps the signatures current
systemctl enable --now clamav-daemon
```

In Docker, `docker-compose.yml` already runs the official ClamAV container and sets
`KEYSTONE_CLAMD_TCP=clamav:3310`. Allow about 2 GB of memory for the daemon. **Settings → System health** shows
whether Keystone can reach it.

## Audit log

Every change to an ISMS record is written automatically, with the user, time and the changed
fields (password hashes are redacted). Sign-ins, failed sign-ins, imports and exports are
logged too. Rows are hash-chained, and database triggers refuse UPDATE and DELETE.
**Admin → Audit log** verifies the chain every time it opens. A failure means someone altered
the database outside Keystone. Treat that as a security incident.

## Backups

Keystone backs itself up once a day, with SQLite or PostgreSQL alike. Each backup holds every database row and every
stored file, and records a SHA-256 checksum for each part. Keystone then **test-restores** it into a scratch
database: it checks every checksum and the audit log's hash chain before marking the backup verified. Older backups beyond
`KEYSTONE_BACKUP_KEEP` are deleted. **Settings → System health** lists recent backups and has **Back up now**.
Administrators are notified (inbox, and email when it is set up) when a backup fails, is missing files, or no verified
backup exists from the last 26 hours.

What you still have to do:

- **Copy backups off the server** (`KEYSTONE_BACKUP_DIR`, or the `keystone-backups` volume in Docker). A backup on
  the same disk doesn't survive losing that disk.
- **Keep the encryption key separately**: `secret.key` in the data directory, or your `KEYSTONE_SECRET_KEY`. It
  isn't in the backup on purpose. Without it, a restore works, but stored integration, email, single sign-on and
  AI credentials must be entered again.
- Backups contain personal data and password hashes. They are written with owner-only permissions; protect the
  copies the same way.

Commands (run where Keystone runs, with the same `KEYSTONE_*` settings; in Docker prefix with
`docker compose exec keystone`):

```bash
python -m keystone.ops backup                                  # back up now (and test-restore)
python -m keystone.ops verify /backups/keystone-backup-….tar.gz  # check a copy, e.g. after moving it off-site
python -m keystone.ops restore /backups/keystone-backup-….tar.gz # restore into the configured database
```

Restore only writes into a **new, empty** database (Keystone creates the tables first), and only from a backup taken
by the same version of Keystone. It refuses a damaged or altered file, and anything it doesn't recognise. To recover,
stop Keystone, point `KEYSTONE_DB_URL` (or `KEYSTONE_DATA_DIR`) at a fresh database, run `restore`, put the
encryption key back, and start Keystone. The restore is recorded in the audit log. Restoring isn't possible from the
web app.

Attachments are stored by SHA-256, and Keystone checks the hash whenever a file is downloaded.

## System health

**Settings → System health** (administrators) shows the database and schema version, whether the scheduler is
running, whether the virus scanner is reachable, whether email is set up, each scheduled job's last run and result,
and recent backups. A job that fails twice in a row raises an administrator alert naming the error type (never its
message, which can contain hosts or values).

## Upgrades

Replace the code (or the image) and restart. Migrations run on start. Back up first
(`python -m keystone.ops backup`): a backup restores only into the version that took it.

## Framework content

Twelve frameworks are bundled: ISO/IEC 27001:2022, NIST CSF 2.0, SOC 2, CIS Controls v8.1, NIS2, DORA, GDPR,
ISO/IEC 27701 (2019 numbering), ISO/IEC 42001:2023, PCI DSS 4.0.1, Cyber Essentials and the Essential Eight. All of
them map to the same 128 Keystone common controls (including 11 privacy and 10 AI governance controls), so evidence
and status are shared: implementing "Secure authentication" counts towards ISO A.8.5, NIS2 21(2)(j), PCI DSS 8.3,
Cyber Essentials and the Essential Eight MFA levels at once.

**Frameworks → Content management** can re-apply the bundled packs (safe: your own mappings,
control status and SoA decisions are kept), turn frameworks on or off, and import licensed
official text for ISO 27001, ISO 27701, ISO 42001, PCI DSS, SOC 2 or CIS. Licensed text stays in your database and is only
exported when someone explicitly chooses the "with licensed text" download. When Keystone is upgraded, packs that
are new to your installation are added **switched off**; turn on the ones that apply.

NIS2 is transposed into national law, and DORA is detailed by regulatory technical standards: the packs list the
obligations of the Directive and Regulation themselves, so check national requirements and the RTS as well.

## Entra exposure

Technicians get the collector from **Entra exposure → Collector**: download the script (with
its SHA-256 to verify), build the exact command for one tenant or a CSV of tenants, and copy
it. They run it with a read-only role and upload `collected.json` on **Entra exposure → Import**. Read
[collector/README.md](../collector/README.md) before the first run, including the guidance on
the Graph Command Line Tools consent prompt and on handling the output files.

## Employees and invitations

Add people under **People** and create an invitation (valid for seven days, single use). When
email is set up and `KEYSTONE_PUBLIC_URL` is set, **Email invitation** sends it to the person;
otherwise copy the link to them through your usual channel. Accepting
it creates an `employee` account that sees only the portal. Offboarding a person disables their
account and ends their sessions.

## Trust Center

**Trust Center → Settings** chooses the public address (`/trust/<slug>`), what is shown and the
NDA text. Only controls that are implemented **and** ready (approved policies, current
evidence, no overdue tasks, no failing checks) are listed as passing. Gated documents need an
approved access request; approval produces a private link that expires after the configured
number of days (emailed to the requester when email is set up). Each framework can be shown as
aligned, certified (only if you hold a current certificate) or hidden. Requests are rate-limited per address, and every approval, NDA signature and
download is in the audit log. Changing the NDA text raises its version, so earlier signatures no
longer count.

## Integrations

Integrations run read-only checks on a schedule and file passing results as evidence. Give
each one the narrowest read-only credential:

| Integration | Credential |
|---|---|
| Website / TLS | None. Only public hosts are checked; private and local addresses are refused |
| GitHub | Fine-grained token: repository *Administration*, *Code scanning alerts* and *Metadata* read-only; organisation *Administration* and *Members* read-only. Without *Members*, the collaborator and owner checks show as unknown |
| AWS | An IAM user or role with the AWS-managed `SecurityAudit` policy (it covers every check, including the credential report, EBS, RDS, VPC flow logs and AWS Config) |
| Microsoft Entra ID | None. It reads the latest imported exposure snapshot and doesn't call Microsoft Graph. (The separate **Microsoft 365** attack surface source does call Microsoft's APIs, read-only; see below.) |
| Okta | An API token created while signed in as a dedicated user with only the Read-only Administrator role |
| Google Workspace | A service account with domain-wide delegation for exactly `admin.directory.user.readonly` and `cloud-identity.policies.readonly`, acting as an administrator with read access to users |
| FortiGate / PAN-OS (configuration by API) | FortiGate: a REST API administrator with a read-only profile and trusted hosts set to Keystone. PAN-OS: an administrator whose role allows only the XML API's Configuration. The firewall's name in `KEYSTONE_INTEGRATION_PRIVATE_HOSTS`, and its CA in `KEYSTONE_EXTRA_CA_FILE` if the certificate isn't public |

Each Connect dialog has a setup guide with copyable commands, filled in with the values you
type, to create the credential and then verify it: for AWS, that the user has only
SecurityAudit and (with the IAM policy simulator, which changes nothing) that it can't modify
anything; for GitHub, that the token can read what the checks need. Secrets are never put into
these commands. **Test connection** runs the checks with the entered settings without saving
results or evidence, so you can confirm access before saving.

A website that blocks automated requests (HTTP 4xx/5xx) is reported as unknown, not as failing.
Redirects are followed over HTTPS only, and each new host must also be public.

For GitHub, AWS and Microsoft 365, **Test connection** also asks the tool what the key may do and warns if it can change
anything (*Key is read-only*). Enter **Key or secret expires on** when you connect, and you're reminded two weeks
before; after three failed runs in a row the ISMS managers are told too.

Secrets are encrypted with `secret.key` and are write-only: the API never returns them, and the
audit log records only that they changed. A check that errors or can't decide is reported as
error or unknown, never as passing.

## Attack surface management

**Integrations → Attack surface sources** connect read-only to the tools that know your devices, accounts and
vulnerabilities; **Attack surface** shows the merged picture and the gaps against your baselines.

| Source | Provides | Read-only access to create |
|---|---|---|
| Microsoft 365 | Entra accounts and MFA registration, Intune compliance and encryption, Defender for Endpoint health and vulnerabilities, Secure Score; checks for MFA, phishing-resistant admin sign-in, legacy sign-in blocked, audit log search, Secure Score trend and Intune compliance | App registration, application permissions: User.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, DeviceManagementManagedDevices.Read.All, SecurityEvents.Read.All, Policy.Read.All (Conditional Access; optional); WindowsDefenderATP Machine.Read.All, Vulnerability.Read.All |
| Jamf Pro | Macs, FileVault, macOS version, last check-in; checks for encryption and check-in | API role with only *Read Computers*, and an API client using it |
| Kandji | Apple devices, FileVault, OS version, last check-in; the same checks | API token allowed only *Device list* and *Device details* |
| Keystone agents (installed software) | Vulnerabilities in the Linux packages Keystone's own agents report (Debian, Ubuntu, AlmaLinux, Rocky Linux) | None. Keystone downloads the public OSV data for those distributions from `osv-vulnerabilities.storage.googleapis.com` (see below) |
| CrowdStrike Falcon | Hosts and sensor status | API client, Hosts: Read |
| SentinelOne | Agents, health, threats, firewall | Service user, Viewer role |
| Sophos Central | Endpoints, health, tamper protection, encryption | Tenant API credential, Service Principal ReadOnly |
| NinjaOne | Devices, pending patches, anti-malware status | API client, Monitoring scope, client credentials |
| Datto RMM | Devices, anti-malware, approved pending patches | API keys of a read-only user |
| N-able N-central | Devices and last check-in | API-only user with a read-only role (JWT) |
| ConnectWise Automate | Computers, last contact, anti-malware definitions | Read-only integrator account plus your ClientID |
| Tenable | Open critical/high/medium vulnerabilities and assets | API keys of a user with view access |
| Qualys VMDR | Hosts with severity 3-5 detections | Reader user with API access |
| Rapid7 InsightVM | Assets with critical and severe vulnerabilities | API key of a read-only user |
| AWS Security Hub | Control results per region (resources passing and failing each control) | IAM user with only AWSSecurityHubReadOnlyAccess |
| Microsoft Defender for Cloud | Security recommendations per Azure subscription (healthy and unhealthy resources); checks for high-severity recommendations and Defender plans for servers, storage and SQL | App registration with the Security Reader role on each subscription (no API permissions) |
| Google Security Command Center | Active misconfiguration findings for the organisation, by category | Service account with only Security Center Findings Viewer; JSON key |

How it works: each run reads the source (read-only), matches devices across tools (serial number, then Entra device
ID, then host name), and re-checks every enabled **baseline**. Gaps become **findings**; they close by themselves when
fixed. New critical and high findings notify the device's or account's owner (devices are linked to people by email),
or the ISMS managers when nobody owns it; critical ones are also emailed straight away when email is set up. A baseline
that every item meets files evidence on its controls. **Exceptions** need the risk-acceptance permission, a reason and an
end date within a year, and can't be approved by the owner of the device or account.

Safety: keys are encrypted and write-only; each connector may only contact its vendor's hosts (exact hosts, or the
vendor's domain for customer consoles such as `*.sentinelone.net`); self-hosted N-central and Automate servers must
have public addresses unless listed in `KEYSTONE_INTEGRATION_PRIVATE_HOSTS`, and their credentials are dropped when the
server address changes; redirects are refused; responses are size-capped. **Test connection** reads one page per
source, saves nothing, and lists the field names the API returned, so a field mapping can be confirmed against your
tenant. Devices without an API can be imported from CSV (Attack surface → Import CSV).

### Alerts pulled from endpoint security tools

CrowdStrike Falcon, SentinelOne, Sophos Central and Microsoft 365 (Defender for Endpoint) can also bring their alerts
into **Operations → Alert inbox**: edit the integration and set *Bring alerts into the Alert inbox* to Yes. Each run
then reads the alerts raised since the last good run (at most a week back) and adds new ones; an alert already in the
inbox isn't counted again. Extra read permission needed: CrowdStrike *Alerts: Read*; Microsoft *WindowsDefenderATP
Alert.Read.All*; SentinelOne's Viewer and Sophos's ReadOnly roles already allow it. If reading alerts fails, the run
says so but the device inventory is still updated. Pulled alerts arrive through a source of their own (named after the
integration), which has no token and accepts nothing posted to it.

### Check-ins from backup jobs and CI

Sources of kind **Backup** and **CI** (Alert inbox → Sources) can also report results to `POST /api/inbound/checkin`
with their token:

```sh
# A backup job's result: by its reference (BAK-0001) or exact name in Business continuity → Backup jobs
curl -s -X POST "$KEYSTONE/api/inbound/checkin" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"kind":"backup","job":"BAK-0001","status":"success"}'          # or "failure" with "note": "why"

# A security scan of a release, added to the open release sign-off for that application and version
curl -s -X POST "$KEYSTONE/api/inbound/checkin" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"kind":"release_scan","application":"Booking platform","version":"4.3","tool":"semgrep","result":"pass","summary":"0 findings"}'
```

A backup check-in records "successful backup" or "failure" on the job, signed with the source's name; restore tests stay
with people. A release scan only adds a line to *Security testing done*: a person still signs the release off.

### Vulnerabilities from installed software (Keystone agents)

Agents 1.2 and later list installed software with each full report: Linux source packages and versions (dpkg) or
packages with epoch:version-release (rpm), Windows programs, and Mac apps. Each host's page shows its list, and
Configuration → Software searches across hosts. Install an agent with `--no-software` (Windows `-NoSoftware`) to leave
the list out.

Connect **Keystone agents (installed software)** under Integrations → Attack surface sources to turn the Linux
packages into vulnerabilities. Once a day, for each distribution your hosts run, Keystone downloads the whole OSV file
(`https://osv-vulnerabilities.storage.googleapis.com/<Debian|Ubuntu|AlmaLinux|Rocky Linux>/all.zip`), only when it
changed since the last run, and matches package versions itself with Debian's and rpm's version ordering. Nothing about
your hosts is sent anywhere. Only advisories with a fixed version are recorded ("fixed in …"), so every result says what
to upgrade to. Matches appear under Attack surface → Vulnerabilities with the usual KEV/EPSS priorities and fix-by
dates; a package that has been upgraded closes its finding on the next run.

Allow that host through your egress firewall. The files are kept in `<KEYSTONE_DATA_DIR>/osv/` (a few hundred MB per
distribution) and can be deleted at any time; they're downloaded again. Windows and Mac software is listed but not
matched: use your scanner or Defender Vulnerability Management for those.

### Vulnerability priorities and fix-by dates

**Attack surface → Vulnerabilities** lists open vulnerabilities in the order to fix them:

| Priority | Rule |
|---|---|
| P1 Known exploited | A CVE on CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalogue |
| P2 Likely to be exploited | FIRST [EPSS](https://www.first.org/epss/) probability at or above the threshold (default 10 %), or the scanner reports a public exploit for a critical or high one |
| P3 | Critical or high |
| P4 | Medium or low |

Each gets a **fix-by date**: first seen plus the deadline for its severity (defaults: critical 15, high 30, medium 90,
low 180 days). Known-exploited ones get the shorter KEV deadline (default 14 days), counted from when they were first
seen or added to the catalogue, whichever is later. The dashboard counts known-exploited and overdue vulnerabilities.
**Change** (needs the integration-management permission) sets the deadlines and threshold and can turn either feed off.

Both feeds are public and need no account. Once a day (and on **Update feeds now**) Keystone downloads the whole KEV
catalogue from `www.cisa.gov` and the whole EPSS daily file from `epss.empiricalsecurity.com`, then keeps only the
scores for CVEs it has seen. Because whole files are downloaded, neither site learns which vulnerabilities you have.
Allow those two hosts through your egress firewall. If a download fails, the previous data is kept, the error is
shown on the page, and the `vuln-intel` job shows as failed under System health.

### Internet-facing domains

**Attack surface → Internet-facing** checks the domains your organisation uses for its website and email, the way
anyone on the internet sees them. Add a domain, publish the TXT record Keystone shows at
`_keystone-verification.<domain>` (or on the domain itself), and press **Verify**. Keep the record: Keystone looks for it
before every check and stops checking a domain whose record has gone. This is what stops Keystone being used to map
domains you don't own.

What it looks at, once a day and on **Check now** (needs the integration-management permission):

- **Email security** of the domain: SPF (missing, several records, `+all`, no `-all`/`~all`), DMARC (missing, or
  `p=none`), and whether a CAA record limits who may issue certificates.
- **Host names** under the domain from certificate transparency logs (via `crt.sh`), plus the domain itself, `www`, and
  any host you add by hand (for names behind a wildcard certificate). Up to 300 per domain.
- For each host: its DNS records; a **dangling CNAME** (pointing at a cloud name that no longer exists, so someone else
  could claim it); a public name that points to an **internal address**; and, for hosts with public addresses,
  **HTTPS**: TLS version, certificate validity and expiry, whether plain HTTP redirects to HTTPS, and HSTS.

It never port-scans, never tries logins or vulnerability probes, and only connects to ports 443 and 80 of public
addresses under a verified domain. New critical or high issues notify the ISMS managers, and the dashboard counts them.
DNS queries go through the server's own resolver; allow `crt.sh` through your egress firewall for discovery (it is also
used every day to look for look-alike domains, Risk → Domain protection). Supplier breach news needs
`haveibeenpwned.com`: Keystone downloads the whole public breach list once a day and matches it to your vendors itself. Some DNS
providers answer "no records" instead of "no such name" for missing names, so a dangling CNAME there isn't detected:
the check errs towards silence rather than false alarms.

## Configuration baselines and agents

**Configuration** (needs `integration.manage`) holds the baselines, the agents and firewall uploads.

1. **Baselines.** Create one per platform. "Start with the recommended settings" fills in Keystone's recommended
   rules. The first baseline of a platform becomes its default.
2. **Agents.** Set `KEYSTONE_PUBLIC_URL` to the HTTPS address hosts reach Keystone on. The Agents tab shows the
   download, its SHA-256 and the one-line install command with the enrolment key.
   - **Windows** (elevated PowerShell 5.1+): installs to `%ProgramFiles%\Keystone Agent`, keeps its config and token in
     `%ProgramData%\Keystone Agent` (SYSTEM and Administrators only), and registers the scheduled task "Keystone Agent"
     (SYSTEM, at startup and every hour). `-Collect` prints what would be sent without sending.
   - **macOS** (sudo; `sh` and `curl` are built in): installs to `/usr/local/lib/keystone-agent`, keeps config and token
     in `/etc/keystone-agent` (mode 600), and loads `/Library/LaunchDaemons/org.keystone.agent.plist` (every hour).
     `sh keystone-agent-macos.sh collect` prints what would be sent. Some settings need Full Disk Access for the agent
     to read them on recent macOS; without it they show as unknown, never as passing.
   - **Linux** (root, `sh` and `curl`): installs to `/usr/local/lib/keystone-agent`, keeps config and token in
     `/etc/keystone-agent` (mode 600), and adds a systemd timer, or `/etc/cron.d/keystone-agent` without systemd, that
     runs every hour. `sh keystone-agent.sh collect` prints what would be sent.
   - Agents 1.2 and later **check in every hour** and send a full report when Keystone says one is due (the "Report at
     least every" setting) or when their own `--hours` have passed. A host that hasn't checked in for 3 hours is shown
     as quiet and notified. Older agents keep working and report on their old schedule.
   - **Updating** agents: Keystone never pushes code to hosts (a compromised Keystone must not mean compromised hosts).
     Hosts on an older agent are marked "update to …"; reinstall them with the new script. Check every download's
     SHA-256 first: the Agents tab shows the command.
   - **Integrity**: each agent reports the SHA-256 of its own script. Keystone records every script it has served, and
     marks any other hash as **Modified agent**. This catches accidental and careless changes; someone with
     administrator rights on the host could still fake the hash, so treat agent results as reported data.
   - **Signed Windows agent**: to run the agent under an `AllSigned` execution policy, sign
     `agents/windows/keystone-agent.ps1` with your organisation's code-signing certificate (`Set-AuthenticodeSignature`)
     and put the signed copy at `<KEYSTONE_DATA_DIR>/agents/keystone-agent.ps1`. Keystone serves it only if, without its
     signature block, it is exactly the shipped script; otherwise it logs a warning and serves the shipped one.
   - **Pinning** (optional): `--pin sha256//BASE64` (Windows `-Pin`) makes an agent accept only a server whose public
     key matches, in addition to the normal certificate checks. Give two pins separated by `;` before a certificate
     renewal that changes the key, or renew with the same key (certbot `--reuse-key`). On Windows, pinning needs Windows
     PowerShell 5.1, which the scheduled task uses.
   - For many hosts, deploy the same command through your RMM, Group Policy, Intune, Ansible or similar.
   - Rotate the enrolment key when installs are done; enrolled agents keep working. Or limit it: an expiry in days
     and/or a maximum number of installs (Agents tab → Enrolment key → Change limits).
   - Revoke a device from its page.
   - A reinstall enrols as a new device, so remove the old entry.
3. **Firewalls.** Upload a configuration export under "Upload firewall configuration", choosing "Update" to replace
   an existing firewall's results. Export the *full* configuration where the device offers it (FortiGate: `show
   full-configuration`): settings left at their defaults are missing from shorter exports and show as unknown. The
   file is not stored.
4. **Custom checks** (Configuration → Custom checks).
   - Add one from the library, or create your own: choose the platform, what to read (the probe) and its
     parameters, the value type, and optionally a value to use when the setting isn't present.
   - Add the check to a baseline as a rule. The rule is pre-filled with the check's suggested value.
   - Agents fetch the definitions on each run. Firewall checks run when a configuration is uploaded, so upload again
     after adding one.
   - Install an agent with `-NoCustomChecks` / `--no-custom-checks` to keep a host on the built-in settings only.
     Its custom results then show as unknown.
   - Probes that read file contents refuse password, key and home-directory files. Keystone refuses to save such a
     check, and the agents refuse to run one even if told to. On macOS that includes the local directory's password
     store, keychains and users' home folders.
5. **Scoping.** Which baselines apply to a host:
   - Its pinned baseline, or else the platform default.
   - Plus every baseline whose scope matches it: one of the baseline's tags, or a host-name pattern such as `web-*`.
   Give hosts tags at install (`-Tags web,dmz` / `--tags web,dmz`) or on their page. A rule can also be limited to
   tags ("Only for tags").
6. **Sharing baselines.** Export a baseline as JSON (with the custom checks it uses) and import it into another
   Keystone. Imports are validated like hand-made baselines. Unknown control codes are dropped and listed, and a
   custom check with the same key but a different definition stops the import.
7. **Housekeeping.** A job every 6 hours ends expired exceptions, refreshes evidence for baselines that every target
   meets, and keeps the last 500 reports of history per target.

Agents report every 4 hours by default (Agents tab). A host is shown as out of date after three missed reports, and a
firewall after 90 days without an upload.

## API tokens

Staff can create personal API tokens under **My account** for scripts and reporting tools (`Authorization: Bearer
kst_…`). A token acts as its owner, with the owner's current permissions; read-only tokens allow GET only. Tokens
expire within a year, are stored hashed and shown once, stop working when the owner is deactivated or expires, and can
be revoked by the owner or a user administrator (**Show everyone's tokens**). They can never be used for account and
security administration (`/api/auth`, `/api/tokens`, `/api/users`, `/api/settings/*`, `/api/scim`): those need a
signed-in session. Each token records when and from where it was last used; changes made with a token are audited as
its owner.

## Chat and webhooks (Slack, Teams, signed webhooks)

**Settings → Chat and webhooks** (integration-management permission) sends events to channels and systems:

| Event | When |
|---|---|
| Incident reported | Any new incident (reference and severity only: titles stay in Keystone) |
| Critical or high attack surface finding | New findings, summarised per baseline |
| Known-exploited vulnerability found | Open vulnerabilities newly matched to CISA KEV |
| Critical or high internet-facing issue | New issues on verified domains |
| System health problem | Failed jobs and backup problems (as administrators are alerted) |
| Policy version approved | Each approval |
| Access review completed | Each completed campaign |

- **Slack:** an incoming webhook URL (`https://hooks.slack.com/services/...`).
- **Teams:** in the channel, Workflows → "Post to a channel when a webhook request is received"; copy the URL
  (`*.logic.azure.com` or `*.environment.api.powerplatform.com`; legacy connector URLs on `*.webhook.office.com` also work).
- **Webhook:** any public HTTPS URL. Each POST carries JSON `{id, event, created_at, data: {title, detail, severity, ref,
  url}}` and the headers `X-Keystone-Event`, `X-Keystone-Delivery` and `X-Keystone-Signature: t=<unix time>,v1=<hex>`,
  where v1 is HMAC-SHA256 of `<t>.<raw body>` with the signing secret shown once when the destination is created.
  Reject requests whose t is more than a few minutes old. An internal endpoint must be listed in
  `KEYSTONE_INTEGRATION_PRIVATE_HOSTS`.

Messages are queued with the change that caused them and sent within a minute; failures are retried after 1, 5, 30,
120 and 720 minutes. URLs are stored encrypted and shown only as their host (Slack and Teams URLs contain their
token); **Send test** checks a destination at once.

## Ticketing (Jira, ServiceNow, ConnectWise PSA, Autotask)

**Integrations → Ticketing** connects your service desk, so people can open a ticket from a vulnerability, an attack
surface finding, a task or a nonconformity (**Ticket** button), and see when it's closed.

| System | Keystone needs | Creates |
|---|---|---|
| Jira Cloud | Site, a dedicated user's email and API token, project key, issue type | An issue in the project |
| ServiceNow | Instance, an integration user (web service access only), incident or problem, optional assignment group | An incident or problem |
| ConnectWise PSA | API site (or your server), company ID, API member keys, clientId, service board ID, company record ID | A service ticket |
| Autotask | Zone URL, API user and secret, tracking identifier, company ID, optional queue | A ticket |

Keystone **only creates tickets and reads their status**: it never edits, comments on or closes them, and reads
nothing else. Give the account only the rights to do that, in one project, table, board or queue. Each ticket holds a
title, a short factual description built by Keystone (for incidents, only the reference, title and severity) and a
link back to the record; one ticket per record per system. Raising a ticket needs the same permission as changing the
record (for example task-write for tasks, control-write for vulnerabilities and findings). The integration runs hourly:
it reads the status of open tickets, and tells whoever raised a ticket when it closes. Closing a ticket doesn't close
the Keystone record; vulnerabilities and findings close when the tools stop reporting them.

**Open tickets automatically** (off by default) opens one for each new known-exploited (P1), or P1 and P2,
vulnerability, at most 25 per run. Credentials are encrypted, write-only, and dropped if the site address changes. The
field mappings come from each vendor's API documentation: try **Test connection** and one ticket before relying on it.

## AI (optional)

Keystone works fully without AI. To turn on the policy assistant and questionnaire drafting,
open **Settings → AI** (administrators only), paste an Anthropic API key (or set
`ANTHROPIC_API_KEY`), choose the model (default `claude-opus-5-5`) and effort, and switch it on.
The server needs outbound HTTPS to `api.anthropic.com`.

What is sent: the policy assistant sends the document being edited, its linked controls, the
instruction and the organisation profile. Questionnaire drafting sends the questions and the
text of **approved** policies and approved knowledge-base answers. **Control narratives**
(Controls → Edit → Draft with AI) send the control, the identifiers and Keystone-written titles of
the requirements it maps to (never licensed text), the titles of linked approved policies, its
current implementation notes and the organisation profile. **Risk suggestions** (Risk register →
Suggest risks) send the organisation profile, the asset list (name, type, classification, ratings,
personal-data flag), active suppliers (name, services, criticality) and the control catalogue;
existing risks are never sent, and suggestions that duplicate one are removed inside Keystone.
People records, users, risks, incidents, evidence files and credentials are never sent.
Everything Claude returns is a draft: a person saves the notes or picks which risks to add. Every call is listed under
**Settings → AI** with its user, feature, model and token counts, and written to the audit
log. A refused or failed call is recorded too and changes nothing.
