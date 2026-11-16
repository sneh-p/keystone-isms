# Administrator guide

## Installing

**Python** 3.12 (the hashed lockfile is resolved for 3.12; the Docker image uses it) and **Node.js** 22 (to build the web app once):

```bash
python3 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements.lock && .venv/bin/pip install --no-deps -e .
(cd web && npm ci && npm run build)
KEYSTONE_DATA_DIR=/srv/keystone .venv/bin/uvicorn keystone.api.app:create_app --factory --host 127.0.0.1 --port 8000
```

**Docker** (multi-stage: Node builds the web app, a slim Python image runs it):

```bash
docker compose up -d --build      # Keystone plus nginx on port 80
# or the image alone:
docker build -t keystone-isms .
docker run -d --name keystone -p 127.0.0.1:8000:8000 -v keystone-data:/data keystone-isms
```

On start, Keystone runs its database migrations (Alembic) automatically. The first visitor
sees a setup screen to create the first administrator, followed by the onboarding wizard. Do
this straight away after deploying.

One process serves everything: the web app, the API under `/api` (interactive docs at `/api/docs` only
when `KEYSTONE_API_DOCS=1`), the public Trust Center under `/trust/<slug>`, and a background scheduler that
runs integration checks every 15 minutes and records the dashboard's daily figures (for its trend lines). Run **one** instance per database, or set
`KEYSTONE_DISABLE_SCHEDULER=1` on all but one.

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
      `/vendor-portal`; people accepting invitations need `/invite`.
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
| `KEYSTONE_DB_URL` | SQLite in the data dir | e.g. `postgresql+psycopg://keystone:…@db/keystone` (install the driver) |
| `KEYSTONE_SESSION_TIMEOUT_MINUTES` | 30 | Idle sign-out |
| `KEYSTONE_MAX_UPLOAD_MB` | 25 | Per-file upload limit |
| `KEYSTONE_SECRET_KEY` | generated in the data dir | Fernet key that encrypts integration, email (SMTP), single sign-on and AI credentials. Set it to keep the key out of the data volume |
| `KEYSTONE_FRAME_ANCESTORS` | `'self'` | Who may embed Keystone in a frame (CSP source list), e.g. `https://intranet.example` |
| `KEYSTONE_DISABLE_SCHEDULER` | unset | Set to `1` to stop this instance running scheduled integration checks |
| `ANTHROPIC_API_KEY` | unset | Optional key for AI features, used when no key is stored under **Settings → AI** |
| `KEYSTONE_PUBLIC_URL` | unset | Public address for links Keystone hands out, e.g. `https://isms.example.com`. When unset, links use the address the administrator's browser is on |
| `KEYSTONE_API_DOCS` | unset | Set to `1` to serve the interactive API docs and OpenAPI schema (development only) |
| `KEYSTONE_SMTP_PRIVATE_HOSTS` | unset | Comma-separated host names of internal SMTP relays Keystone may connect to. Without it, only relays with public addresses are allowed |
| `KEYSTONE_CLAMD_SOCKET` | `/var/run/clamav/clamd.ctl` | ClamAV daemon socket used to scan vendor uploads |
| `KEYSTONE_INTEGRATION_PRIVATE_HOSTS` | unset | Comma-separated host names of self-hosted tools inside your network (N-central, ConnectWise Automate) that attack surface connectors may reach. Without it, only public addresses are allowed |
| `KEYSTONE_CLAMD_TCP` | unset | `host:port` of a ClamAV daemon (for example a ClamAV container), used instead of the socket |

Don't put secrets in the repository. Pass database credentials through the environment.

## Users and roles

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

## Single sign-on (Microsoft Entra ID, Google)

**Settings → Single sign-on.** `KEYSTONE_PUBLIC_URL` must be set: the provider sends people back
to `<KEYSTONE_PUBLIC_URL>/api/auth/oidc/<entra|google>/callback`, shown on the page to copy.

- **Entra ID:** register a single-tenant app (web platform) with that redirect URI and create a
  client secret. Enter the directory (tenant) ID, client ID and secret. Only accounts from that
  tenant can sign in (`common` and other multi-tenant endpoints are refused).
- **Google:** create an OAuth client (web application) with that redirect URI. Only verified
  email addresses are accepted.

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

In Docker, run a ClamAV container and set `KEYSTONE_CLAMD_TCP=clamav:3310`. Allow at least
1.5 GB of memory for the daemon.

## Audit log

Every change to an ISMS record is written automatically, with the user, time and the changed
fields (password hashes are redacted). Sign-ins, failed sign-ins, imports and exports are
logged too. Rows are hash-chained, and database triggers refuse UPDATE and DELETE.
**Admin → Audit log** verifies the chain every time it opens. A failure means someone altered
the database outside Keystone. Treat that as a security incident.

## Backups

SQLite: stop the app, or use `sqlite3 keystone.db ".backup backup.db"`, and copy the
`attachments/` directory and `secret.key` with it. PostgreSQL: `pg_dump` plus the attachments
directory and `secret.key` (or your `KEYSTONE_SECRET_KEY`). Without the key, stored integration
and AI credentials can't be decrypted and must be entered again.
Attachments are stored by SHA-256, and Keystone checks the hash whenever a file is downloaded.

## Upgrades

Replace the code (or the image) and restart. Migrations run on start. Back up first.

## Framework content

**Frameworks → Content management** can re-apply the bundled packs (safe: your own mappings,
control status and SoA decisions are kept), turn frameworks on or off, and import licensed
official text for ISO 27001, SOC 2 or CIS. Licensed text stays in your database and is only
exported when someone explicitly chooses the "with licensed text" download.

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
| GitHub | Fine-grained token with read-only *Administration* and *Metadata* on the organisation |
| AWS | An IAM user or role with the AWS-managed `SecurityAudit` policy |
| Microsoft Entra ID | None. It reads the latest imported exposure snapshot and doesn't call Microsoft Graph. (The separate **Microsoft 365** attack surface source does call Microsoft's APIs, read-only; see below.) |

Each Connect dialog has a setup guide with copyable commands, filled in with the values you
type, to create the credential and then verify it: for AWS, that the user has only
SecurityAudit and (with the IAM policy simulator, which changes nothing) that it can't modify
anything; for GitHub, that the token can read what the checks need. Secrets are never put into
these commands. **Test connection** runs the checks with the entered settings without saving
results or evidence, so you can confirm access before saving.

A website that blocks automated requests (HTTP 4xx/5xx) is reported as unknown, not as failing.
Redirects are followed over HTTPS only, and each new host must also be public.

Secrets are encrypted with `secret.key` and are write-only: the API never returns them, and the
audit log records only that they changed. A check that errors or can't decide is reported as
error or unknown, never as passing.

## Attack surface management

**Integrations → Attack surface sources** connect read-only to the tools that know your devices, accounts and
vulnerabilities; **Attack surface** shows the merged picture and the gaps against your baselines.

| Source | Provides | Read-only access to create |
|---|---|---|
| Microsoft 365 | Entra accounts and MFA registration, Intune compliance and encryption, Defender for Endpoint health and vulnerabilities, Secure Score | App registration, application permissions: User.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, DeviceManagementManagedDevices.Read.All, SecurityEvents.Read.All; WindowsDefenderATP Machine.Read.All, Vulnerability.Read.All |
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

## AI (optional)

Keystone works fully without AI. To turn on the policy assistant and questionnaire drafting,
open **Settings → AI** (administrators only), paste an Anthropic API key (or set
`ANTHROPIC_API_KEY`), choose the model (default `claude-opus-5-5`) and effort, and switch it on.
The server needs outbound HTTPS to `api.anthropic.com`.

What is sent: the policy assistant sends the document being edited, its linked controls, the
instruction and the organisation profile. Questionnaire drafting sends the questions and the
text of **approved** policies and approved knowledge-base answers. People records, users,
risks, incidents, evidence files and credentials are never sent. Every call is listed under
**Settings → AI** with its user, feature, model and token counts, and written to the audit
log. A refused or failed call is recorded too and changes nothing.
