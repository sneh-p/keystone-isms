# Administrator guide

## Installing

**Python** (3.11 or later):

```bash
python3 -m venv .venv && .venv/bin/pip install .
KEYSTONE_DATA_DIR=/srv/keystone .venv/bin/streamlit run app.py --server.address 127.0.0.1
```

**Docker**:

```bash
docker build -t keystone-isms .
docker run -d --name keystone -p 127.0.0.1:8501:8501 -v keystone-data:/data keystone-isms
```

On start, Keystone runs its database migrations (Alembic) automatically. The first visitor
sees a setup screen to create the first administrator. Do this straight away after deploying.

### Behind nginx (port 80)

`deploy/nginx/keystone.conf` publishes Keystone on port 80 and keeps Streamlit on
`127.0.0.1:8501`. It passes the WebSocket that Streamlit uses for every click, keeps the Host
header (Streamlit checks it against the browser's Origin), disables buffering and allows 50 MB
uploads.

```bash
sudo apt-get install nginx
sudo cp deploy/nginx/keystone.conf /etc/nginx/sites-available/keystone.conf
sudo ln -s /etc/nginx/sites-available/keystone.conf /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default && sudo nginx -t && sudo systemctl reload nginx
```

Run Keystone itself with `deploy/systemd/keystone.service` (or the Docker image bound to
`127.0.0.1:8501`). Port 80 is plain HTTP: add TLS (for example with certbot) before real use.

## Hardening checklist

- [ ] Put Keystone behind a reverse proxy (nginx, Caddy, Traefik) that **terminates TLS**, and
      bind Streamlit to `127.0.0.1` or a private network. The proxy must allow WebSocket upgrades
      for `/_stcore/stream`.
- [ ] Restrict who can reach the site: VPN, IP allowlist or an identity-aware proxy.
- [ ] Put the data directory on an **encrypted** volume. It holds the database and every
      uploaded evidence file.
- [ ] Back up the data directory (see below) and test a restore.
- [ ] Set `KEYSTONE_SESSION_TIMEOUT_MINUTES` to match your policy.
- [ ] Review `config/*.yaml`. The shipped values are calibration starting points.
- [ ] Give people the least-privileged role that fits their work. Keep two administrators.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `KEYSTONE_DATA_DIR` | `./data` | Database (SQLite) and attachments |
| `KEYSTONE_DB_URL` | SQLite in the data dir | e.g. `postgresql+psycopg://keystone:…@db/keystone` (install the driver) |
| `KEYSTONE_SESSION_TIMEOUT_MINUTES` | 30 | Idle sign-out |
| `KEYSTONE_MAX_UPLOAD_MB` | 25 | Per-file upload limit |

Don't put secrets in the repository. Pass database credentials through the environment.

## Users and roles

| Role | Can |
|---|---|
| `admin` | Everything, including managing users |
| `isms_manager` | Everything except managing users: approve policies, accept risks, approve vendor assessments, verify corrective actions, run management reviews |
| `risk_owner` | Assets, risks, evidence, incidents, nonconformities |
| `control_owner` | Control implementation, evidence, incidents, nonconformities |
| `auditor` | Read everything (including the audit log) and record audit findings |
| `viewer` | Read, and acknowledge policies |

Users created by an admin must change their password at first sign-in. Five wrong passwords
lock an account for 15 minutes. An admin can reset a password (the user must then change it),
change a role or disable an account. Accounts are never deleted, so the audit trail stays
intact.

## Audit log

Every change to an ISMS record is written automatically, with the user, time and the changed
fields (password hashes are redacted). Sign-ins, failed sign-ins, imports and exports are
logged too. Rows are hash-chained, and database triggers refuse UPDATE and DELETE.
**Admin → Audit log** verifies the chain every time it opens. A failure means someone altered
the database outside Keystone. Treat that as a security incident.

## Backups

SQLite: stop the app, or use `sqlite3 keystone.db ".backup backup.db"`, and copy the
`attachments/` directory with it. PostgreSQL: `pg_dump` plus the attachments directory.
Attachments are stored by SHA-256, and Keystone checks the hash whenever a file is downloaded.

## Upgrades

Replace the code (or the image) and restart. Migrations run on start. Back up first.

## Framework content

**Frameworks → Content management** can re-apply the bundled packs (safe: your own mappings,
control status and SoA decisions are kept), turn frameworks on or off, and import licensed
official text for ISO 27001, SOC 2 or CIS. Licensed text stays in your database and is only
exported when someone explicitly chooses the "with licensed text" download.

## Entra exposure

Technicians run `collector/Invoke-VendorExposureCollector.ps1` with a read-only role and
upload `collected.json` on **Entra exposure → Exposure import**. Read
[collector/README.md](../collector/README.md) before the first run, including the guidance on
the Graph Command Line Tools consent prompt and on handling the output files.
