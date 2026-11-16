"""Scheduled jobs. Each opens its own session and runs as the system actor."""

from __future__ import annotations

import logging

from keystone.core import db
from keystone.scheduler import register

_LOG = logging.getLogger(__name__)


@register("integration-checks", minutes=15)
def run_due_integrations() -> None:
    from keystone.integrations import service as integ

    with db.session_scope() as s:
        ids = [i.id for i in integ.due(s)]
    for iid in ids:
        try:
            with db.session_scope() as s:
                integ.run(s, None, iid)
        except Exception:  # noqa: BLE001 - one failing integration must not stop the others
            _LOG.exception("integration %s failed", iid)


@register("metric-snapshot", minutes=360)
def snapshot_metrics() -> None:
    """Record today's headline numbers for dashboard trends (idempotent per day)."""
    from keystone.reporting import dashboard

    with db.session_scope() as s:
        dashboard.take_snapshot(s)


@register("notifications", minutes=60)
def refresh_notifications() -> None:
    """Refresh every user's inbox, then send the daily email digest once the configured hour has passed."""
    from keystone.notifications import service as ntf

    with db.session_scope() as s:
        ntf.refresh_all(s)
    with db.session_scope() as s:  # mail errors are caught inside and recorded in smtp_settings.last_error
        ntf.send_digests(s)


@register("vuln-intel", minutes=1440)
def refresh_vuln_intel() -> None:
    """Download CISA KEV and the EPSS daily file, then re-prioritise open vulnerabilities (and move fix-by dates)."""
    from keystone.asm import vulnintel

    with db.session_scope() as s:
        vulnintel.refresh(s)


@register("external-scan", minutes=1440)
def scan_external() -> None:
    """Re-check ownership of each verified domain, then discover and check its hosts (passive; see asm/external.py)."""
    from keystone.asm import external

    with db.session_scope() as s:
        out = external.scan_all(s)
    if out["failed"]:
        raise RuntimeError(f"{out['failed']} domain(s) lost their verification record")


@register("backup", minutes=1440)
def nightly_backup() -> None:
    """Back up the database and stored files, test-restore the result into a scratch database, then prune old
    backups. Set KEYSTONE_BACKUP_DISABLE=1 when backups are taken another way (for example managed PostgreSQL)."""
    import os

    from keystone.ops.service import run_backup

    if os.environ.get("KEYSTONE_BACKUP_DISABLE"):
        return
    run = run_backup(None)
    if run.status == "failed":
        raise RuntimeError("backup failed")  # recorded by the scheduler listener as a failed run


@register("system-alerts", minutes=60)
def system_alerts() -> None:
    """Notify administrators about failing jobs and missing or unverified backups."""
    from keystone.ops.health import alert

    with db.session_scope() as s:
        alert(s)
