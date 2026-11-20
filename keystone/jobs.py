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
    from keystone.indicators.service import measure_all
    from keystone.reporting import dashboard

    with db.session_scope() as s:
        dashboard.take_snapshot(s)
        measure_all(s)


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

    from keystone.registers.service import sync_public_certificates
    from keystone.threatintel.service import scan_lookalikes

    with db.session_scope() as s:
        out = external.scan_all(s)
        sync_public_certificates(s)
        scan_lookalikes(s)
    if out["failed"]:
        raise RuntimeError(f"{out['failed']} domain(s) lost their verification record")


@register("privacy-redaction", minutes=1440)
def redact_privacy_requests() -> None:
    """Clear requesters' names and contact details from requests closed longer than KEYSTONE_DSR_REDACT_DAYS ago."""
    from keystone.privacy.service import redact_closed_requests

    with db.session_scope() as s:
        redact_closed_requests(s)


@register("outbound", minutes=1)
def deliver_outbound() -> None:
    """Send queued Slack, Teams and webhook messages (retries with backoff)."""
    from keystone.outbound.service import deliver_due

    with db.session_scope() as s:
        deliver_due(s)


@register("scheduled-reports", minutes=60)
def scheduled_reports() -> None:
    """Email the reports whose send date has come (checked hourly, sent once per due date)."""
    from keystone.reporting.schedules import run_due

    with db.session_scope() as s:
        run_due(s)


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


@register("config-baselines", minutes=360)
def config_baselines() -> None:
    """Configuration baselines: lapse expired exceptions (and re-evaluate), refresh evidence, trim drift history."""
    from keystone.configcheck import service as cfg

    with db.session_scope() as s:
        cfg.housekeeping(s)


@register("access-review-schedule", minutes=720)
def recurring_access_reviews() -> None:
    """Start the next campaign of recurring access reviews whose date has come."""
    from keystone.access_reviews import service as ar

    with db.session_scope() as s:
        ar.start_due_campaigns(s)


@register("breach-news", minutes=1440)
def breach_news() -> None:
    """Match the public breach list against vendors' web addresses (download only; see threatintel/service.py)."""
    from keystone.threatintel.service import scan_breaches

    with db.session_scope() as s:
        scan_breaches(s)


@register("phishing-simulations", minutes=5)
def phishing_simulations() -> None:
    """Send the next practice emails of running campaigns, and complete campaigns past their two weeks."""
    from keystone.phishing.service import complete_due, send_batch

    with db.session_scope() as s:
        send_batch(s)
        complete_due(s)


@register("on-call", minutes=5)
def on_call_escalation() -> None:
    """Escalate on-call pages nobody acknowledged in time."""
    from keystone.oncall.service import escalate

    with db.session_scope() as s:
        escalate(s)
