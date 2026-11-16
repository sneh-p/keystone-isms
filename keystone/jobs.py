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
