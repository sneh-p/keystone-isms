"""In-process scheduler for recurring jobs (integration checks, task recurrence)."""

from __future__ import annotations

import logging
import os

from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED, EVENT_JOB_SUBMITTED

_LOG = logging.getLogger(__name__)
_scheduler = None
JOBS: list[tuple[str, int, object]] = []  # (name, interval minutes, callable)


def register(name: str, minutes: int):
    def deco(fn):
        JOBS.append((name, minutes, fn))
        return fn

    return deco


def _record(event) -> None:
    """APScheduler listener: record each job's start and outcome in job_status, so failures show under System health
    and raise an alert instead of only reaching the log. APScheduler logs (and survives) errors raised here, for
    example when the database itself is down."""
    from keystone.core import db
    from keystone.ops.health import record_end, record_start

    with db.session_scope() as s:
        if event.code == EVENT_JOB_SUBMITTED:
            record_start(s, event.job_id)
        else:
            record_end(s, event.job_id, getattr(event, "exception", None))


def running() -> bool:
    return _scheduler is not None


def start_scheduler() -> None:
    global _scheduler
    if _scheduler is not None or os.environ.get("KEYSTONE_DISABLE_SCHEDULER"):
        return
    from apscheduler.schedulers.background import BackgroundScheduler

    import keystone.jobs  # noqa: F401  - registers jobs

    _scheduler = BackgroundScheduler(timezone="UTC")
    for name, minutes, fn in JOBS:
        _scheduler.add_job(fn, "interval", minutes=minutes, id=name, max_instances=1, coalesce=True)
    _scheduler.add_listener(_record, EVENT_JOB_SUBMITTED | EVENT_JOB_EXECUTED | EVENT_JOB_ERROR)
    _scheduler.start()
    _LOG.info("scheduler started with %d job(s)", len(JOBS))


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
