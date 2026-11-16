"""In-process scheduler for recurring jobs (integration checks, task recurrence)."""

from __future__ import annotations

import logging
import os

_LOG = logging.getLogger(__name__)
_scheduler = None
JOBS: list[tuple[str, int, object]] = []  # (name, interval minutes, callable)


def register(name: str, minutes: int):
    def deco(fn):
        JOBS.append((name, minutes, fn))
        return fn

    return deco


def start_scheduler() -> None:
    global _scheduler
    if _scheduler is not None or os.environ.get("KEYSTONE_DISABLE_SCHEDULER"):
        return
    from apscheduler.schedulers.background import BackgroundScheduler

    import keystone.jobs  # noqa: F401  - registers jobs

    _scheduler = BackgroundScheduler(timezone="UTC")
    for name, minutes, fn in JOBS:
        _scheduler.add_job(fn, "interval", minutes=minutes, id=name, max_instances=1, coalesce=True)
    _scheduler.start()
    _LOG.info("scheduler started with %d job(s)", len(JOBS))


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
