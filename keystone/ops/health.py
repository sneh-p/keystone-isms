"""Scheduled-job tracking, the system health summary for administrators, and alerts when something stops working."""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.services import authorize

from .models import BackupRun, JobStatus

FAILURES_BEFORE_ALERT = 2
BACKUP_MAX_AGE = timedelta(hours=26)  # daily backups, with slack


def record_start(session: Session, name: str, now: datetime | None = None) -> None:
    row = session.get(JobStatus, name) or JobStatus(name=name, consecutive_failures=0)
    row.last_started = now or datetime.now()
    session.add(row)


def record_end(session: Session, name: str, error: BaseException | None, now: datetime | None = None) -> None:
    now = now or datetime.now()
    row = session.get(JobStatus, name) or JobStatus(name=name, consecutive_failures=0)
    row.last_finished = now
    row.last_ok = error is None
    if error is None:
        row.last_success = now
        row.last_error = None
        row.consecutive_failures = 0
    else:
        row.last_error = type(error).__name__[:200]
        row.consecutive_failures = (row.consecutive_failures or 0) + 1
    session.add(row)


def _scanner_state() -> str:
    from keystone.core import antivirus

    try:
        antivirus.ping()
    except antivirus.ScannerUnavailable:
        return "unavailable"
    return "ok"


def problems(session: Session, now: datetime | None = None) -> list[dict]:
    """What needs an administrator's attention: failing jobs and missing, failed or unverified backups."""
    import os

    now = now or datetime.now()
    out: list[dict] = []
    for row in session.scalars(select(JobStatus).order_by(JobStatus.name)):
        if row.consecutive_failures >= FAILURES_BEFORE_ALERT:
            out.append({"key": f"job:{row.name}", "title": f"Scheduled job “{row.name}” has failed {row.consecutive_failures} times in a row ({row.last_error})"})
    if not os.environ.get("KEYSTONE_BACKUP_DISABLE"):  # backups taken another way (for example managed PostgreSQL)
        last = session.scalars(select(BackupRun).order_by(BackupRun.id.desc()).limit(1)).first()
        good = session.scalars(select(BackupRun).where(BackupRun.status.in_(("ok", "warning")), BackupRun.verified.is_(True)).order_by(BackupRun.id.desc()).limit(1)).first()
        if last is not None and last.status == "failed":
            out.append({"key": "backup:failed", "title": "The last backup failed"})
        elif last is not None and last.status == "warning":
            out.append({"key": "backup:warning", "title": "The last backup is missing stored files (see System health)"})
        if good is None or (good.finished_at and now - good.finished_at > BACKUP_MAX_AGE):
            out.append({"key": "backup:stale", "title": "No verified backup in the last 26 hours"})
    return out


def system_health(session: Session, actor) -> dict:
    """Administrator view (users.manage): jobs, backups, database and scanner. Holds no secrets or paths."""
    from keystone.core.db import engine
    from keystone.notifications.models import SmtpSettings
    from importlib import import_module

    from keystone.scheduler import JOBS, running

    import_module("keystone.jobs")  # registers the jobs, so they are listed even before the scheduler starts

    authorize(session, actor, "users.manage")
    jobs = {r.name: r for r in session.scalars(select(JobStatus))}
    backups = session.scalars(select(BackupRun).order_by(BackupRun.id.desc()).limit(10)).all()
    smtp = session.scalars(select(SmtpSettings).limit(1)).first()
    rev = session.connection().exec_driver_sql("SELECT version_num FROM alembic_version").scalar() if engine().dialect.has_table(session.connection(), "alembic_version") else None
    return {
        "database": engine().dialect.name,
        "schema_revision": rev,
        "scheduler_running": running(),
        "virus_scanner": _scanner_state(),
        "email": "configured" if smtp and smtp.enabled else "not configured",
        "jobs": [
            {
                "name": name, "every_minutes": minutes,
                "last_started": j.last_started if j else None, "last_finished": j.last_finished if j else None,
                "last_success": j.last_success if j else None, "last_ok": j.last_ok if j else None,
                "last_error": j.last_error if j else None, "consecutive_failures": j.consecutive_failures if j else 0,
            }
            for name, minutes, _fn in JOBS
            for j in [jobs.get(name)]
        ],
        "backups": [
            {"id": b.id, "started_at": b.started_at, "finished_at": b.finished_at, "filename": b.filename, "size_bytes": b.size_bytes,
             "rows": b.rows, "files": b.files, "status": b.status, "verified": b.verified, "detail": b.detail}
            for b in backups
        ],
        "problems": problems(session),
    }


def alert(session: Session, now: datetime | None = None) -> int:
    """Turn current problems into inbox notifications (and immediate emails) for active administrators. One
    notification per problem per day; resolved problems simply stop producing new ones. Returns notifications made."""
    from keystone.core.auth import User, expired
    from keystone.core.rbac import Role
    from keystone.notifications.models import Notification

    now = now or datetime.now()
    found = problems(session, now)
    if not found:
        return 0
    admins = [u for u in session.scalars(select(User).where(User.active.is_(True), User.role == Role.ADMIN.value)) if not expired(u)]
    made = 0
    fresh: dict[int, list[str]] = {}
    for p in found:
        key = f"system:{p['key']}:{now:%Y%m%d}"[:64]
        for u in admins:
            if session.scalar(select(Notification.id).where(Notification.user_id == u.id, Notification.key == key)) is None:
                session.add(Notification(user_id=u.id, key=key, kind="system", title=p["title"][:500], page="/settings/system", created_at=now))
                fresh.setdefault(u.id, []).append(p["title"])
                made += 1
    session.flush()
    if fresh:
        _email(session, admins, fresh)
        from keystone.outbound.service import emit

        for p in found:
            if any(p["title"] in lines for lines in fresh.values()):
                emit(session, "system.alert", title=p["title"], severity="high", page="/settings/system")
    return made


def _email(session: Session, admins, fresh: dict[int, list[str]]) -> None:
    from keystone.core.settings import get_settings
    from keystone.notifications import service as ntf

    base = get_settings().public_url
    tail = f"\n\nSystem health: {base}/settings/system\n" if base else "\n\nOpen Keystone and go to Settings, System health.\n"
    ntf.send_now(session, [(u.email, "Keystone needs attention", "Keystone found problems that need an administrator:\n\n" + "\n".join(f"- {t}" for t in fresh[u.id]) + tail)
                           for u in admins if u.id in fresh and u.email])
