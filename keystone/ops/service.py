"""Running backups (scheduled, on demand from Settings, or from the command line) and recording the outcome."""

from __future__ import annotations

import logging
import threading
from datetime import datetime

from sqlalchemy.orm import Session

from keystone.core import db
from keystone.core.audit import log_event
from keystone.core.services import authorize, get_or_404

from . import backup
from .models import BackupRun

_LOG = logging.getLogger(__name__)
_RUNNING = threading.Lock()  # one backup at a time in this process (scheduled or on demand)


class BackupBusy(RuntimeError):
    pass


def run_backup(actor) -> BackupRun:
    """Create, test-restore and prune. Each step's outcome is stored on a BackupRun; nothing here raises for an
    ordinary failure (the run is marked failed with a short reason instead)."""
    if not _RUNNING.acquire(blocking=False):
        raise BackupBusy("A backup is already running.")
    try:
        return _run(actor)
    finally:
        _RUNNING.release()


def _run(actor) -> BackupRun:
    with db.session_scope(actor) as s:
        run = BackupRun(started_at=datetime.now(), status="running")
        s.add(run)
        s.flush()
        run_id = run.id
    status, verified, detail, result = "failed", False, None, None
    try:
        result = backup.create_backup(db.engine())
        backup.trial_restore(result.path)
        verified = True
        status = "warning" if result.missing_files else "ok"
        detail = f"{len(result.missing_files)} stored file(s) missing or damaged on disk" if result.missing_files else None
        pruned = backup.prune()
        if pruned:
            detail = ((detail + "; ") if detail else "") + f"removed {len(pruned)} old backup(s)"
    except backup.BackupError as e:
        detail = str(e)[:500]
    except OSError as e:
        detail = f"couldn't write the backup ({type(e).__name__})"
        _LOG.exception("backup failed")
    with db.session_scope(actor) as s:
        run = get_or_404(s, BackupRun, run_id)
        run.finished_at, run.status, run.verified, run.detail = datetime.now(), status, verified, detail
        if result is not None:
            run.filename, run.size_bytes, run.rows, run.files = result.path.name, result.size, result.rows, result.files
        log_event(s, actor, "backup", "Backup", run_id, f"Backup {status}{' and verified' if verified else ''}")
    with db.session_scope() as s:
        return get_or_404(s, BackupRun, run_id)


def check_can_backup(session: Session, actor) -> None:
    """Permission check for the on-demand backup button (users.manage); the router runs it in the background."""
    authorize(session, actor, "users.manage")
    if _RUNNING.locked():
        raise BackupBusy("A backup is already running.")
