"""Check-ins from scripts and CI (POST /api/inbound/checkin), with the same per-tool tokens as the alert inbox.

- A **backup** source reports a job's result: it records "successful backup" or "failure" on the backup job in the
  register (found by its reference, e.g. BAK-0003, or its exact name). Only those two steps; restore tests and anything
  needing a person's judgement stay with people (keystone/registers/service.SYSTEM_MOVES).
- A **CI** source reports a security scan of a release: the result is added to "Security testing done" on the open
  release sign-off for that application and version. It never signs anything off: someone other than the requester
  still decides.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from keystone.core.db import utcnow
from keystone.registers.models import RegisterEntry
from keystone.registers.service import system_move

from .models import AlertSource

MAX_TESTS_TEXT = 20_000


class CheckinRefused(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def _entry(session: Session, register: str, name: str) -> RegisterEntry | None:
    """By reference (BAK-0003) or exact title, ignoring case."""
    name = name.strip()
    ref = name.upper().rsplit("-", 1)
    if len(ref) == 2 and ref[1].isdigit():
        e = session.scalar(select(RegisterEntry).where(RegisterEntry.register == register, RegisterEntry.seq == int(ref[1])))
        if e is not None and e.ref.upper() == name.upper():
            return e
    rows = list(session.scalars(select(RegisterEntry).where(RegisterEntry.register == register, func.lower(RegisterEntry.title) == name.lower()).limit(2)))
    return rows[0] if len(rows) == 1 else None


def checkin(session: Session, source: AlertSource, *, kind: str, job: str | None = None, status: str | None = None, note: str | None = None,
            application: str | None = None, version: str | None = None, tool: str | None = None, result: str | None = None, summary: str | None = None) -> dict:
    who = f"{source.name} (check-in)"
    if kind == "backup":
        if source.kind != "backup":
            raise CheckinRefused(403, "Only a source of kind Backup can report backup results.")
        if not job or status not in ("success", "failure"):
            raise CheckinRefused(422, "Give the backup job (its reference or name) and status success or failure.")
        e = _entry(session, "backups", job)
        if e is None or e.status == "retired":
            raise CheckinRefused(404, "No such backup job (use its reference, e.g. BAK-0001, or its exact name).")
        system_move(session, e, status, who, note if status == "failure" else None)
        source.last_received_at, source.received = utcnow(), source.received + 1
        return {"entry": e.ref, "status": e.status}
    if kind == "release_scan":
        if source.kind != "ci":
            raise CheckinRefused(403, "Only a source of kind CI can report release scans.")
        if not application or not version or result not in ("pass", "fail"):
            raise CheckinRefused(422, "Give the application, the version and result pass or fail.")
        app = _entry(session, "applications", application)
        if app is None:
            raise CheckinRefused(404, "No such application in Application security.")
        rel = next((e for e in session.scalars(select(RegisterEntry).where(RegisterEntry.register == "release-signoffs", RegisterEntry.status == "requested"))
                    if (e.data or {}).get("application") == app.id and str((e.data or {}).get("version", "")).strip() == version.strip()), None)
        if rel is None:
            raise CheckinRefused(404, "No open release sign-off for that application and version.")
        line = f"[{utcnow():%Y-%m-%d %H:%M} UTC, {who}] {tool or 'scan'}: {result.upper()}" + (f" - {summary.strip()}" if summary and summary.strip() else "")
        text = ((rel.data or {}).get("tests") or "").rstrip()
        rel.data = {**(rel.data or {}), "tests": (f"{text}\n{line}" if text else line)[-MAX_TESTS_TEXT:]}
        source.last_received_at, source.received = utcnow(), source.received + 1
        session.flush()
        return {"entry": rel.ref, "status": rel.status}
    raise CheckinRefused(422, "Unknown kind.")
