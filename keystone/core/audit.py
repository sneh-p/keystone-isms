"""Append-only, hash-chained audit log.

Every flush that inserts, updates or deletes an `Audited` model writes one audit
row per object, automatically, so no service can forget to log a change. Rows
are chained: hash = sha256(prev_hash + canonical entry), so tampering with or
removing a row breaks verify_chain(). The table is protected from UPDATE and
DELETE by an ORM guard and by database triggers.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, Text, event, insert, inspect, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Mapped, Session, mapped_column

from .db import Audited, Base, utcnow

REDACTED = "***redacted***"


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    actor_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actor_name: Mapped[str] = mapped_column(String(150), nullable=False, default="system")
    action: Mapped[str] = mapped_column(String(40), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(80), nullable=False)
    entity_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    changes: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)


class AuditLogImmutable(RuntimeError):
    pass


@event.listens_for(AuditLog, "before_update")
def _no_update(*_):
    raise AuditLogImmutable("audit log is append-only")


@event.listens_for(AuditLog, "before_delete")
def _no_delete(*_):
    raise AuditLogImmutable("audit log is append-only")


GENESIS = "0" * 64


def _jsonable(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (bytes, bytearray)):
        return f"<{len(value)} bytes>"
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    return value


def _canonical(entry: dict) -> str:
    return json.dumps(_jsonable(entry), sort_keys=True, separators=(",", ":"), default=str)


def _entry_hash(prev_hash: str, entry: dict) -> str:
    return hashlib.sha256((prev_hash + _canonical(entry)).encode("utf-8")).hexdigest()


def _hashed_fields(row: dict) -> dict:
    return {k: row[k] for k in ("ts", "actor_id", "actor_name", "action", "entity_type", "entity_id", "summary", "changes")}


def _write(conn: Connection, actor, action: str, entity_type: str, entity_id: int | None, summary: str, changes: dict | None) -> None:
    prev = conn.execute(select(AuditLog.hash).order_by(AuditLog.id.desc()).limit(1)).scalar()
    row = {
        "ts": utcnow(),
        "actor_id": getattr(actor, "id", None),
        "actor_name": getattr(actor, "username", None) or "system",
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "summary": summary[:2000],
        "changes": _jsonable(changes) if changes else None,
    }
    row["prev_hash"] = prev or GENESIS
    row["hash"] = _entry_hash(row["prev_hash"], _hashed_fields(row))
    conn.execute(insert(AuditLog).values(**row))


def log_event(session: Session, actor, action: str, entity_type: str, entity_id: int | None = None, summary: str = "", changes: dict | None = None) -> None:
    """Explicit audit entry for events that are not row changes (login, export, approval)."""
    _write(session.connection(), actor, action, entity_type, entity_id, summary, changes)


def _columns(obj) -> list[str]:
    return [c.key for c in inspect(type(obj)).column_attrs]


def _snapshot(obj) -> dict:
    redact = set(getattr(obj, "__audit_redact__", ()))
    return {k: (REDACTED if k in redact else getattr(obj, k)) for k in _columns(obj) if k not in ("created_at", "updated_at")}


def _diff(obj) -> dict:
    redact = set(getattr(obj, "__audit_redact__", ()))
    state = inspect(obj)
    out = {}
    for key in _columns(obj):
        if key in ("updated_at",):
            continue
        hist = state.attrs[key].history
        if hist.has_changes():
            old = hist.deleted[0] if hist.deleted else None
            new = hist.added[0] if hist.added else None
            out[key] = [REDACTED, REDACTED] if key in redact else [old, new]
    return out


def _label(obj) -> str:
    for attr in ("title", "name", "username", "code", "display_name"):
        val = getattr(obj, attr, None)
        if val:
            return str(val)[:120]
    return ""


@event.listens_for(Session, "before_flush")
def _set_created_by(session: Session, _ctx, _instances):
    actor = session.info.get("actor")
    for obj in session.new:
        if hasattr(obj, "created_by_id") and getattr(obj, "created_by_id", None) is None and actor is not None:
            obj.created_by_id = actor.id


@event.listens_for(Session, "after_flush")
def _audit_changes(session: Session, _ctx):
    actor = session.info.get("actor")
    conn = session.connection()
    for obj in list(session.new):
        if isinstance(obj, Audited):
            _write(conn, actor, "create", type(obj).__name__, obj.id, f"Created {type(obj).__name__} {_label(obj)}".strip(), _snapshot(obj))
    for obj in list(session.dirty):
        if isinstance(obj, Audited) and session.is_modified(obj, include_collections=False):
            changes = _diff(obj)
            if changes:
                _write(conn, actor, "update", type(obj).__name__, obj.id, f"Updated {type(obj).__name__} {_label(obj)}".strip(), changes)
    for obj in list(session.deleted):
        if isinstance(obj, Audited):
            _write(conn, actor, "delete", type(obj).__name__, obj.id, f"Deleted {type(obj).__name__} {_label(obj)}".strip(), _snapshot(obj))


def verify_chain(session: Session) -> tuple[bool, int | None]:
    """Return (ok, first_bad_id)."""
    prev = GENESIS
    for row in session.execute(select(AuditLog).order_by(AuditLog.id)).scalars():
        fields = {
            "ts": row.ts,
            "actor_id": row.actor_id,
            "actor_name": row.actor_name,
            "action": row.action,
            "entity_type": row.entity_type,
            "entity_id": row.entity_id,
            "summary": row.summary,
            "changes": row.changes,
        }
        if row.prev_hash != prev or row.hash != _entry_hash(prev, fields):
            return False, row.id
        prev = row.hash
    return True, None


SQLITE_GUARDS = [
    "CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log "
    "BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;",
    "CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log "
    "BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;",
]
POSTGRES_GUARDS = [
    "CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$ "
    "BEGIN RAISE EXCEPTION 'audit log is append-only'; END; $$ LANGUAGE plpgsql;",
    "DROP TRIGGER IF EXISTS audit_log_no_change ON audit_log;",
    "CREATE TRIGGER audit_log_no_change BEFORE UPDATE OR DELETE ON audit_log "
    "FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();",
]


def guard_statements(dialect: str) -> list[str]:
    return {"sqlite": SQLITE_GUARDS, "postgresql": POSTGRES_GUARDS}.get(dialect, [])


def install_db_guards(engine: Engine) -> None:
    with engine.begin() as conn:
        for stmt in guard_statements(engine.dialect.name):
            conn.execute(text(stmt))
