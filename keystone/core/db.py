"""Database engine, sessions and the declarative base."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Iterator

from sqlalchemy import DateTime, ForeignKey, Integer, MetaData, create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .settings import get_settings

NAMING = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class OwnedMixin:
    """created_by is set automatically from the session actor (see audit.py)."""

    created_by_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)


class Audited:
    """Marker: every insert/update/delete of subclasses is written to the audit log."""

    __audit_redact__: tuple[str, ...] = ()
    REF_PREFIX: str | None = None

    @property
    def ref(self) -> str:
        prefix = self.REF_PREFIX or type(self).__name__[:3].upper()
        return f"{prefix}-{(self.id or 0):04d}"  # type: ignore[attr-defined]


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover - driver specific
    if type(dbapi_conn).__module__.startswith("sqlite3"):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def configure(url: str | None = None) -> Engine:
    """(Re)configure the global engine. Tests call this with a temp database."""
    global _engine, _SessionLocal
    url = url or get_settings().database_url
    if url.startswith("sqlite:///"):
        from pathlib import Path

        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    _engine = create_engine(url, future=True)
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def engine() -> Engine:
    return _engine or configure()


def migrate() -> None:
    """Bring the configured database to the latest schema with Alembic (app start, scripts)."""
    from .migrate import upgrade_to_head

    upgrade_to_head(str(engine().url.render_as_string(hide_password=False)))


def create_all() -> None:
    """Create tables directly from the models (fast path used by tests)."""
    from keystone import models  # noqa: F401  - registers every model

    Base.metadata.create_all(engine())
    from .audit import install_db_guards

    install_db_guards(engine())


@contextmanager
def session_scope(actor=None) -> Iterator[Session]:
    """Transactional session. `actor` (a User) is recorded on audit entries."""
    if _SessionLocal is None:
        configure()
    assert _SessionLocal is not None
    session = _SessionLocal()
    session.info["actor"] = actor
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
