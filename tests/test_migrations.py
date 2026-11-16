"""Phase 11: the Alembic baseline produces exactly the schema the models describe."""

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DatabaseError

from keystone import models  # noqa: F401
from keystone.core.db import Base
from keystone.core.migrate import alembic_config, upgrade_to_head
from tests.conftest import _test_db_url


def _url(tmp_path, name: str) -> str:
    """SQLite file per test, or the throwaway PostgreSQL database under scripts/test-postgres.sh."""
    url = _test_db_url(tmp_path)
    return url if url.startswith("postgresql") else f"sqlite:///{tmp_path / name}"


def test_upgrade_matches_models(tmp_path):
    url = _url(tmp_path, "m.db")
    upgrade_to_head(url)
    eng = create_engine(url)
    with eng.connect() as conn:
        diffs = compare_metadata(MigrationContext.configure(conn, opts={"render_as_batch": True}), Base.metadata)
    assert diffs == []
    assert set(inspect(eng).get_table_names()) - {"alembic_version"} == set(Base.metadata.tables)


def test_migrated_audit_log_is_append_only(tmp_path):
    url = _url(tmp_path, "m.db")
    upgrade_to_head(url)
    eng = create_engine(url)
    with eng.begin() as conn:
        conn.execute(text("INSERT INTO audit_log (ts, actor_name, action, entity_type, summary, prev_hash, hash) VALUES ('2026-01-01', 'x', 'create', 'T', '', 'a', 'b')"))
    statements = ["UPDATE audit_log SET summary='x'", "DELETE FROM audit_log"]
    if eng.dialect.name == "postgresql":
        statements.append("TRUNCATE audit_log")  # skips row triggers; has its own guard
    for stmt in statements:
        with pytest.raises(DatabaseError, match="append-only"):
            with eng.begin() as conn:
                conn.execute(text(stmt))


def test_upgrade_is_idempotent_and_downgrade_works(tmp_path):
    from alembic import command

    url = _url(tmp_path, "m.db")
    upgrade_to_head(url)
    upgrade_to_head(url)
    command.downgrade(alembic_config(url), "base")
    assert set(inspect(create_engine(url)).get_table_names()) == {"alembic_version"}


def test_unversioned_database_is_adopted(tmp_path):
    from keystone.core import db

    url = _url(tmp_path, "legacy.db")
    db.configure(url)
    db.create_all()
    upgrade_to_head(url)
    with create_engine(url).connect() as conn:
        from alembic.script import ScriptDirectory
        head = ScriptDirectory.from_config(alembic_config(url)).get_current_head()
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == head
    upgrade_to_head(url)  # and a second start is a no-op
    db.engine().dispose()


def test_each_migration_runs_on_populated_data(tmp_path):
    """Migrations must work on a live database, not only an empty one: rebuilding a table that others reference
    fails in SQLite while foreign keys are enforced (what broke the first version of 0015)."""
    from alembic import command
    from alembic.script import ScriptDirectory

    url = _url(tmp_path, "live.db")
    cfg = alembic_config(url)
    revisions = [r.revision for r in reversed(list(ScriptDirectory.from_config(cfg).walk_revisions()))]
    eng = create_engine(url)
    for i, rev in enumerate(revisions):
        command.upgrade(cfg, rev)
        if i == 0:
            with eng.begin() as conn:  # a user and rows that reference it, from the baseline onwards
                conn.execute(text("INSERT INTO users (id, username, display_name, role, password_hash, active, must_change_password, failed_logins, created_at, updated_at) "
                                  "VALUES (1, 'admin', 'Admin', 'admin', 'x', TRUE, FALSE, 0, '2026-01-01', '2026-01-01')"))
                conn.execute(text("INSERT INTO assets (name, asset_type, classification, confidentiality, integrity, availability, contains_personal_data, status, owner_id, created_by_id, created_at, updated_at) "
                                  "VALUES ('Laptop', 'hardware', 'internal', 3, 3, 3, FALSE, 'active', 1, 1, '2026-01-01', '2026-01-01')"))
    with eng.connect() as conn:
        if eng.dialect.name == "sqlite":  # PostgreSQL enforces foreign keys on every statement
            assert conn.execute(text("PRAGMA foreign_key_check")).fetchall() == []
        assert conn.execute(text("SELECT count(*) FROM users")).scalar() == 1
