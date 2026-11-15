"""Phase 11: the Alembic baseline produces exactly the schema the models describe."""

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DatabaseError

from keystone import models  # noqa: F401
from keystone.core.db import Base
from keystone.core.migrate import alembic_config, upgrade_to_head


def test_upgrade_matches_models(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    upgrade_to_head(url)
    eng = create_engine(url)
    with eng.connect() as conn:
        diffs = compare_metadata(MigrationContext.configure(conn, opts={"render_as_batch": True}), Base.metadata)
    assert diffs == []
    assert set(inspect(eng).get_table_names()) - {"alembic_version"} == set(Base.metadata.tables)


def test_migrated_audit_log_is_append_only(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    upgrade_to_head(url)
    eng = create_engine(url)
    with eng.begin() as conn:
        conn.execute(text("INSERT INTO audit_log (ts, actor_name, action, entity_type, summary, prev_hash, hash) VALUES ('2026-01-01', 'x', 'create', 'T', '', 'a', 'b')"))
    for stmt in ("UPDATE audit_log SET summary='x'", "DELETE FROM audit_log"):
        with pytest.raises(DatabaseError, match="append-only"):
            with eng.begin() as conn:
                conn.execute(text(stmt))


def test_upgrade_is_idempotent_and_downgrade_works(tmp_path):
    from alembic import command

    url = f"sqlite:///{tmp_path / 'm.db'}"
    upgrade_to_head(url)
    upgrade_to_head(url)
    command.downgrade(alembic_config(url), "base")
    assert set(inspect(create_engine(url)).get_table_names()) == {"alembic_version"}


def test_unversioned_database_is_adopted(tmp_path):
    from keystone.core import db

    url = f"sqlite:///{tmp_path / 'legacy.db'}"
    db.configure(url)
    db.create_all()
    upgrade_to_head(url)
    with create_engine(url).connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0001"
    upgrade_to_head(url)  # and a second start is a no-op
    db.engine().dispose()
