"""Run Alembic migrations programmatically (used at app start and by scripts)."""

from __future__ import annotations

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from .settings import PROJECT_ROOT, get_settings


class UnversionedSchemaMismatch(RuntimeError):
    pass


def alembic_config(url: str | None = None) -> Config:
    cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url or get_settings().database_url)
    cfg.attributes["configure_logger"] = False
    return cfg


def upgrade_to_head(url: str | None = None) -> None:
    url = url or get_settings().database_url
    if url.startswith("sqlite:///"):
        from pathlib import Path

        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    cfg = alembic_config(url)
    eng = create_engine(url)
    try:
        tables = set(inspect(eng).get_table_names())
        if "alembic_version" not in tables and "users" in tables:
            # Created directly from the models (tests, early versions): adopt it if it matches.
            from keystone import models  # noqa: F401
            from keystone.core.db import Base

            with eng.connect() as conn:
                diffs = compare_metadata(MigrationContext.configure(conn, opts={"render_as_batch": True}), Base.metadata)
            if diffs:
                raise UnversionedSchemaMismatch(f"Database has tables but no migration history, and differs from the models: {diffs[:5]}")
            command.stamp(cfg, "head")
            from .audit import install_db_guards

            install_db_guards(eng)
            return
    finally:
        eng.dispose()
    command.upgrade(cfg, "head")
