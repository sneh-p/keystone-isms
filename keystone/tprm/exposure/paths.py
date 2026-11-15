"""Filesystem locations for config and schema files."""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
CONFIG_DIR = PROJECT_ROOT / "config"
SCHEMA_PATH = PROJECT_ROOT / "schemas" / "collected.schema.json"
