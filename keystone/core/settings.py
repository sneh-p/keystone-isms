"""Runtime settings, read from environment variables (prefix KEYSTONE_)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("KEYSTONE_DATA_DIR", PROJECT_ROOT / "data")))
    db_url: str = field(default_factory=lambda: os.environ.get("KEYSTONE_DB_URL", ""))
    session_timeout_minutes: int = field(default_factory=lambda: int(os.environ.get("KEYSTONE_SESSION_TIMEOUT_MINUTES", "30")))
    max_upload_mb: int = field(default_factory=lambda: int(os.environ.get("KEYSTONE_MAX_UPLOAD_MB", "25")))
    min_password_length: int = 12
    max_failed_logins: int = 5
    lockout_minutes: int = 15

    @property
    def database_url(self) -> str:
        return self.db_url or f"sqlite:///{self.data_dir / 'keystone.db'}"

    @property
    def attachments_dir(self) -> Path:
        return self.data_dir / "attachments"


def get_settings() -> Settings:
    return Settings()
