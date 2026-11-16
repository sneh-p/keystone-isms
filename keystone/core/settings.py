"""Runtime settings, read from environment variables (prefix KEYSTONE_)."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("KEYSTONE_DATA_DIR", PROJECT_ROOT / "data")))
    db_url: str = field(default_factory=lambda: os.environ.get("KEYSTONE_DB_URL", ""))
    session_timeout_minutes: int = field(default_factory=lambda: int(os.environ.get("KEYSTONE_SESSION_TIMEOUT_MINUTES", "30")))
    max_upload_mb: int = field(default_factory=lambda: int(os.environ.get("KEYSTONE_MAX_UPLOAD_MB", "25")))
    # Public base URL for links Keystone hands out (invitations, Trust Center access). Never derived from the
    # request's Host header (SC-CFG-006). When unset, the API returns paths and the browser adds its own origin.
    public_url: str = field(default_factory=lambda: os.environ.get("KEYSTONE_PUBLIC_URL", "").strip().rstrip("/"))
    min_password_length: int = 12
    max_failed_logins: int = 5
    lockout_minutes: int = 15

    def __post_init__(self) -> None:
        if self.public_url and not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d{1,5})?", self.public_url):
            raise ValueError("KEYSTONE_PUBLIC_URL must be a scheme and host, for example https://isms.example.com")

    @property
    def database_url(self) -> str:
        """KEYSTONE_DB_URL, or SQLite in the data directory. For PostgreSQL, keep the password out of the URL and the
        environment by pointing KEYSTONE_DB_PASSWORD_FILE at a file (for example a Docker secret)."""
        if not self.db_url:
            return f"sqlite:///{self.data_dir / 'keystone.db'}"
        pw_file = os.environ.get("KEYSTONE_DB_PASSWORD_FILE", "").strip()
        if not pw_file:
            return self.db_url
        from sqlalchemy.engine import make_url

        password = Path(pw_file).read_text(encoding="utf-8").strip()
        return make_url(self.db_url).set(password=password).render_as_string(hide_password=False)

    @property
    def attachments_dir(self) -> Path:
        return self.data_dir / "attachments"


def get_settings() -> Settings:
    return Settings()
