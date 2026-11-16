"""Encryption at rest for integration credentials (Fernet: AES-128-CBC + HMAC-SHA256).

The key comes from KEYSTONE_SECRET_KEY (urlsafe base64, 32 bytes). If it is not set, a key is
generated once into <data dir>/secret.key with 0600 permissions. Back the key up with the database:
without it, stored credentials cannot be decrypted (they would have to be re-entered).
"""

from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken

from .settings import get_settings


def _key() -> bytes:
    env = os.environ.get("KEYSTONE_SECRET_KEY")
    if env:
        return env.encode()
    path = get_settings().data_dir / "secret.key"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(Fernet.generate_key())
    return path.read_bytes().strip()


def encrypt(plaintext: str) -> str:
    return Fernet(_key()).encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return Fernet(_key()).decrypt(token.encode()).decode()
    except InvalidToken:
        raise ValueError("Stored credentials cannot be decrypted with the current KEYSTONE_SECRET_KEY; re-enter them.") from None
