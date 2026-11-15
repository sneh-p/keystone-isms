"""File attachments (evidence, policy documents). Stored content-addressed under data/attachments."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from sqlalchemy import Integer, String, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from .db import Audited, Base, OwnedMixin, TimestampMixin
from .settings import get_settings

ALLOWED_EXTENSIONS = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".txt": "text/plain",
    ".csv": "text/csv",
    ".md": "text/markdown",
    ".json": "application/json",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".msg": "application/vnd.ms-outlook",
    ".eml": "message/rfc822",
}
# Magic numbers checked for types where a mismatch suggests a disguised file.
MAGIC = {
    ".pdf": [b"%PDF"],
    ".png": [b"\x89PNG"],
    ".jpg": [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".gif": [b"GIF8"],
    ".docx": [b"PK\x03\x04"],
    ".xlsx": [b"PK\x03\x04"],
    ".pptx": [b"PK\x03\x04"],
}


class AttachmentRejected(ValueError):
    pass


class Attachment(Audited, OwnedMixin, TimestampMixin, Base):
    __tablename__ = "attachments"
    REF_PREFIX = "ATT"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str] = mapped_column(String(120), nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entity_type: Mapped[str | None] = mapped_column(String(80), nullable=True)
    entity_id: Mapped[int | None] = mapped_column(Integer, nullable=True)


def safe_filename(name: str) -> str:
    name = Path(name.replace("\\", "/")).name
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip(" .")
    return (name or "file")[:200]


def _blob_path(sha: str) -> Path:
    return get_settings().attachments_dir / sha[:2] / sha


def save_attachment(session: Session, actor, filename: str, data: bytes, entity_type: str | None = None, entity_id: int | None = None) -> Attachment:
    if actor is None:
        raise AttachmentRejected("uploads require a signed-in user")
    session.info["actor"] = actor
    fname = safe_filename(filename)
    ext = Path(fname).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise AttachmentRejected(f"File type {ext or '(none)'} is not allowed.")
    limit = get_settings().max_upload_mb * 1024 * 1024
    if len(data) == 0:
        raise AttachmentRejected("File is empty.")
    if len(data) > limit:
        raise AttachmentRejected(f"File is larger than {get_settings().max_upload_mb} MB.")
    if ext in MAGIC and not any(data.startswith(m) for m in MAGIC[ext]):
        raise AttachmentRejected(f"File content does not match its {ext} extension.")
    sha = hashlib.sha256(data).hexdigest()
    path = _blob_path(sha)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(path)
    att = Attachment(filename=fname, content_type=ALLOWED_EXTENSIONS[ext], size=len(data), sha256=sha, entity_type=entity_type, entity_id=entity_id)
    session.add(att)
    session.flush()
    return att


def read_attachment(att: Attachment) -> bytes:
    data = _blob_path(att.sha256).read_bytes()
    if hashlib.sha256(data).hexdigest() != att.sha256:
        raise RuntimeError(f"Attachment {att.id} failed its integrity check.")
    return data


def attachments_for(session: Session, entity_type: str, entity_id: int) -> list[Attachment]:
    return list(session.scalars(select(Attachment).where(Attachment.entity_type == entity_type, Attachment.entity_id == entity_id).order_by(Attachment.created_at)))
