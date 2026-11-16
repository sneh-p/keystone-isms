"""Backups that can be restored, and are: every scheduled backup is test-restored into a scratch database.

A backup is a gzip'd tar file that Keystone writes and reads itself:

    manifest.json              format, schema revision, created time, per-member SHA-256 and row counts
    tables/<table>.jsonl       every row of every table, one JSON object per line
    files/<sha256>             each stored attachment, named by its content hash

It is database-neutral: a backup taken from SQLite restores into PostgreSQL and the other way round, so it is also
how you move between the two. The encryption key (secret.key or KEYSTONE_SECRET_KEY) is deliberately not included:
keep it separately. Without it a restore works, but stored integration, SMTP, SSO and AI credentials must be
re-entered.

Reading a backup is defensive (SC-FILE-003): only regular members with the exact names above are accepted, sizes are
capped, every member is checked against the manifest's hash before anything is written, attachments are written only
under the name of their own verified hash, and nothing is ever extracted by the name stored in the archive. Restores
refuse a database that already holds data and a backup taken at a different schema revision. Restore is a command-line
operation for the server operator; the web app can't upload or restore a backup.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import re
import sqlite3
import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path

from sqlalchemy import JSON, Date, DateTime, Integer, LargeBinary, Numeric, Table, create_engine, func, insert, inspect, select, text, update
from sqlalchemy.engine import Connection, Engine

from keystone.core.settings import get_settings

FORMAT = "keystone-backup/1"
NAME_RE = re.compile(r"keystone-backup-\d{8}T\d{6}Z\.tar\.gz")
_MEMBER_TABLE = re.compile(r"tables/([a-z][a-z0-9_]{0,62})\.jsonl")
_MEMBER_FILE = re.compile(r"files/([0-9a-f]{64})")
MAX_MEMBER_BYTES = 2 * 1024**3  # one table or one attachment
MAX_MANIFEST_BYTES = 10 * 1024**2
SKIP_TABLES = {"alembic_version"}  # recreated by migrations on the target


class BackupError(RuntimeError):
    pass


@dataclass
class BackupResult:
    path: Path
    rows: int
    files: int
    size: int
    missing_files: list[str] = field(default_factory=list)


def backup_dir() -> Path:
    raw = os.environ.get("KEYSTONE_BACKUP_DIR", "").strip()
    return Path(raw) if raw else get_settings().data_dir / "backups"


def keep_count() -> int:
    raw = os.environ.get("KEYSTONE_BACKUP_KEEP", "14").strip()
    if not raw.isdigit() or not 1 <= int(raw) <= 3650:
        raise BackupError("KEYSTONE_BACKUP_KEEP must be a whole number from 1 to 3650.")
    return int(raw)


def _metadata():
    from importlib import import_module

    from keystone.core.db import Base

    import_module("keystone.models")  # registers every model

    return Base.metadata


def _head_revision() -> str:
    from alembic.script import ScriptDirectory

    from keystone.core.migrate import alembic_config

    head = ScriptDirectory.from_config(alembic_config("sqlite://")).get_current_head()
    if head is None:
        raise BackupError("No migrations found.")
    return head


# ---- value encoding (type-driven, so user JSON can never be mistaken for an encoded value) ------------------------

def _encode(value):
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, bytes | bytearray | memoryview):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, Decimal):
        return str(value)
    return value


def _decoder(column):
    t = column.type
    if isinstance(t, DateTime):
        return lambda v: None if v is None else datetime.fromisoformat(v)
    if isinstance(t, Date):
        return lambda v: None if v is None else date.fromisoformat(v)
    if isinstance(t, LargeBinary):
        return lambda v: None if v is None else base64.b64decode(v, validate=True)
    if isinstance(t, Numeric) and t.asdecimal:
        return lambda v: None if v is None else Decimal(v)
    if isinstance(t, JSON):
        return lambda v: v
    return lambda v: v


# ---- create ---------------------------------------------------------------------------------------------------------

@contextmanager
def _snapshot(engine: Engine) -> Iterator[Connection]:
    """A connection that sees one consistent state of the whole database for the duration of the backup."""
    if engine.dialect.name == "sqlite":
        src = engine.url.database
        if not src:
            raise BackupError("In-memory SQLite databases can't be backed up.")
        with tempfile.TemporaryDirectory(prefix="keystone-snap-") as tmp:
            copy = Path(tmp) / "snapshot.db"
            with sqlite3.connect(f"file:{src}?mode=ro", uri=True) as live, sqlite3.connect(copy) as dst:
                live.backup(dst)  # SQLite's online backup API: a consistent copy while the app keeps running
            eng = create_engine(f"sqlite:///{copy}")
            try:
                with eng.connect() as conn:
                    yield conn
            finally:
                eng.dispose()
    else:
        with engine.connect().execution_options(isolation_level="REPEATABLE READ") as conn, conn.begin():
            yield conn


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes, mtime: float) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mtime = int(mtime)
    info.mode = 0o600
    tar.addfile(info, io.BytesIO(data))


def _add_file(tar: tarfile.TarFile, name: str, path: Path, mtime: float) -> str:
    """Add a file from disk, hashing it as it is read. Returns the SHA-256 of what went into the archive."""
    digest = hashlib.sha256()
    data = path.read_bytes()
    digest.update(data)
    _add_bytes(tar, name, data, mtime)
    return digest.hexdigest()


def create_backup(engine: Engine, dest_dir: Path | None = None, now: datetime | None = None) -> BackupResult:
    """Write a backup of the database and stored files into dest_dir (default: backup_dir())."""
    from keystone.core.attachments import _blob_path

    now = now or datetime.now(timezone.utc)
    dest = dest_dir or backup_dir()
    dest.mkdir(mode=0o700, parents=True, exist_ok=True)  # a new directory is owner-only; each backup file is 0600
    final = dest / f"keystone-backup-{now:%Y%m%dT%H%M%SZ}.tar.gz"
    if final.exists():
        raise BackupError("A backup with this timestamp already exists.")
    part = dest / (final.name + ".part")
    meta = _metadata()
    manifest: dict = {"format": FORMAT, "revision": _head_revision(), "created": now.isoformat(), "dialect": engine.dialect.name,
                      "tables": {}, "files": {}, "missing_files": []}
    total_rows = 0
    mtime = now.timestamp()
    fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=int(mtime)) as gz, tarfile.open(fileobj=gz, mode="w|") as tar:
            with _snapshot(engine) as conn:
                current = conn.execute(text("SELECT version_num FROM alembic_version")).scalar() if inspect(conn).has_table("alembic_version") else None
                if current != manifest["revision"]:
                    raise BackupError("The database isn't at the latest schema revision; start Keystone once to migrate it.")
                shas: set[str] = set()
                for table in meta.sorted_tables:
                    if table.name in SKIP_TABLES:
                        continue
                    pk = list(table.primary_key.columns)
                    buf = io.BytesIO()
                    n = 0
                    for row in conn.execute(select(table).order_by(*pk)).mappings():
                        buf.write(json.dumps({k: _encode(v) for k, v in row.items()}, ensure_ascii=False, separators=(",", ":")).encode())
                        buf.write(b"\n")
                        n += 1
                        if table.name == "attachments" and row.get("sha256"):
                            shas.add(row["sha256"])
                    data = buf.getvalue()
                    _add_bytes(tar, f"tables/{table.name}.jsonl", data, mtime)
                    manifest["tables"][table.name] = {"rows": n, "sha256": hashlib.sha256(data).hexdigest()}
                    total_rows += n
            for sha in sorted(shas):
                if not re.fullmatch(r"[0-9a-f]{64}", sha):
                    manifest["missing_files"].append(sha[:64])
                    continue
                path = _blob_path(sha)
                if not path.is_file():
                    manifest["missing_files"].append(sha)
                    continue
                got = _add_file(tar, f"files/{sha}", path, mtime)
                if got != sha:  # the stored file no longer matches its hash: record it, don't hide it
                    manifest["missing_files"].append(sha)
                manifest["files"][sha] = got
            _add_bytes(tar, "manifest.json", json.dumps(manifest, indent=1, sort_keys=True).encode(), mtime)
        os.replace(part, final)
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    return BackupResult(final, total_rows, len(manifest["files"]), final.stat().st_size, manifest["missing_files"])


def prune(dest_dir: Path | None = None, keep: int | None = None) -> list[str]:
    """Delete the oldest backups beyond `keep`. Only files whose names Keystone itself generates are touched."""
    dest = dest_dir or backup_dir()
    keep = keep if keep is not None else keep_count()
    if not dest.is_dir():
        return []
    ours = sorted(p for p in dest.iterdir() if p.is_file() and not p.is_symlink() and NAME_RE.fullmatch(p.name))
    old = ours[:-keep] if len(ours) > keep else []
    for p in old:
        p.unlink()
    return [p.name for p in old]


# ---- read and restore -------------------------------------------------------------------------------------------------

@dataclass
class _Archive:
    manifest: dict
    tables: dict[str, bytes]
    files: set[str]  # attachment hashes present and verified (contents are streamed again at restore time)


_CHUNK = 1024 * 1024


def _stream_member(tar: tarfile.TarFile, member: tarfile.TarInfo, sink=None) -> str:
    """Read a member in chunks, optionally copying it to `sink`. Returns its SHA-256."""
    if member.size > MAX_MEMBER_BYTES:
        raise BackupError(f"{member.name} is larger than allowed.")
    f = tar.extractfile(member)
    if f is None:
        raise BackupError(f"{member.name} can't be read.")
    digest, seen = hashlib.sha256(), 0
    while chunk := f.read(_CHUNK):
        seen += len(chunk)
        if seen > member.size:
            raise BackupError(f"{member.name} has an unexpected size.")
        digest.update(chunk)
        if sink is not None:
            sink.write(chunk)
    if seen != member.size:
        raise BackupError(f"{member.name} has an unexpected size.")
    return digest.hexdigest()


def _read_member(tar: tarfile.TarFile, member: tarfile.TarInfo, cap: int) -> bytes:
    if member.size > cap:
        raise BackupError(f"{member.name} is larger than allowed.")
    f = tar.extractfile(member)
    if f is None:
        raise BackupError(f"{member.name} can't be read.")
    data = f.read(cap + 1)
    if len(data) > cap or len(data) != member.size:
        raise BackupError(f"{member.name} has an unexpected size.")
    return data


def read_backup(path: Path) -> _Archive:
    """Read and fully verify a backup. Raises BackupError on anything unexpected; writes nothing."""
    tables: dict[str, bytes] = {}
    files: set[str] = set()
    manifest: dict | None = None
    try:
        with tarfile.open(path, mode="r:gz") as tar:
            for member in tar:
                if not member.isreg():
                    raise BackupError("The backup contains an entry that isn't a regular file.")
                name = member.name
                if name == "manifest.json":
                    if manifest is not None:
                        raise BackupError("The backup has more than one manifest.")
                    manifest = json.loads(_read_member(tar, member, MAX_MANIFEST_BYTES))
                elif m := _MEMBER_TABLE.fullmatch(name):
                    if m.group(1) in tables:
                        raise BackupError("The backup repeats a table.")
                    tables[m.group(1)] = _read_member(tar, member, MAX_MEMBER_BYTES)
                elif m := _MEMBER_FILE.fullmatch(name):
                    if m.group(1) in files or _stream_member(tar, member) != m.group(1):
                        raise BackupError("A stored file is repeated or doesn't match its checksum: the backup is damaged.")
                    files.add(m.group(1))
                else:
                    raise BackupError("The backup contains an unexpected entry.")
    except (tarfile.TarError, OSError, EOFError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise BackupError("The file isn't a readable Keystone backup.") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
        raise BackupError("The file isn't a Keystone backup in a format this version understands.")
    listed = manifest.get("tables")
    if not isinstance(listed, dict) or set(listed) != set(tables):
        raise BackupError("The backup's tables don't match its manifest.")
    for name, info in listed.items():
        if hashlib.sha256(tables[name]).hexdigest() != info.get("sha256"):
            raise BackupError(f"Table {name} doesn't match its checksum: the backup is damaged.")
    if files != {s for s, got in (manifest.get("files") or {}).items() if s == got}:
        raise BackupError("The backup's files don't match its manifest.")
    return _Archive(manifest, tables, files)


def _cyclic_fks(table: Table) -> list[str]:
    """Foreign keys that can't be satisfied in one ordered pass (created after the tables with use_alter, or pointing at
    the same table): those columns are inserted empty and filled in once every row exists."""
    return [fk.parent.name for fk in table.foreign_keys if fk.use_alter or fk.column.table is table]


def restore_backup(path: Path, url: str, *, write_files: bool = True, actor_note: str = "command line") -> dict:
    """Restore a verified backup into the empty database at `url`, which is migrated to the latest schema first.
    Returns counts. Refuses a database that already holds any rows."""
    from keystone.core.audit import log_event, verify_chain
    from keystone.core.migrate import upgrade_to_head
    from sqlalchemy.orm import Session

    archive = read_backup(path)
    head = _head_revision()
    if archive.manifest.get("revision") != head:
        raise BackupError("This backup was taken by a different version of Keystone. Restore it with that version, then upgrade.")
    upgrade_to_head(url)
    meta = _metadata()
    engine = create_engine(url)
    try:
        known = {t.name: t for t in meta.sorted_tables}
        unknown = set(archive.tables) - set(known)
        if unknown:
            raise BackupError("The backup has tables this version doesn't know.")
        with engine.begin() as conn:
            for table in meta.sorted_tables:
                if table.name not in SKIP_TABLES and conn.execute(select(func.count()).select_from(table)).scalar():
                    raise BackupError("The target database isn't empty. Restore into a new, empty database.")
            total = 0
            deferred: list[tuple[Table, dict, dict]] = []
            for table in meta.sorted_tables:
                if table.name not in archive.tables:
                    continue
                decode = {c.name: _decoder(c) for c in table.columns}
                later = _cyclic_fks(table)
                pk = [c.name for c in table.primary_key.columns]
                batch: list[dict] = []
                for line in archive.tables[table.name].splitlines():
                    raw = json.loads(line)
                    if not isinstance(raw, dict) or set(raw) - set(decode):
                        raise BackupError(f"Table {table.name} has columns this version doesn't know.")
                    row = {k: decode[k](v) for k, v in raw.items()}
                    held = {k: row[k] for k in later if row.get(k) is not None}
                    if held:  # keep columns with onupdate defaults (updated_at) as they were in the backup
                        held.update({c.name: row.get(c.name) for c in table.columns if c.onupdate is not None})
                        deferred.append((table, {k: row[k] for k in pk}, held))
                        row.update({k: None for k in later})
                    batch.append(row)
                    if len(batch) >= 500:
                        conn.execute(insert(table), batch)
                        batch = []
                if batch:
                    conn.execute(insert(table), batch)
                total += archive.manifest["tables"][table.name]["rows"]
            for table, key, values in deferred:
                conn.execute(update(table).where(*[table.c[k] == v for k, v in key.items()]).values(**values))
            if engine.dialect.name == "postgresql":  # rows came with their ids: move each sequence past them
                for table in meta.sorted_tables:
                    pks = list(table.primary_key.columns)
                    if table.name in SKIP_TABLES or len(pks) != 1 or not isinstance(pks[0].type, Integer):
                        continue
                    seq = conn.execute(select(func.pg_get_serial_sequence(table.name, pks[0].name))).scalar()
                    if seq:
                        nxt = select(func.coalesce(func.max(pks[0]), 0) + 1).scalar_subquery()
                        conn.execute(select(func.setval(seq, nxt, False)))
        with Session(engine) as s:
            ok, bad = verify_chain(s)
            if not ok:
                raise BackupError(f"The restored audit log doesn't verify (first bad entry {bad}).")
            log_event(s, None, "restore", "Backup", None, f"Restored from backup taken {archive.manifest.get('created')} ({actor_note})")
            s.commit()
    finally:
        engine.dispose()
    written = 0
    if write_files:
        written = _restore_files(path, archive.files)
    return {"rows": total, "files": len(archive.files), "files_written": written, "created": archive.manifest.get("created")}


def _restore_files(path: Path, expected: set[str]) -> int:
    """Copy each verified attachment into the attachments store, under the name of its own hash (never a name from the
    archive), via a temporary file that is kept only if its contents hash to that name."""
    from keystone.core.attachments import _blob_path

    written = 0
    with tarfile.open(path, mode="r:gz") as tar:
        for member in tar:
            m = _MEMBER_FILE.fullmatch(member.name)
            if not m or not member.isreg() or m.group(1) not in expected:
                continue
            sha = m.group(1)
            dst = _blob_path(sha)
            if dst.exists():
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=dst.parent, prefix=".restore-")
            try:
                with os.fdopen(fd, "wb") as out:
                    got = _stream_member(tar, member, out)
                if got != sha:
                    raise BackupError("A stored file changed while it was being restored.")
                os.chmod(tmp, 0o600)
                os.replace(tmp, dst)
                written += 1
            finally:
                Path(tmp).unlink(missing_ok=True)
    return written


def trial_restore(path: Path) -> dict:
    """Restore the backup into a scratch SQLite database and check it: what makes a scheduled backup 'verified'."""
    with tempfile.TemporaryDirectory(prefix="keystone-restore-test-") as tmp:
        return restore_backup(path, f"sqlite:///{Path(tmp) / 'restore.db'}", write_files=False, actor_note="test restore")
