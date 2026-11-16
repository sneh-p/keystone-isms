"""Backups (round trip, tamper resistance, retention), job health, alerts and the system health API."""

from __future__ import annotations

import gzip
import io
import json
import tarfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select, text

from keystone.core.migrate import upgrade_to_head
from tests.conftest import PASSWORD, _test_db_url, api_login


def _rows(engine) -> dict[str, list[tuple]]:
    from keystone.ops.backup import SKIP_TABLES, _metadata

    out = {}
    with engine.connect() as conn:
        for t in _metadata().sorted_tables:
            if t.name not in SKIP_TABLES:
                out[t.name] = [tuple(r) for r in conn.execute(select(t).order_by(*t.primary_key.columns))]
    return out


@pytest.fixture
def populated(tmp_path, monkeypatch):
    """A migrated database (SQLite, or PostgreSQL under scripts/test-postgres.sh) holding the demo organisation and one
    stored file."""
    from keystone import demo
    from keystone.core import auth
    from keystone.core import db as dbmod
    from keystone.core.attachments import save_attachment

    data = tmp_path / "data"
    monkeypatch.setenv("KEYSTONE_DATA_DIR", str(data))
    url = _test_db_url(tmp_path)
    if url.startswith("sqlite"):
        url = f"sqlite:///{tmp_path / 'source.db'}"
    upgrade_to_head(url)
    dbmod.configure(url)
    with dbmod.session_scope() as s:
        admin = auth.create_user(s, None, username="admin", display_name="Admin", password=demo.DEMO_PASSWORD)
    with dbmod.session_scope() as s:
        admin = s.get(auth.User, admin.id)
        demo.seed(s, admin)
        save_attachment(s, admin, "evidence.pdf", b"%PDF-1.7 backup test", "Evidence", 1)
    yield dbmod, url
    dbmod.engine().dispose()


def _target(tmp_path) -> str:
    return f"sqlite:///{tmp_path / 'target.db'}"


def test_round_trip_restores_every_row_and_file(populated, tmp_path, monkeypatch):
    from keystone.core.attachments import _blob_path
    from keystone.core.audit import AuditLog, verify_chain
    from keystone.ops import backup
    from sqlalchemy.orm import Session

    dbmod, url = populated
    before = _rows(dbmod.engine())
    result = backup.create_backup(dbmod.engine(), tmp_path / "backups")
    sha_col = [c.name for c in backup._metadata().tables["attachments"].columns].index("sha256")
    shas = {r[sha_col] for r in before["attachments"]}
    assert result.rows == sum(len(v) for v in before.values()) and result.files == len(shas) >= 2 and result.missing_files == []
    assert backup.NAME_RE.fullmatch(result.path.name)
    assert oct(result.path.stat().st_mode & 0o777) == "0o600"

    monkeypatch.setenv("KEYSTONE_DATA_DIR", str(tmp_path / "restored-data"))  # a new server
    out = backup.restore_backup(result.path, _target(tmp_path))
    assert out["files_written"] == len(shas)
    import hashlib

    assert _blob_path(hashlib.sha256(b"%PDF-1.7 backup test").hexdigest()).read_bytes() == b"%PDF-1.7 backup test"

    target = create_engine(_target(tmp_path))
    after = _rows(target)
    restored_log = after.pop("audit_log")
    before_log = before.pop("audit_log")
    assert after == before
    assert restored_log[:-1] == before_log  # the original chain, plus one entry recording the restore
    with Session(target) as s:
        assert verify_chain(s) == (True, None)
        assert s.scalars(select(AuditLog.action).order_by(AuditLog.id.desc())).first() == "restore"
    target.dispose()


def test_backup_from_one_database_restores_into_another(populated, tmp_path):
    """Under scripts/test-postgres.sh this restores a PostgreSQL backup into SQLite and back into PostgreSQL."""
    from keystone.ops import backup

    dbmod, url = populated
    before = _rows(dbmod.engine())
    path = backup.create_backup(dbmod.engine(), tmp_path / "b").path
    dbmod.engine().dispose()
    if url.startswith("postgresql"):
        with create_engine(url).begin() as conn:
            conn.execute(text("DROP SCHEMA public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
        backup.restore_backup(path, url, write_files=False)
        eng = create_engine(url)
        assert {k: v for k, v in _rows(eng).items() if k != "audit_log"} == {k: v for k, v in before.items() if k != "audit_log"}
        with eng.begin() as conn:  # sequences were moved past the restored ids, so new rows don't collide
            conn.execute(text("INSERT INTO audit_log (ts, actor_name, action, entity_type, summary, prev_hash, hash) VALUES ('2030-01-01', 'x', 'create', 'T', '', 'a', 'unique-new-row')"))
        eng.dispose()
    else:
        out = backup.trial_restore(path)
        assert out["rows"] == sum(len(v) for v in before.values())


def test_restore_refuses_a_database_with_data(populated, tmp_path):
    from keystone.ops import backup

    dbmod, url = populated
    path = backup.create_backup(dbmod.engine(), tmp_path / "b").path
    with pytest.raises(backup.BackupError, match="isn't empty"):
        backup.restore_backup(path, url)


def _rewrite(src: Path, dst: Path, change) -> None:
    """Copy a backup member by member, letting `change(name, data)` return replacement members."""
    with tarfile.open(src, "r:gz") as tin, gzip.open(dst, "wb") as gz, tarfile.open(fileobj=gz, mode="w|") as tout:
        members = [(m.name, tin.extractfile(m).read()) for m in tin]
        for name, data in change(members):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tout.addfile(info, io.BytesIO(data))


def test_damaged_or_crafted_backups_are_refused(populated, tmp_path):
    from keystone.ops import backup

    dbmod, _url = populated
    good = backup.create_backup(dbmod.engine(), tmp_path / "b").path

    def edited_table(members):
        return [(n, d.replace(b"Alpine Ski House", b"Evil Ski House") if n == "tables/organisation.jsonl" else d) for n, d in members]

    def traversal(members):
        return [*members, ("../../etc/cron.d/x", b"* * * * * root id")]

    def wrong_revision(members):
        out = []
        for n, d in members:
            if n == "manifest.json":
                m = json.loads(d)
                m["revision"] = "0001"
                d = json.dumps(m).encode()
            out.append((n, d))
        return out

    def swapped_file(members):
        return [(n, b"not the original" if n.startswith("files/") else d) for n, d in members]

    for change, message in ((edited_table, "checksum"), (traversal, "unexpected entry"), (wrong_revision, "different version"), (swapped_file, "checksum")):
        bad = tmp_path / f"bad-{change.__name__}.tar.gz"
        _rewrite(good, bad, change)
        with pytest.raises(backup.BackupError, match=message):
            backup.restore_backup(bad, _target(tmp_path))
    assert not Path(_target(tmp_path).removeprefix("sqlite:///")).exists() or not _rows(create_engine(_target(tmp_path)))["users"]

    link = tmp_path / "link.tar.gz"
    with gzip.open(link, "wb") as gz, tarfile.open(fileobj=gz, mode="w|") as tar:
        info = tarfile.TarInfo("manifest.json")
        info.type, info.linkname = tarfile.SYMTYPE, "/etc/passwd"
        tar.addfile(info)
    with pytest.raises(backup.BackupError, match="regular file"):
        backup.read_backup(link)
    (tmp_path / "junk.tar.gz").write_bytes(b"not a tar file")
    with pytest.raises(backup.BackupError, match="readable"):
        backup.read_backup(tmp_path / "junk.tar.gz")


def test_prune_keeps_the_newest_and_ignores_other_files(tmp_path):
    from keystone.ops import backup

    d = tmp_path / "b"
    d.mkdir()
    names = [f"keystone-backup-2026110{i}T010000Z.tar.gz" for i in range(1, 6)]
    for n in [*names, "notes.txt", "keystone-backup-latest.tar.gz"]:
        (d / n).write_bytes(b"x")
    assert backup.prune(d, keep=2) == names[:3]
    assert sorted(p.name for p in d.iterdir()) == sorted([*names[3:], "notes.txt", "keystone-backup-latest.tar.gz"])


def test_scheduled_backup_is_verified_and_recorded(populated, tmp_path, monkeypatch):
    from keystone.core.audit import AuditLog
    from keystone.ops.service import run_backup

    dbmod, _url = populated
    monkeypatch.setenv("KEYSTONE_BACKUP_DIR", str(tmp_path / "nightly"))
    monkeypatch.setenv("KEYSTONE_BACKUP_KEEP", "1")
    first = run_backup(None)
    assert first.status == "ok" and first.verified and first.rows > 100 and first.files >= 2
    import time

    time.sleep(1.1)  # backups are named by the second
    second = run_backup(None)
    assert second.status == "ok" and "removed 1 old backup" in (second.detail or "")
    assert [p.name for p in (tmp_path / "nightly").iterdir()] == [second.filename]
    with dbmod.session_scope() as s:
        assert s.scalars(select(AuditLog.summary).where(AuditLog.action == "backup")).all() == ["Backup ok and verified"] * 2


def test_failed_backup_is_recorded_not_raised(populated, tmp_path, monkeypatch):
    from keystone.ops.service import run_backup

    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    monkeypatch.setenv("KEYSTONE_BACKUP_DIR", str(blocker / "sub"))
    run = run_backup(None)
    assert run.status == "failed" and not run.verified and "couldn't write" in run.detail


def test_job_failures_and_stale_backups_alert_admins_once_a_day(users, db, monkeypatch):
    from keystone.notifications.models import Notification
    from keystone.ops import health
    from keystone.ops.models import BackupRun

    now = datetime(2026, 11, 16, 9, 0)
    with db.session_scope() as s:
        for _ in range(2):
            health.record_start(s, "integration-checks", now)
            health.record_end(s, "integration-checks", TimeoutError("secret-host.internal:443 timed out"), now)
        s.add(BackupRun(started_at=now - timedelta(days=3), finished_at=now - timedelta(days=3), status="ok", verified=True))
    with db.session_scope() as s:
        found = {p["key"]: p["title"] for p in health.problems(s, now)}
        assert set(found) == {"job:integration-checks", "backup:stale"}
        assert "TimeoutError" in found["job:integration-checks"] and "secret-host" not in found["job:integration-checks"]
        from keystone.core.auth import User

        admins = s.scalars(select(User.id).where(User.role == "admin")).all()
        assert health.alert(s, now) == 2 * len(admins)  # every admin, both problems
        assert health.alert(s, now) == 0  # not repeated the same day
    with db.session_scope() as s:
        notes = s.scalars(select(Notification).where(Notification.kind == "system")).all()
        assert {n.user_id for n in notes} == set(admins) and users["isms_manager"].id not in set(admins)
        health.record_end(s, "integration-checks", None, now)
        s.add(BackupRun(started_at=now, finished_at=now, status="ok", verified=True))
    with db.session_scope() as s:
        assert health.problems(s, now) == []


def test_refresh_keeps_system_notifications(users, db):
    from keystone.notifications import service as ntf
    from keystone.notifications.models import Notification

    with db.session_scope() as s:
        s.add(Notification(user_id=users["admin"].id, key="system:backup:stale:20261116", kind="system", title="x", page="/settings/system", created_at=datetime.now()))
    with db.session_scope() as s:
        ntf.refresh(s, s.get(type(users["admin"]), users["admin"].id))
    with db.session_scope() as s:
        assert s.scalars(select(Notification.resolved_at).where(Notification.kind == "system")).one() is None


def test_system_health_api(api, ready_users, db):
    from alembic import command

    from keystone.core.migrate import alembic_config
    from keystone.ops.models import BackupRun

    command.stamp(alembic_config(str(db.engine().url.render_as_string(hide_password=False))), "head")
    assert api.get("/api/health").json()["status"] == "ok"
    assert api.get("/api/system/health").status_code == 401
    api_login(api, ready_users["isms_manager"].username)
    assert api.get("/api/system/health").status_code == 403
    assert api.post("/api/system/backups").status_code == 403
    api.post("/api/auth/logout")
    api_login(api, "admin", PASSWORD)
    body = api.get("/api/system/health").json()
    assert {j["name"] for j in body["jobs"]} >= {"backup", "system-alerts", "notifications"}
    assert body["virus_scanner"] in ("ok", "unavailable") and "secret" not in json.dumps(body).lower()
    r = api.post("/api/system/backups")
    assert r.status_code == 202
    with db.session_scope() as s:  # TestClient runs background tasks before returning
        run = s.scalars(select(BackupRun)).one()
        assert run.status == "ok" and run.verified
    assert api.get("/api/system/health").json()["backups"][0]["filename"] == run.filename
