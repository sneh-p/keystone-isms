"""Operator commands. Run inside the Keystone environment (container or venv) with the same KEYSTONE_* settings:

    python -m keystone.ops backup                 write a backup now (and test-restore it)
    python -m keystone.ops verify FILE            check a backup's checksums and test-restore it into a scratch database
    python -m keystone.ops restore FILE           restore into the configured database, which must be new and empty

Restore is deliberately not available from the web app.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m keystone.ops", description="Keystone backups")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("backup", help="write a backup now and test-restore it")
    for name in ("verify", "restore"):
        p = sub.add_parser(name)
        p.add_argument("file", type=Path)
    args = parser.parse_args(argv)

    from keystone.core import db
    from keystone.ops import backup

    try:
        if args.cmd == "backup":
            from keystone.ops.service import run_backup

            db.migrate()
            run = run_backup(None)
            print(f"{run.status}: {run.filename or '-'} ({run.rows or 0} rows, {run.files or 0} files){' - ' + run.detail if run.detail else ''}")
            return 0 if run.status in ("ok", "warning") else 1
        if args.cmd == "verify":
            out = backup.trial_restore(args.file)
            print(f"ok: backup from {out['created']} restores cleanly ({out['rows']} rows, {out['files']} files)")
            return 0
        url = db.engine().url.render_as_string(hide_password=False)
        out = backup.restore_backup(args.file, url)
        print(f"restored backup from {out['created']}: {out['rows']} rows, {out['files_written']} of {out['files']} files written")
        return 0
    except backup.BackupError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
