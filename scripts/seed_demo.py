"""Create a demo Keystone database for a fictional organisation.

Usage:  KEYSTONE_DATA_DIR=./demo-data python scripts/seed_demo.py
Signs in as admin / Demo-Password-2026! (and the demo users listed in keystone/demo.py).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from keystone import demo  # noqa: E402
from keystone.core import auth, db  # noqa: E402


def main() -> None:
    db.configure()
    db.migrate()
    with db.session_scope() as s:
        if not auth.needs_bootstrap(s):
            sys.exit("Database already has users; refusing to seed demo data into it.")
        admin = auth.create_user(s, None, username="admin", display_name="Demo Admin", password=demo.DEMO_PASSWORD)
    with db.session_scope(admin) as s:
        demo.seed(s, s.get(auth.User, admin.id))
    print(f"Demo data created in {db.engine().url}. Sign in as admin / {demo.DEMO_PASSWORD}")


if __name__ == "__main__":
    main()
