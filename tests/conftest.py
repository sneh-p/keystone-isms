import copy
import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def tenant_a():
    return load_fixture("collected_tenant_a.json")


@pytest.fixture
def tenant_a_later():
    return load_fixture("collected_tenant_a_later.json")


@pytest.fixture
def tenant_b():
    return load_fixture("collected_tenant_b_no_p1.json")


@pytest.fixture
def clone():
    return copy.deepcopy


# ---- database fixtures -------------------------------------------------------------

PASSWORD = "Correct-Horse-9-Battery"


@pytest.fixture(autouse=True)
def _fast_password_hashing(monkeypatch):
    """Production argon2 parameters are deliberately slow; tests use cheap ones."""
    from argon2 import PasswordHasher

    from keystone.core import auth

    fast = PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1)
    monkeypatch.setattr(auth, "_hasher", fast)
    monkeypatch.setattr(auth, "_DUMMY_HASH", fast.hash("dummy"))


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Fresh SQLite database + data dir per test."""
    monkeypatch.setenv("KEYSTONE_DATA_DIR", str(tmp_path / "data"))
    url = f"sqlite:///{tmp_path / 'data' / 'test.db'}"
    monkeypatch.setenv("KEYSTONE_DB_URL", url)
    from keystone.core import db as dbmod

    dbmod.configure(url)
    dbmod.create_all()
    yield dbmod
    dbmod.engine().dispose()


@pytest.fixture
def users(db):
    """One active user per role. Returns {role_value: User}."""
    from keystone.core.auth import create_user
    from keystone.core.rbac import Role

    out = {}
    with db.session_scope() as s:
        admin = create_user(s, None, username="admin", display_name="Ada Admin", password=PASSWORD)
        out["admin"] = admin
        for role in Role:
            if role is Role.ADMIN:
                continue
            out[role.value] = create_user(s, admin, username=role.value.replace("_", ""), display_name=role.value.replace("_", " ").title(), password=PASSWORD, role=role)
        out["admin2"] = create_user(s, admin, username="admin2", display_name="Second Admin", password=PASSWORD, role=Role.ADMIN)
    return out


@pytest.fixture
def session(db):
    """A session with no actor; tests pass actors explicitly to services."""
    with db.session_scope() as s:
        yield s


@pytest.fixture
def content(db, users):
    """Database with all framework packs, common controls and crosswalk loaded."""
    from keystone.frameworks.loader import seed_content

    with db.session_scope(users["admin"]) as s:
        return seed_content(s, users["admin"])


# ---- API fixtures ----------------------------------------------------------------------------

@pytest.fixture
def api(db, monkeypatch):
    monkeypatch.setenv("KEYSTONE_DISABLE_SCHEDULER", "1")
    from fastapi.testclient import TestClient

    from keystone.api.app import create_app

    return TestClient(create_app(migrate=False))


def api_login(client, username, password=PASSWORD):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    client.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return r.json()


@pytest.fixture
def ready_users(users, db):
    """users fixture with the forced password change cleared."""
    from keystone.core.auth import User

    with db.session_scope() as s:
        for u in s.query(User).all():
            u.must_change_password = False
    return users
