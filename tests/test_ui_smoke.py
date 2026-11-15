"""Every page renders without exceptions for every role (Streamlit AppTest)."""

import ast
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
APP = str(ROOT / "app.py")


def _pages():
    tree = ast.parse((ROOT / "app.py").read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) == "PAGES":
            return [(e.elts[0].value, e.elts[3].value) for e in node.value.elts]
    raise AssertionError("PAGES not found")


PAGES = [p for p in _pages() if (ROOT / p[0]).exists()]


def _app(uid=None):
    at = AppTest.from_file(APP, default_timeout=30)
    if uid is not None:
        at.session_state["uid"] = uid
    return at


def test_bootstrap_form_on_empty_db(db):
    at = _app().run()
    assert not at.exception
    assert "first-time setup" in at.title[0].value


def test_login_form_when_signed_out(users):
    at = _app().run()
    assert not at.exception
    assert at.button[0].label == "Sign in" or any(b.label == "Sign in" for b in at.button)


def test_login_flow(users):
    at = _app().run()
    at.text_input[0].input("admin")
    at.text_input[1].input("Correct-Horse-9-Battery")
    at.button[0].click().run()
    assert not at.exception
    assert at.session_state["uid"] == users["admin"].id


def test_wrong_password_shows_generic_error(users):
    at = _app().run()
    at.text_input[0].input("admin")
    at.text_input[1].input("nope")
    at.button[0].click().run()
    assert any("Invalid username or password" in e.value for e in at.error)


def test_must_change_password_gate(users):
    at = _app(users["viewer"].id).run()  # created by admin -> must change
    assert not at.exception
    assert at.title[0].value == "Change your password"


@pytest.mark.parametrize("path,perm", PAGES, ids=[p[0] for p in PAGES])
@pytest.mark.parametrize("role", ["admin", "viewer", "auditor"])
def test_page_renders(users, db, path, perm, role):
    from keystone.core.auth import User
    from keystone.core.rbac import has_permission

    with db.session_scope() as s:
        u = s.get(User, users[role].id)
        u.must_change_password = False
    at = _app(users[role].id)
    at.run()
    if not has_permission(users[role], perm):
        with pytest.raises(ValueError, match="Could not find a navigation page"):
            at.switch_page(path)
        return
    at.switch_page(path).run()
    assert not at.exception, [e.value for e in at.exception]


@pytest.fixture
def demo_db(db):
    from keystone import demo
    from keystone.core import auth

    with db.session_scope() as s:
        admin = auth.create_user(s, None, username="admin", display_name="Demo Admin", password=demo.DEMO_PASSWORD)
    with db.session_scope(admin) as s:
        handles = demo.seed(s, s.get(auth.User, admin.id))
        return {k: v.id for k, v in handles["people"].items()}


@pytest.mark.parametrize("path,perm", PAGES, ids=[p[0] for p in PAGES])
@pytest.mark.parametrize("who", ["admin", "omar.audit"])
def test_page_renders_with_demo_data(demo_db, path, perm, who):
    from keystone.core.rbac import has_permission
    from keystone.core.auth import User
    from keystone.core import db as dbmod

    with dbmod.session_scope() as s:
        allowed = has_permission(s.get(User, demo_db[who]), perm)
    at = _app(demo_db[who])
    at.run()
    if not allowed:
        return
    at.switch_page(path).run()
    assert not at.exception, [e.value for e in at.exception]
