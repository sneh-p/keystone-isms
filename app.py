"""Keystone ISMS - Streamlit entry point.

Run:  streamlit run app.py
"""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from keystone.core import auth, db
from keystone.core.rbac import ROLE_LABELS, Role, has_permission
from keystone.ui.common import current_user, init_db_once, logout, show_flash, touch_session

st.set_page_config(page_title="Keystone ISMS", page_icon="🗝️", layout="wide")
init_db_once()

# (path, title, icon, permission, section)
PAGES = [
    ("pages/home.py", "Overview", "🏠", "read", "Keystone"),
    ("pages/organisation.py", "Organisation & scope", "🏢", "read", "Governance"),
    ("pages/frameworks.py", "Frameworks", "📚", "read", "Governance"),
    ("pages/policies.py", "Policies", "📜", "read", "Governance"),
    ("pages/assets.py", "Assets", "🗄️", "read", "Risk"),
    ("pages/risks.py", "Risk register", "⚠️", "read", "Risk"),
    ("pages/controls.py", "Controls", "🛡️", "read", "Controls"),
    ("pages/soa.py", "Statement of Applicability", "📋", "read", "Controls"),
    ("pages/evidence.py", "Evidence", "📎", "read", "Controls"),
    ("pages/vendors.py", "Vendors", "🤝", "read", "Third parties"),
    ("pages/questionnaires.py", "Questionnaires", "📝", "read", "Third parties"),
    ("pages/vendor_assessments.py", "Vendor assessments", "⚖️", "read", "Third parties"),
    ("pages/exposure_import.py", "Exposure import", "📥", "read", "Entra exposure"),
    ("pages/exposure_map.py", "Exposure map", "🗺️", "read", "Entra exposure"),
    ("pages/cross_tenant.py", "Cross-tenant view", "🔀", "read", "Entra exposure"),
    ("pages/vendor_matching.py", "Vendor matching", "🔗", "read", "Entra exposure"),
    ("pages/remediation.py", "Remediation candidates", "🧹", "read", "Entra exposure"),
    ("pages/incidents.py", "Incidents", "🚨", "read", "Operations"),
    ("pages/nonconformities.py", "Nonconformities & CAPA", "🔧", "read", "Improvement"),
    ("pages/audits.py", "Internal audits", "🔍", "read", "Improvement"),
    ("pages/management_review.py", "Management review", "🧭", "read", "Improvement"),
    ("pages/reports.py", "Reports & exports", "📊", "read", "Improvement"),
    ("pages/account.py", "My account", "👤", "read", "Admin"),
    ("pages/users.py", "Users", "👥", "users.manage", "Admin"),
    ("pages/audit_log.py", "Audit log", "🧾", "audit_log.view", "Admin"),
]


def bootstrap_form() -> None:
    st.title("🗝️ Keystone ISMS: first-time setup")
    st.write("Create the first administrator account. Later accounts are created by an administrator.")
    with st.form("bootstrap"):
        username = st.text_input("Username")
        name = st.text_input("Display name")
        email = st.text_input("Email (optional)")
        pw = st.text_input("Password", type="password", help="12+ characters, three of: lowercase, uppercase, digit, symbol.")
        pw2 = st.text_input("Confirm password", type="password")
        if st.form_submit_button("Create administrator", type="primary"):
            if pw != pw2:
                st.error("Passwords do not match.")
                return
            try:
                with db.session_scope() as s:
                    if not auth.needs_bootstrap(s):
                        st.error("Setup has already been completed.")
                        return
                    auth.create_user(s, None, username=username, display_name=name, password=pw, email=email or None)
                st.success("Administrator created. Sign in below.")
                st.rerun()
            except (ValueError, auth.PasswordPolicyError) as e:
                st.error(str(e))


def login_form() -> None:
    st.title("🗝️ Keystone ISMS")
    show_flash()
    with st.form("login"):
        username = st.text_input("Username")
        pw = st.text_input("Password", type="password")
        if st.form_submit_button("Sign in", type="primary"):
            try:
                with db.session_scope() as s:
                    user = auth.authenticate(s, username, pw)
                    st.session_state["uid"] = user.id
                touch_session()
                st.rerun()
            except auth.AuthError as e:
                st.error(str(e))


def change_password_form(user) -> None:
    st.title("Change your password")
    st.info("You must set a new password before continuing.")
    with st.form("pwchange"):
        cur = st.text_input("Current password", type="password")
        new = st.text_input("New password", type="password")
        new2 = st.text_input("Confirm new password", type="password")
        if st.form_submit_button("Change password", type="primary"):
            if new != new2:
                st.error("Passwords do not match.")
                return
            try:
                with db.session_scope(user) as s:
                    auth.change_password(s, s.get(auth.User, user.id), cur, new)
                st.session_state["flash"] = ("success", "Password changed.")
                st.rerun()
            except (auth.AuthError, auth.PasswordPolicyError) as e:
                st.error(str(e))


def main() -> None:
    with db.session_scope() as s:
        bootstrap = auth.needs_bootstrap(s)
    if bootstrap:
        bootstrap_form()
        return
    user = current_user()
    if user is None or not touch_session():
        login_form()
        return
    if user.must_change_password:
        change_password_form(user)
        return

    sections: dict[str, list] = {}
    for path, title, icon, perm, section in PAGES:
        if has_permission(user, perm) and (Path(__file__).parent / path).exists():
            sections.setdefault(section, []).append(st.Page(path, title=title, icon=icon, default=path == "pages/home.py"))
    nav = st.navigation(sections)
    with st.sidebar:
        st.caption(f"Signed in as **{user.display_name}** · {ROLE_LABELS[Role(user.role)]}")
        if st.button("Sign out", use_container_width=True):
            logout()
            st.rerun()
    show_flash()
    nav.run()


main()
