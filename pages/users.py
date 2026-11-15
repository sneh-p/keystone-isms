import streamlit as st

from keystone.core import auth
from keystone.core.rbac import ROLE_LABELS, Role
from keystone.ui.common import fmt_date, guard, run_action, session, table

admin = guard("users.manage")
st.title("👥 Users")

with session() as s:
    users = auth.list_users(s)
    table(
        {
            "Username": u.username,
            "Name": u.display_name,
            "Role": ROLE_LABELS[Role(u.role)],
            "Active": u.active,
            "Must change password": u.must_change_password,
            "Last sign-in": fmt_date(u.last_login_at),
            "Locked until": fmt_date(u.locked_until),
        }
        for u in users
    )
    by_id = {u.id: f"{u.display_name} ({u.username})" for u in users}

roles = [r.value for r in Role]

st.subheader("Add user")
with st.form("add_user", clear_on_submit=True):
    c1, c2 = st.columns(2)
    username = c1.text_input("Username")
    name = c2.text_input("Display name")
    email = c1.text_input("Email")
    role = c2.selectbox("Role", roles, format_func=lambda r: ROLE_LABELS[Role(r)], index=roles.index("viewer"))
    pw = st.text_input("Temporary password", type="password", help="The user must change it at first sign-in.")
    if st.form_submit_button("Create user", type="primary"):
        run_action(lambda s, a: auth.create_user(s, a, username=username, display_name=name, password=pw, role=role, email=email or None), success=f"User {username} created.")
        st.rerun()

st.subheader("Edit user")
if by_id:
    uid = st.selectbox("User", list(by_id), format_func=by_id.get)
    with session() as s:
        target = s.get(auth.User, uid)
        cur_role, cur_active = target.role, target.active
    with st.form("edit_user"):
        new_role = st.selectbox("Role", roles, index=roles.index(cur_role), format_func=lambda r: ROLE_LABELS[Role(r)])
        active = st.checkbox("Active", value=cur_active)
        reset = st.text_input("Reset password (optional)", type="password")
        if st.form_submit_button("Save"):
            def _save(s, a):
                u = s.get(auth.User, uid)
                auth.update_user(s, a, u, role=new_role, active=active)
                if reset:
                    auth.admin_reset_password(s, a, u, reset)
            run_action(_save, success="User updated.")
            st.rerun()
