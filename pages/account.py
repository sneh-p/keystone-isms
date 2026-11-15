import streamlit as st

from keystone.core import auth
from keystone.core.rbac import ROLE_LABELS, ROLE_PERMISSIONS, Role
from keystone.ui.common import fmt_date, guard, session

user = guard()
st.title("👤 My account")
st.write(f"**{user.display_name}** (`{user.username}`) · {ROLE_LABELS[Role(user.role)]}")
st.caption(f"Last sign-in: {fmt_date(user.last_login_at)}")
with st.expander("What my role allows"):
    st.write(", ".join(sorted(ROLE_PERMISSIONS[Role(user.role)])))

st.subheader("Change password")
with st.form("pw"):
    cur = st.text_input("Current password", type="password")
    new = st.text_input("New password", type="password")
    new2 = st.text_input("Confirm new password", type="password")
    if st.form_submit_button("Change password"):
        if new != new2:
            st.error("Passwords do not match.")
        else:
            try:
                with session() as s:
                    auth.change_password(s, s.get(auth.User, user.id), cur, new)
                st.success("Password changed.")
            except (auth.AuthError, auth.PasswordPolicyError) as e:
                st.error(str(e))
