import streamlit as st

from keystone.org.service import get_org
from keystone.ui.common import guard, session

user = guard()
with session() as s:
    o = get_org(s)
st.title(f"🗝️ {o.name if o else 'Keystone ISMS'}")
st.write(f"Welcome, {user.display_name}.")
if o is None:
    st.info("Start by describing your organisation and ISMS scope on the **Organisation & scope** page.")
