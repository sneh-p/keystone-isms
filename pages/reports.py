import streamlit as st

from keystone.org.service import get_org
from keystone.reporting import registers
from keystone.ui.common import can, current_user, guard, session

guard()
st.title("📊 Reports and exports")
st.caption("Exports are written to the audit log. Spreadsheet cells are protected against formula injection. Treat exported files as confidential.")

names = list(registers.REGISTERS) + (["Audit log"] if can("audit_log.view") else [])
with session() as s:
    o = get_org(s)
org = o.name if o else ""

for name in names:
    c1, c2 = st.columns([3, 1])
    c1.markdown(f"**{name}**")
    if c2.button("Prepare", key=f"prep_{name}"):
        with session() as s:
            st.session_state[f"export_{name}"] = registers.export(s, current_user(), name, org)
    data = st.session_state.get(f"export_{name}")
    if data:
        c2.download_button("Download", data, f"{name.replace(' ', '_')}.xlsx", key=f"dl_{name}", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
st.divider()
st.markdown("The **Statement of Applicability** (XLSX and Word) is on the SoA page, and **remediation candidates** for Entra apps are on the Remediation page.")
