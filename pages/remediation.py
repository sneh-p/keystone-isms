import streamlit as st

from keystone.tprm.exposure import exports
from keystone.ui.common import guard, session, table

guard()
st.title("🧹 Remediation candidates")
st.caption("Read-only findings to act on in Entra ID. Keystone makes no changes to your tenants.")

with session() as s:
    data = exports.remediation_candidates(s)
    xlsx_bytes = exports.remediation_xlsx(s)

st.download_button("Download XLSX", xlsx_bytes, "remediation_candidates.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
labels = {
    "dormant_high_risk": ("Dormant apps at High or Critical exposure", "Remove the app or its permissions if no longer used."),
    "unverified_user_consented": ("Unverified publishers with user consent", "Review the grants; consider revoking and restricting user consent."),
    "expired_credentials": ("Expired credentials still present", "Delete expired secrets and certificates."),
    "sp_credentials_on_vendor_apps": ("Credentials added to vendor apps in your tenant", "Confirm who added them; unexpected credentials can be an attacker's persistence."),
    "users_can_consent": ("Tenants where users can consent to apps", "Restrict user consent and enable the admin consent workflow."),
}
for key, (title, advice) in labels.items():
    st.subheader(f"{title} ({len(data[key])})")
    st.caption(advice)
    table(data[key])
