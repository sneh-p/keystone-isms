import streamlit as st

from keystone.tprm.exposure import importer
from keystone.tprm.exposure.schema import CollectedFileInvalid
from keystone.ui.common import can, fmt_date, guard, run_action, session, table, tri

guard()
st.title("📥 Import Entra exposure data")
st.caption("Upload collected.json produced by collector/Invoke-VendorExposureCollector.ps1. Keystone never connects to Microsoft Graph itself.")
st.info("The collector output is a map of your attack surface. Delete the output folder from the technician's workstation after import, per your retention policy.")

if not can("exposure.import"):
    st.warning("Your role cannot import exposure data.")
    st.stop()

up = st.file_uploader("collected.json", type=["json"])
if up is None:
    with session() as s:
        snaps = [(t.name, t.entra_tenant_id, [fmt_date(x.collected_at_utc) for x in importer.latest_snapshots(s, t.id, 50)]) for t in importer.tenants(s)]
    st.subheader("Imported snapshots")
    table({"Tenant": n, "Entra tenant ID": tid, "Snapshots": len(x), "Latest": x[0] if x else "—"} for n, tid, x in snaps)
    st.stop()

try:
    doc = importer.load_document(up.getvalue())
except CollectedFileInvalid as e:
    st.error("This file does not match the collected.json schema and cannot be imported.")
    st.code("\n".join(e.errors))
    st.stop()

with session() as s:
    p = importer.preview(s, doc)

st.subheader(f"{p.tenant_name} · collected {fmt_date(p.collected_at)} UTC")
st.write(f"Entra tenant `{p.tenant_id}` · default domain {p.default_domain or '—'} · collected by {p.operator} · Entra ID P1/P2: {tri(p.entra_p1_available)}")
if p.write_scopes_present:
    st.warning("The collector's token carried write-capable scopes previously consented to Microsoft Graph Command Line Tools in this tenant. The collector only read data, but that standing consent is itself a finding worth reviewing.")
for sev, key, msg in p.problems:
    (st.error if sev == "error" else st.warning)(f"**{key}**: {msg}")
table({"Dataset": k, "Records": "could not check (null)" if v is None else v} for k, v in p.counts.items())

if p.duplicate:
    st.error("This snapshot (same tenant and collection time) has already been imported.")
    st.stop()

name = None
if p.existing_tenant:
    st.success(f"Will be added to existing tenant **{p.existing_tenant}**.")
else:
    st.warning("This Entra tenant is not registered in Keystone yet.")
    name = st.text_input("Register it as", p.tenant_name)

if st.button("Import snapshot", type="primary"):
    res = run_action(importer.import_document, doc, name)
    if res:
        st.success(f"Imported {res.apps} apps. Third-party/unknown by exposure: {res.by_level}. Owner classes: {res.by_class}.")
