import streamlit as st

from keystone.controls import service as ctl
from keystone.frameworks import service as fwsvc
from keystone.org.service import get_org
from keystone.reporting import exports
from keystone.ui.common import can, fmt_date, guard, run_action, session, table, user_options

guard()
st.title("📋 Statement of Applicability")
st.caption("Applicability and justification for every requirement, derived from your controls and risks. Record a decision to override the default. ISO 27001 6.1.3 d).")

with session() as s:
    fws = [(f.id, f.code, f"{f.name} {f.version}") for f in fwsvc.frameworks(s)]
if not fws:
    st.info("Load framework content on the Frameworks page first.")
    st.stop()
choice = st.selectbox("Framework", fws, format_func=lambda f: f[2])
fid, code, label = choice

with session() as s:
    people = user_options(s)
    rows = ctl.soa_rows(s, fid)
    approvals = [(a.version, people.get(a.approved_by_id), fmt_date(a.approved_at), a.note) for a in ctl.soa_approvals(s, fid)]
    changed = ctl.soa_changes_since_approval(s, fid)
    org = get_org(s)
    org_name = org.name if org else "Organisation"
    data = [
        {
            "Ref": r.requirement.ref, "Requirement": r.requirement.title, "Applicable": "Yes" if r.applicable else "No",
            "Justification": r.justification, "Basis": {"decision": "Recorded decision", "controls_na": "Controls N/A", "risks": "Risk treatment", "baseline": "Baseline"}[r.justification_source],
            "Implementation": r.implementation.replace("_", " "), "Controls": ", ".join(r.controls), "Risks": ", ".join(r.risks),
        }
        for r in rows
    ]
    req_opts = {r.requirement.id: f"{r.requirement.ref} {r.requirement.title[:80]}" for r in rows}
    current = {r.requirement.id: (r.applicable, r.justification, r.justification_source) for r in rows}
    has_licensed = any(r.requirement.licensed_text for r in rows)
    version_note = f"approved v{approvals[0][0]}" if approvals and not changed else ("draft (changed since v%d)" % approvals[0][0] if approvals else "draft, not yet approved")
    xlsx_bytes = exports.soa_xlsx(org_name, label, rows, version_note)
    docx_bytes = exports.soa_docx(org_name, label, rows, version_note)
    lic_bytes = exports.soa_xlsx(org_name, label, rows, version_note, include_licensed_text=True) if has_licensed else None

c = st.columns(4)
c[0].metric("Requirements", len(rows))
c[1].metric("Applicable", sum(r.applicable for r in rows))
c[2].metric("Implemented (applicable)", sum(1 for r in rows if r.applicable and r.implementation == "implemented"))
c[3].metric("Version", version_note)
if changed:
    st.warning(f"{len(changed)} requirement(s) changed since the last approval: {', '.join(changed[:20])}")

table(data)
d1, d2, d3 = st.columns(3)
d1.download_button("Download XLSX", xlsx_bytes, f"SoA_{code}.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
d2.download_button("Download Word", docx_bytes, f"SoA_{code}.docx", mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
if lic_bytes:
    d3.download_button("XLSX with licensed text (internal use)", lic_bytes, f"SoA_{code}_licensed.xlsx")

if can("soa.write"):
    st.subheader("Record an applicability decision")
    rid = st.selectbox("Requirement", list(req_opts), format_func=req_opts.get)
    app, just, src = current[rid]
    with st.form("soa"):
        applicable = st.radio("Applicable?", ["Yes", "No"], index=0 if app else 1, horizontal=True)
        justification = st.text_area("Justification", just if src == "decision" else "")
        a, b = st.columns(2)
        if a.form_submit_button("Save decision", type="primary"):
            run_action(ctl.set_soa_entry, rid, applicable == "Yes", justification, success="Decision saved.")
            st.rerun()
        if b.form_submit_button("Remove decision (use default)"):
            run_action(ctl.clear_soa_entry, rid, success="Decision removed.")
            st.rerun()
    st.subheader("Approve this version")
    with st.form("approve"):
        note = st.text_input("Approval note")
        if st.form_submit_button("Approve SoA"):
            run_action(ctl.approve_soa, fid, note or None, success="SoA approved.")
            st.rerun()

st.subheader("Approval history")
table({"Version": v, "Approved by": who, "On": when, "Note": n} for v, who, when, n in approvals)
