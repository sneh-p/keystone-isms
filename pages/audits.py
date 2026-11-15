import streamlit as st

from keystone.audits import service as aud
from keystone.audits.models import AUDIT_TYPES, FINDING_TYPES, Audit
from keystone.frameworks import service as fw
from keystone.tprm.service import list_vendors
from keystone.ui.common import can, fmt_date, guard, run_action, select_user, session, table, user_options

guard()
st.title("🔍 Audits")
st.caption("Internal audit programme (ISO 27001 9.2), plus external, certification and supplier audits.")
FT = {"major_nc": "🔴 Major NC", "minor_nc": "🟠 Minor NC", "observation": "🟡 Observation", "opportunity": "🔵 Opportunity", "conformity": "🟢 Conformity"}

with session() as s:
    people = user_options(s)
    audits = aud.list_audits(s)
    rows = [{"Ref": a.ref, "Audit": a.title, "Type": a.audit_type, "Lead auditor": people.get(a.lead_auditor_id), "Planned": f"{fmt_date(a.planned_start)} – {fmt_date(a.planned_end)}", "Status": a.status, "Controls": len(a.controls), "Findings": len(a.findings)} for a in audits]
    opts = {a.id: f"{a.ref} {a.title} ({a.status})" for a in audits}
    ctl_opts = {c.id: f"{c.code} {c.title}" for c in fw.controls(s)}
    fw_opts = {None: "—", **{f.id: f"{f.name} {f.version}" for f in fw.frameworks(s)}}
    v_opts = {None: "—", **{v.id: v.name for v in list_vendors(s)}}
    cov = aud.control_coverage(s)

c = st.columns(3)
c[0].metric("Audits", len(audits))
c[1].metric(f"Controls audited (last {aud.COVERAGE_MONTHS} months)", f"{cov['pct']}%")
c[2].metric("Controls not yet audited", len(cov["not_audited"]))
with st.expander("Controls not yet covered by an audit"):
    st.write(", ".join(cov["not_audited"]) or "All applicable controls covered.")
table(rows)

editable = can("audit.manage")
pick = st.selectbox("Audit", [None, *opts], format_func=lambda k: "(plan a new audit)" if k is None else opts[k])
with session() as s:
    a = s.get(Audit, pick) if pick else None
    cur = {f: getattr(a, f) for f in aud.AUDIT_FIELDS} | {"status": a.status, "controls": [c.id for c in a.controls], "conflicts": aud.independence_conflicts(a)} if a else {"status": "planned", "controls": [], "conflicts": []}
    findings = [(f.ref, FT[f.finding_type], f.title, f.evidence, f.nonconformity_id) for f in a.findings] if a else []

if cur["conflicts"]:
    st.warning("Objectivity: the lead auditor owns in-scope controls " + ", ".join(cur["conflicts"]) + ".")

if editable and cur["status"] != "closed":
    with st.form("audit"):
        title = st.text_input("Title", cur.get("title") or "")
        c1, c2, c3 = st.columns(3)
        atype = c1.selectbox("Type", AUDIT_TYPES, index=AUDIT_TYPES.index(cur.get("audit_type") or "internal"))
        start = c2.date_input("Planned start", value=cur.get("planned_start"))
        end = c3.date_input("Planned end", value=cur.get("planned_end"))
        c1, c2 = st.columns(2)
        with c1:
            lead = select_user("Lead auditor", people, cur.get("lead_auditor_id"), "lead")
        team = c2.text_input("Audit team", cur.get("audit_team") or "")
        c1, c2 = st.columns(2)
        fwid = c1.selectbox("Criteria framework", list(fw_opts), index=list(fw_opts).index(cur.get("framework_id")), format_func=fw_opts.get)
        vid = c2.selectbox("Supplier (for supplier audits)", list(v_opts), index=list(v_opts).index(cur.get("vendor_id")), format_func=v_opts.get)
        scope = st.text_area("Scope", cur.get("scope") or "")
        criteria = st.text_area("Criteria and method", cur.get("criteria") or "")
        ctls = st.multiselect("Controls in scope", list(ctl_opts), default=cur["controls"], format_func=ctl_opts.get)
        summary = st.text_area("Summary (for the report)", cur.get("summary") or "")
        conclusion = st.text_area("Conclusion", cur.get("conclusion") or "")
        if st.form_submit_button("Save audit", type="primary"):
            run_action(aud.save_audit, pick, control_ids=ctls, title=title, audit_type=atype, planned_start=start, planned_end=end, lead_auditor_id=lead, audit_team=team or None, framework_id=fwid, vendor_id=vid, scope=scope or None, criteria=criteria or None, summary=summary or None, conclusion=conclusion or None, success="Audit saved.")
            st.rerun()
    if pick and st.button(f"Move to {aud.NEXT[cur['status']].replace('_', ' ')}"):
        run_action(aud.advance, pick, success="Audit status updated.")
        st.rerun()

if pick:
    st.subheader("Findings")
    table({"Ref": f[0], "Type": f[1], "Finding": f[2], "Evidence": f[3], "Nonconformity": f"NC-{f[4]:04d}" if f[4] else ""} for f in findings)
    if can("audit.findings") and cur["status"] in ("in_progress", "reporting"):
        with st.form("finding", clear_on_submit=True):
            c1, c2 = st.columns([1, 3])
            ftype = c1.selectbox("Type", FINDING_TYPES, format_func=FT.get)
            ftitle = c2.text_input("Finding")
            desc = st.text_area("Description")
            ev = st.text_area("Evidence (what was sampled or seen)")
            fctl = st.selectbox("Control", [None, *ctl_opts], format_func=lambda k: "—" if k is None else ctl_opts[k])
            st.caption("Major and minor nonconformities automatically open a nonconformity record for corrective action.")
            if st.form_submit_button("Record finding"):
                run_action(aud.add_finding, pick, finding_type=ftype, title=ftitle, description=desc or None, evidence=ev or None, common_control_id=fctl, success="Finding recorded.")
                st.rerun()
