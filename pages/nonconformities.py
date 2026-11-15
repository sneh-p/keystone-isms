import streamlit as st

from keystone.frameworks.service import controls as all_controls
from keystone.improvement import service as imp
from keystone.improvement.models import NC_SEVERITIES, NC_SOURCES, Nonconformity
from keystone.incidents.service import list_incidents
from keystone.ui.common import person, can, fmt_date, guard, run_action, select_user, session, table, user_options

guard()
st.title("🔧 Nonconformities and corrective actions")
st.caption("ISO 27001 clause 10.2: react, find the root cause, act, and check the action worked.")

with session() as s:
    people = user_options(s)
    att = imp.nc_attention(s)
    ncs = imp.list_ncs(s, include_closed=st.toggle("Include closed", True))
    rows = [{"Ref": n.ref, "Nonconformity": n.title, "Source": n.source, "Severity": n.severity, "Status": n.status, "Owner": people.get(n.owner_id), "Due": fmt_date(n.due_date), "Actions": f"{sum(a.status == 'verified' for a in n.actions)}/{len(n.actions)} verified"} for n in ncs]
    opts = {n.id: f"{n.ref} {n.title}" for n in ncs}
    ctl_opts = {None: "—", **{c.id: f"{c.code} {c.title}" for c in all_controls(s)}}
    inc_opts = {None: "—", **{i.id: f"{i.ref} {i.title}" for i in list_incidents(s)}}

c = st.columns(4)
c[0].metric("Open", len(att["open"]))
c[1].metric("Overdue", len(att["overdue"]))
c[2].metric("Actions overdue", len(att["actions_overdue"]))
c[3].metric("Awaiting effectiveness check", len(att["awaiting_verification"]))
table(rows)

if can("nc.write") or can("audit.findings"):
    with st.expander("Raise a nonconformity"):
        with st.form("raise", clear_on_submit=True):
            title = st.text_input("Nonconformity")
            c1, c2 = st.columns(2)
            src = c1.selectbox("Source", NC_SOURCES, index=NC_SOURCES.index("self_identified"))
            sev = c2.selectbox("Severity", NC_SEVERITIES, index=1)
            desc = st.text_area("Description and evidence")
            c1, c2 = st.columns(2)
            ctl = c1.selectbox("Related control", list(ctl_opts), format_func=ctl_opts.get)
            incd = c2.selectbox("Related incident", list(inc_opts), format_func=inc_opts.get)
            due = st.date_input("Target closure date", value=None)
            if st.form_submit_button("Raise", type="primary"):
                fields = dict(title=title, source=src, severity=sev, description=desc or None, common_control_id=ctl, incident_id=incd)
                if due:
                    fields["due_date"] = due
                run_action(imp.raise_nc, success="Nonconformity raised.", **fields)
                st.rerun()

if not opts:
    st.stop()
st.subheader("Detail")
nid = st.selectbox("Nonconformity", list(opts), format_func=opts.get)
with session() as s:
    n = s.get(Nonconformity, nid)
    cur = {k: getattr(n, k) for k in ("status", "description", "containment", "root_cause", "owner_id", "due_date")}
    actions = [(a.id, a.description, a.status, people.get(a.owner_id), fmt_date(a.due_date), a.completion_notes, person(people, a.verified_by_id), a.effectiveness_notes) for a in n.actions]
st.write(f"Status **{cur['status']}**")
if cur["description"]:
    st.write(cur["description"])

if can("nc.write") and cur["status"] != "closed":
    with st.form("analyse"):
        cont = st.text_area("Immediate containment / correction", cur["containment"] or "")
        rc = st.text_area("Root cause", cur["root_cause"] or "")
        owner = select_user("Owner", people, cur["owner_id"], "nc_owner")
        if st.form_submit_button("Save"):
            run_action(imp.update_nc, nid, containment=cont or None, root_cause=rc or None, owner_id=owner, success="Saved.")
            st.rerun()

st.markdown("**Corrective actions**")
table({"Action": a[1], "Status": a[2], "Owner": a[3], "Due": a[4], "Done": a[5], "Verified by": a[6], "Effectiveness": a[7]} for a in actions)
if can("nc.write") and cur["status"] != "closed":
    with st.form("action", clear_on_submit=True):
        desc = st.text_input("New corrective action")
        c1, c2 = st.columns(2)
        with c1:
            aown = select_user("Owner", people, None, "ca_owner")
        due = c2.date_input("Due", value=None)
        if st.form_submit_button("Add action"):
            run_action(imp.add_action, nid, desc, aown, due, success="Action added.")
            st.rerun()
    if cur["status"] == "open" and st.button("Move to action planned"):
        run_action(imp.plan, nid, success="Action plan recorded.")
        st.rerun()
    open_actions = {a[0]: a[1] for a in actions if a[2] == "open"}
    if open_actions:
        with st.form("complete"):
            aid = st.selectbox("Complete action", list(open_actions), format_func=open_actions.get)
            notes = st.text_input("What was done")
            if st.form_submit_button("Mark done"):
                run_action(imp.complete_action, aid, notes, success="Action completed.")
                st.rerun()
if can("nc.verify"):
    done = {a[0]: a[1] for a in actions if a[2] == "done"}
    if done:
        with st.form("verify"):
            aid = st.selectbox("Check effectiveness of", list(done), format_func=done.get)
            eff = st.radio("Was it effective?", ["Yes", "No"], horizontal=True) == "Yes"
            notes = st.text_area("Evidence of effectiveness")
            if st.form_submit_button("Record check"):
                run_action(imp.verify_action, aid, eff, notes, success="Effectiveness check recorded.")
                st.rerun()
    if cur["status"] == "verification" and st.button("Close nonconformity", type="primary"):
        run_action(imp.close, nid, success="Nonconformity closed.")
        st.rerun()
