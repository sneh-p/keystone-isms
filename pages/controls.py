import streamlit as st

from keystone.controls import service as ctl
from keystone.frameworks import service as fwsvc
from keystone.frameworks.models import CONTROL_STATUSES, STATUS_LABELS, CommonControl
from keystone.ui.common import can, fmt_date, guard, run_action, select_user, session, table, user_options

guard()
st.title("🛡️ Controls")
st.caption("Keystone's common controls. Implementing a control once counts towards every framework it maps to.")

with session() as s:
    people = user_options(s)
    controls = fwsvc.controls(s)
    if not controls:
        st.info("Load framework content on the Frameworks page first.")
        st.stop()
    counts = ctl.status_counts(s)
    att = ctl.control_attention(s)
    rows = [
        {
            "Code": c.code, "Domain": c.domain, "Control": c.title, "Status": STATUS_LABELS[c.status],
            "Owner": people.get(c.owner_id), "Next review": fmt_date(c.next_review_date),
            "Frameworks": ", ".join(sorted(fwsvc.requirements_for_control(c))),
        }
        for c in controls
    ]
    opts = {c.id: f"{c.code} · {c.title}" for c in controls}
    no_evidence = [c.code for c in att["implemented_without_evidence"]]
    overdue = [c.code for c in att["review_overdue"]]

cols = st.columns(len(CONTROL_STATUSES))
for col, status in zip(cols, CONTROL_STATUSES):
    col.metric(STATUS_LABELS[status], counts.get(status, 0))
if no_evidence:
    st.warning(f"{len(no_evidence)} implemented or partial control(s) have no current evidence: {', '.join(no_evidence[:15])}{'…' if len(no_evidence) > 15 else ''}")
if overdue:
    st.warning(f"Control reviews overdue: {', '.join(overdue)}")

c1, c2, c3 = st.columns(3)
fdom = c1.multiselect("Domain", sorted({r['Domain'] for r in rows}))
fst = c2.multiselect("Status", [STATUS_LABELS[x] for x in CONTROL_STATUSES])
q = c3.text_input("Search")
table(r for r in rows if (not fdom or r["Domain"] in fdom) and (not fst or r["Status"] in fst) and (not q or q.lower() in (r["Code"] + r["Control"]).lower()))

st.subheader("Control detail")
pick = st.selectbox("Control", list(opts), format_func=opts.get)
with session() as s:
    c = s.get(CommonControl, pick)
    cur = {k: getattr(c, k) for k in ("status", "owner_id", "implementation_notes", "na_justification", "review_interval_days", "description", "last_reviewed_at", "next_review_date")}
    reqs = {fw: [f"{r.ref} {r.title[:60]}" for r in rs] for fw, rs in fwsvc.requirements_for_control(c).items()}
    evs = [{"Evidence": e.title, "Kind": e.kind, "Collected": fmt_date(e.collected_on), "Valid until": fmt_date(e.valid_until), "State": ctl.evidence_state(e)} for e in ctl.evidence_for(s, pick)]
st.write(cur["description"])
for fw, items in reqs.items():
    st.markdown(f"**{fw}**: " + "; ".join(items))
st.caption(f"Last reviewed {fmt_date(cur['last_reviewed_at'])} · next review {fmt_date(cur['next_review_date'])}")
st.markdown("**Evidence**")
table(evs)

if can("control.write"):
    with st.form("ctl"):
        status = st.selectbox("Implementation status", CONTROL_STATUSES, index=CONTROL_STATUSES.index(cur["status"]), format_func=STATUS_LABELS.get)
        owner = select_user("Control owner", people, cur["owner_id"], "ctl_owner")
        notes = st.text_area("How it is implemented", cur["implementation_notes"] or "")
        na = st.text_area("Why not applicable (if so)", cur["na_justification"] or "")
        interval = st.number_input("Review every (days)", 30, 1095, int(cur["review_interval_days"]))
        if st.form_submit_button("Save control", type="primary"):
            run_action(ctl.update_control, pick, status=status, owner_id=owner, implementation_notes=notes or None, na_justification=na or None, review_interval_days=int(interval), success="Control saved.")
            st.rerun()
    if st.button("Record a review of this control"):
        run_action(ctl.review_control, pick, success="Review recorded.")
        st.rerun()
