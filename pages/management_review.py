from datetime import date

import streamlit as st

from keystone.audits import review as mr
from keystone.audits.models import ManagementReview
from keystone.ui.common import person, can, fmt_date, guard, run_action, select_user, session, table, user_options

guard()
st.title("🧭 Management review")
st.caption("ISO 27001 9.3. Inputs are compiled from Keystone's live records and frozen when the review is finalised.")
editable = can("review.write")

with session() as s:
    people = user_options(s)
    reviews = mr.list_reviews(s)
    rows = [{"Ref": r.ref, "Review": r.title, "Held on": fmt_date(r.held_on), "Period from": fmt_date(r.period_start), "Status": r.status, "Finalised by": person(people, r.finalized_by_id)} for r in reviews]
    opts = {r.id: f"{r.ref} {r.title} ({fmt_date(r.held_on)}, {r.status})" for r in reviews}
table(rows)

if editable:
    with st.expander("Prepare a new review", expanded=not reviews):
        with st.form("new", clear_on_submit=True):
            title = st.text_input("Title", f"Management review {date.today():%B %Y}")
            held = st.date_input("Meeting date")
            att = st.text_input("Attendees")
            if st.form_submit_button("Compile inputs and create draft", type="primary"):
                run_action(mr.create_review, title=title, held_on=held, attendees=att or None, success="Draft created with compiled inputs.")
                st.rerun()

if not opts:
    st.stop()
rid = st.selectbox("Review", list(opts), format_func=opts.get)
with session() as s:
    r = s.get(ManagementReview, rid)
    cur = {f: getattr(r, f) for f in mr.REVIEW_FIELDS} | {"status": r.status, "inputs": r.inputs}
i = cur["inputs"]
final = cur["status"] == "final"
st.write(f"Period {i['period_start']} to {i['period_end']} · inputs compiled {i['generated_at']} UTC" + (" · **final, read-only**" if final else ""))

def kv(d: dict):
    table({"Item": k.replace("_", " "), "Value": ", ".join(map(str, v)) if isinstance(v, list) else (", ".join(f"{a}: {b}" for a, b in v.items()) if isinstance(v, dict) else v)} for k, v in d.items())

st.subheader("a) Actions from previous reviews")
kv(i["a_previous_actions"])
st.subheader("b) Changes in internal and external issues")
kv(i["b_issues"])
st.subheader("c) Interested parties")
table(i["c_interested_parties"])
st.subheader("d) Information security performance")
st.markdown("**1. Nonconformities and corrective actions**")
kv(i["d1_nonconformities"])
st.markdown("**2. Monitoring and measurement results**")
kv(i["d2_monitoring"])
st.markdown("**3. Audit results**")
kv(i["d3_audits"])
st.markdown("**4. Information security objectives**")
table(i["d4_objectives"])
st.subheader("f) Risk assessment and risk treatment")
kv(i["f_risk"])
st.subheader("Also: incidents and third parties")
kv(i["incidents"])
kv(i["third_parties"])

if editable and not final:
    if st.button("Refresh inputs from current records"):
        run_action(mr.refresh_inputs, rid, success="Inputs refreshed.")
        st.rerun()
with st.form("record"):
    att = st.text_input("Attendees", cur["attendees"] or "", disabled=final)
    fb = st.text_area("e) Feedback from interested parties", cur["interested_party_feedback"] or "", disabled=final)
    opp = st.text_area("g) Opportunities for continual improvement", cur["improvement_opportunities"] or "", disabled=final)
    disc = st.text_area("Discussion", cur["discussion"] or "", disabled=final)
    dec = st.text_area("Decisions (9.3.3: improvement and changes to the ISMS)", cur["decisions"] or "", disabled=final)
    acts = st.text_area("Actions, owners and dates", cur["actions"] or "", disabled=final)
    if st.form_submit_button("Save", disabled=final or not editable):
        run_action(mr.update_review, rid, attendees=att or None, interested_party_feedback=fb or None, improvement_opportunities=opp or None, discussion=disc or None, decisions=dec or None, actions=acts or None, success="Saved.")
        st.rerun()

if editable and not final:
    with st.form("improve", clear_on_submit=True):
        st.markdown("**Track a decision as an improvement item**")
        t = st.text_input("Improvement item")
        own = select_user("Owner", people, None, "mr_owner")
        due = st.date_input("Due", value=None)
        if st.form_submit_button("Create tracked item"):
            run_action(mr.raise_improvement, rid, t, own, due, success="Improvement item created (see Nonconformities & CAPA).")
            st.rerun()
    if st.button("Finalise review (locks the record)", type="primary"):
        run_action(mr.finalize, rid, success="Review finalised.")
        st.rerun()
