import streamlit as st

from keystone.tprm import service as tprm
from keystone.tprm.models import VendorQuestionnaire
from keystone.ui.common import can, fmt_date, guard, run_action, session, table, user_options

guard()
st.title("📝 Vendor questionnaires")
st.caption("Send a template, then enter the vendor's answers as they come back. Scores weight each yes/partial/no answer.")
editable = can("vendor.write")

with session() as s:
    people = user_options(s)
    tpls = {t.id: f"{t.name} v{t.version}" for t in tprm.templates(s)}
    vendors = {v.id: v.name for v in tprm.list_vendors(s)}
    qs = tprm.questionnaires_for(s)
    rows = [{"Ref": q.ref, "Vendor": vendors.get(q.vendor_id, "?"), "Template": tpls.get(q.template_id, "?"), "Status": q.status, "Due": fmt_date(q.due_date), "Score": f"{q.score:.0f}%" if q.score is not None else "—", "Reviewed by": people.get(q.reviewed_by_id)} for q in qs]
    q_opts = {q.id: f"{q.ref} {vendors.get(q.vendor_id, '?')} ({q.status})" for q in qs}

if not tpls and editable and st.button("Load the Keystone baseline questionnaire"):
    run_action(tprm.load_default_templates, success="Template loaded.")
    st.rerun()

table(rows)

if editable and tpls and vendors:
    with st.expander("Send a questionnaire"):
        with st.form("send"):
            vid = st.selectbox("Vendor", list(vendors), format_func=vendors.get)
            tid = st.selectbox("Template", list(tpls), format_func=tpls.get)
            due = st.date_input("Due date", value=None)
            if st.form_submit_button("Mark as sent"):
                run_action(tprm.send_questionnaire, vid, tid, due, success="Questionnaire recorded as sent.")
                st.rerun()

if q_opts:
    st.subheader("Responses")
    qid = st.selectbox("Questionnaire", list(q_opts), format_func=q_opts.get)
    with session() as s:
        q = s.get(VendorQuestionnaire, qid)
        questions, responses, status, notes = q.template.questions, dict(q.responses or {}), q.status, q.review_notes
        score, findings = tprm.score_responses(questions, responses)
    st.metric("Score", f"{score:.0f}%" if score is not None else "—")
    locked = status == "reviewed" or not editable
    with st.form("answers"):
        new = {}
        section = None
        for qu in questions:
            if qu.get("section") != section:
                section = qu.get("section")
                st.markdown(f"**{section}**")
            cur = responses.get(qu["id"]) or {}
            label = qu["text"] + (" *" if qu.get("required") else "")
            if qu["type"] == "text":
                new[qu["id"]] = {"answer": None, "comment": st.text_area(label, cur.get("comment") or "", key=f"c_{qid}_{qu['id']}", disabled=locked)}
                continue
            options = ["", *tprm.QUESTION_TYPES[qu["type"]]]
            a, b = st.columns([1, 2])
            ans = a.selectbox(label, options, index=options.index(cur.get("answer") or ""), key=f"a_{qid}_{qu['id']}", disabled=locked)
            com = b.text_input("Comment", cur.get("comment") or "", key=f"m_{qid}_{qu['id']}", disabled=locked, label_visibility="hidden")
            new[qu["id"]] = {"answer": ans or None, "comment": com}
        c1, c2 = st.columns(2)
        if c1.form_submit_button("Save answers", disabled=locked):
            run_action(tprm.record_responses, qid, new, False, success="Answers saved.")
            st.rerun()
        if c2.form_submit_button("Save and mark received", disabled=locked or status not in ("sent", "draft")):
            run_action(tprm.record_responses, qid, new, True, success="Questionnaire received.")
            st.rerun()
    st.subheader("Findings")
    table({"Question": f["question"], "Answer": f["answer"], "Weight": f["weight"], "Related control": f["control"], "Comment": f["comment"]} for f in findings)
    if status == "received" and editable:
        with st.form("review"):
            rn = st.text_area("Review notes")
            if st.form_submit_button("Complete review"):
                run_action(tprm.review_questionnaire, qid, rn, success="Review completed.")
                st.rerun()
    elif notes:
        st.info(f"Review notes: {notes}")
