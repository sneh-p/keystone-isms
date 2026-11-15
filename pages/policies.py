import streamlit as st

from keystone.core.attachments import Attachment, read_attachment
from keystone.frameworks.service import controls as all_controls
from keystone.policies import service as pol
from keystone.policies.models import DOC_TYPES, PolicyDocument
from keystone.ui.common import person, can, current_user, fmt_date, guard, run_action, select_user, session, table, user_options

user = guard()
st.title("📜 Policies and documents")

with session() as s:
    people = user_options(s)
    pending = [(v.id, v.document.code, v.document.title, v.version_label, v.body, v.attachment_id) for v in pol.pending_for(s, current_user())]
    docs = pol.documents(s, include_retired=st.toggle("Include retired"))
    rows = []
    for d in docs:
        cur = pol.current_version(s, d)
        ov = pol.open_version(d)
        ack = pol.ack_status(s, d)
        rows.append({"Code": d.code, "Title": d.title, "Type": d.doc_type, "Owner": people.get(d.owner_id), "Status": d.status, "Current version": cur.version_label if cur else "—", "In progress": f"{ov.version_label} ({ov.status})" if ov else "", "Next review": fmt_date(d.next_review_date), "Acknowledged": f"{ack.pct:.0f}% ({ack.acknowledged}/{ack.total})" if ack else "n/a"})
    doc_opts = {d.id: f"{d.code} {d.title}" for d in docs}
    ctl_opts = {c.id: f"{c.code} {c.title}" for c in all_controls(s)}
    att = pol.policy_attention(s)

if pending:
    st.subheader(f"📌 Waiting for your acknowledgement ({len(pending)})")
    for vid, code, title, label, body, att_id in pending:
        with st.expander(f"{code} {title} v{label}"):
            if body:
                st.markdown(body)
            if att_id:
                with session() as s:
                    a = s.get(Attachment, att_id)
                    st.download_button(f"Download {a.filename}", read_attachment(a), a.filename, key=f"pd_{vid}")
            if st.button("I have read and understood this document", key=f"ack_{vid}", type="primary"):
                run_action(pol.acknowledge, vid, success="Thank you, acknowledgement recorded.")
                st.rerun()

c = st.columns(4)
c[0].metric("Documents", len(docs))
c[1].metric("Reviews overdue", len(att["review_overdue"]))
c[2].metric("Awaiting approval", len(att["awaiting_approval"]))
c[3].metric("Acknowledgement incomplete", len(att["acknowledgement_incomplete"]))
table(rows)

if can("policy.write"):
    with st.expander("New document"):
        with st.form("newdoc", clear_on_submit=True):
            c1, c2 = st.columns([1, 3])
            code = c1.text_input("Code", placeholder="POL-001")
            title = c2.text_input("Title")
            c1, c2, c3 = st.columns(3)
            dtype = c1.selectbox("Type", DOC_TYPES)
            interval = c2.number_input("Review every (months)", 1, 36, 12)
            ackreq = c3.checkbox("Staff must acknowledge", True)
            owner = select_user("Owner", people, None, "doc_owner")
            ctls = st.multiselect("Implements controls", list(ctl_opts), format_func=ctl_opts.get)
            if st.form_submit_button("Create document"):
                run_action(pol.save_document, code=code, title=title, doc_type=dtype, review_interval_months=int(interval), requires_acknowledgement=ackreq, owner_id=owner, control_ids=ctls, success="Document created.")
                st.rerun()

if not doc_opts:
    st.stop()
st.subheader("Document detail")
did = st.selectbox("Document", list(doc_opts), format_func=doc_opts.get)
with session() as s:
    d = s.get(PolicyDocument, did)
    versions = [(v.id, v.version_label, v.status, people.get(v.author_id), fmt_date(v.submitted_at), person(people, v.approved_by_id), fmt_date(v.approved_at), v.change_summary, v.approval_note, v.body, v.attachment_id, v.author_id) for v in reversed(d.versions)]
    status, controls = d.status, [c.code for c in d.controls]
    ov = pol.open_version(d)
    ov_info = (ov.id, ov.status, ov.body or "", ov.change_summary or "", ov.author_id) if ov else None
st.caption(f"Status {status} · controls: {', '.join(controls) or '—'}")
table({"Version": v[1], "Status": v[2], "Author": v[3], "Submitted": v[4], "Approved by": v[5], "Approved": v[6], "Changes": v[7], "Note": v[8]} for v in versions)
show = next((v for v in versions if v[2] == "approved"), versions[0] if versions else None)
if show:
    with st.expander(f"Read version {show[1]} ({show[2]})"):
        if show[9]:
            st.markdown(show[9])
        if show[10]:
            with session() as s:
                a = s.get(Attachment, show[10])
                st.download_button(f"Download {a.filename}", read_attachment(a), a.filename, key=f"dl_{show[0]}")

if can("policy.write") and status != "retired":
    if ov_info is None:
        with st.form("startver"):
            major = st.radio("New version", ["Major (x.0)", "Minor (x.y)"], horizontal=True) == "Major (x.0)"
            summary = st.text_input("What changes")
            if st.form_submit_button("Start a new version"):
                run_action(pol.start_version, did, change_summary=summary or None, major=major, success="Draft version started.")
                st.rerun()
    elif ov_info[1] == "draft":
        with st.form("editver"):
            body = st.text_area("Document text (Markdown)", ov_info[2], height=300)
            summary = st.text_input("Change summary", ov_info[3])
            up = st.file_uploader("Or attach the document (PDF, Word)", type=["pdf", "docx", "md", "txt"])
            c1, c2 = st.columns(2)
            if c1.form_submit_button("Save draft"):
                run_action(pol.edit_version, ov_info[0], body=body, change_summary=summary, filename=up.name if up else None, data=up.getvalue() if up else None, success="Draft saved.")
                st.rerun()
            if c2.form_submit_button("Submit for approval", type="primary"):
                ok = run_action(pol.edit_version, ov_info[0], body=body, change_summary=summary, filename=up.name if up else None, data=up.getvalue() if up else None)
                if ok:
                    run_action(pol.submit_version, ov_info[0], success="Submitted for approval.")
                st.rerun()

if can("policy.approve") and ov_info and ov_info[1] == "in_review":
    st.markdown("**Approval**")
    if ov_info[4] == user.id:
        st.info("You wrote this version, so someone else must approve it.")
    with st.form("approve"):
        note = st.text_input("Note")
        c1, c2 = st.columns(2)
        if c1.form_submit_button("Approve", type="primary"):
            run_action(pol.approve_version, ov_info[0], note or None, success="Version approved and published.")
            st.rerun()
        if c2.form_submit_button("Return to author"):
            run_action(pol.return_version, ov_info[0], note, success="Returned to author.")
            st.rerun()

if can("policy.approve") and status == "approved":
    c1, c2 = st.columns(2)
    if c1.button("Record periodic review: no changes needed"):
        run_action(pol.record_review_no_change, did, success="Review recorded.")
        st.rerun()
    if c2.button("Retire document"):
        run_action(pol.retire, did, success="Document retired.")
        st.rerun()
