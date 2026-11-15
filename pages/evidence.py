import streamlit as st

from keystone.controls import service as ctl
from keystone.core.attachments import Attachment, read_attachment
from keystone.frameworks import service as fwsvc
from keystone.ui.common import can, fmt_date, guard, run_action, session, table, user_options

guard()
st.title("📎 Evidence")

with session() as s:
    people = user_options(s)
    controls = {c.id: f"{c.code} · {c.title}" for c in fwsvc.controls(s)}
    evs = ctl.evidence_for(s)
    att = ctl.control_attention(s)
    rows = [
        {"Ref": e.ref, "Control": controls.get(e.common_control_id, "")[:60], "Evidence": e.title, "Kind": e.kind, "Collected": fmt_date(e.collected_on), "Valid until": fmt_date(e.valid_until), "State": ctl.evidence_state(e), "Reviewed": fmt_date(e.reviewed_at)}
        for e in evs
    ]
    files = {e.id: (e.title, e.attachment_id) for e in evs if e.attachment_id}
    ev_opts = {e.id: f"{e.ref} {e.title}" for e in evs}

c = st.columns(3)
c[0].metric("Evidence items", len(evs))
c[1].metric("Expiring within 30 days", len(att["evidence_expiring"]))
c[2].metric("Expired", len(att["evidence_expired"]))
state = st.multiselect("State", ["current", "expiring", "expired", "superseded"], default=["current", "expiring", "expired"])
table(r for r in rows if r["State"] in state)

if files:
    pick = st.selectbox("Download a file", list(files), format_func=lambda k: files[k][0])
    with session() as s:
        a = s.get(Attachment, files[pick][1])
        try:
            st.download_button(f"Download {a.filename}", read_attachment(a), a.filename, mime=a.content_type)
        except (OSError, RuntimeError) as e:
            st.error(f"File unavailable: {e}")

if can("evidence.write") and controls:
    st.subheader("Add evidence")
    with st.form("ev", clear_on_submit=True):
        cid = st.selectbox("Control", list(controls), format_func=controls.get)
        title = st.text_input("Title")
        kind = st.radio("Kind", ["file", "link", "note"], horizontal=True)
        up = st.file_uploader("File (for kind = file)")
        url = st.text_input("Link (for kind = link)")
        desc = st.text_area("Description / note")
        a, b = st.columns(2)
        collected = a.date_input("Collected on")
        valid = b.date_input("Valid until", value=None)
        if st.form_submit_button("Add evidence", type="primary"):
            run_action(ctl.add_evidence, cid, title=title, kind=kind, collected_on=collected, valid_until=valid, description=desc or None, url=url or None, filename=up.name if up else None, data=up.getvalue() if up else None, success="Evidence added.")
            st.rerun()
    if ev_opts:
        st.subheader("Review evidence")
        with st.form("evrev"):
            eid = st.selectbox("Evidence", list(ev_opts), format_func=ev_opts.get)
            sup = st.checkbox("Mark as superseded")
            if st.form_submit_button("Record review"):
                run_action(ctl.review_evidence, eid, sup, success="Review recorded.")
                st.rerun()
