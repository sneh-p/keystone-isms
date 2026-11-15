import streamlit as st
from sqlalchemy import select

from keystone.core.audit import AuditLog, verify_chain
from keystone.ui.common import fmt_date, guard, session, table

guard("audit_log.view")
st.title("🧾 Audit log")
st.caption("Append-only and hash-chained. Every change to ISMS records is written here automatically.")

with session() as s:
    ok, bad = verify_chain(s)
    if ok:
        st.success("Integrity check passed: the hash chain is intact.")
    else:
        st.error(f"Integrity check FAILED at entry {bad}. The audit log has been altered outside Keystone.")
    c1, c2, c3 = st.columns(3)
    etypes = ["(all)"] + sorted(set(s.scalars(select(AuditLog.entity_type).distinct())))
    etype = c1.selectbox("Record type", etypes)
    actor = c2.text_input("Actor contains")
    limit = c3.number_input("Show latest", 50, 5000, 300, step=50)
    q = select(AuditLog).order_by(AuditLog.id.desc()).limit(int(limit))
    if etype != "(all)":
        q = q.where(AuditLog.entity_type == etype)
    if actor:
        q = q.where(AuditLog.actor_name.contains(actor.lower()))
    rows = s.scalars(q).all()
    table(
        {
            "#": r.id,
            "When (UTC)": fmt_date(r.ts),
            "Actor": r.actor_name,
            "Action": r.action,
            "Record": f"{r.entity_type} {r.entity_id or ''}",
            "Summary": r.summary,
            "Changes": str(r.changes)[:300] if r.changes else "",
        }
        for r in rows
    )
