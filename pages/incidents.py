from datetime import datetime

import streamlit as st

from keystone.assets.service import list_assets
from keystone.incidents import service as inc
from keystone.incidents.models import CATEGORIES, RESOLUTIONS, SEVERITIES, Incident
from keystone.risk.service import list_risks
from keystone.tprm.service import list_vendors
from keystone.ui.common import can, fmt_date, guard, run_action, select_user, session, table, tri, user_options

guard()
st.title("🚨 Incidents")
editable = can("incident.write")
SEV = {"low": "🟢 low", "medium": "🟡 medium", "high": "🟠 high", "critical": "🔴 critical"}

with session() as s:
    people = user_options(s)
    att = inc.incident_attention(s)
    items = inc.list_incidents(s, include_closed=st.toggle("Include closed", True))
    rows = [{"Ref": i.ref, "Incident": i.title, "Severity": SEV[i.severity], "Category": i.category, "Status": i.status, "Detected": fmt_date(i.detected_at), "Owner": people.get(i.owner_id), "Personal data": tri(i.personal_data_involved), "Notify by": fmt_date(inc.notification_deadline(i)) if inc.notification_deadline(i) and not i.regulator_notified_at else ("notified" if i.regulator_notified_at else "—")} for i in items]
    opts = {i.id: f"{i.ref} {i.title}" for i in items}
    asset_opts = {a.id: a.name for a in list_assets(s)}
    vendor_opts = {None: "—", **{v.id: v.name for v in list_vendors(s)}}
    risk_opts = {None: "—", **{r.id: f"{r.ref} {r.title}" for r in list_risks(s)}}
    overdue_notif = [f"{i.ref} (due {fmt_date(inc.notification_deadline(i))})" for i in att["notification_overdue"]]

c = st.columns(4)
c[0].metric("Open incidents", len(att["open"]))
c[1].metric("Regulator notification pending", len(att["notification_due"]))
c[2].metric("Notification overdue", len(att["notification_overdue"]))
c[3].metric("Containment target missed", len(att["containment_overdue"]))
if overdue_notif:
    st.error("Regulator notification deadline passed: " + ", ".join(overdue_notif))
table(rows)

if editable:
    with st.expander("Report an incident", expanded=not items):
        with st.form("report", clear_on_submit=True):
            title = st.text_input("What happened")
            c1, c2, c3 = st.columns(3)
            cat = c1.selectbox("Category", CATEGORIES)
            sev = c2.selectbox("Severity", SEVERITIES, index=1)
            pii = c3.selectbox("Personal data involved?", [None, True, False], format_func=lambda v: tri(v))
            c1, c2 = st.columns(2)
            d = c1.date_input("Detected on")
            t = c2.time_input("at (UTC)")
            desc = st.text_area("Description")
            rep = st.text_input("Reported by")
            if st.form_submit_button("Report incident", type="primary"):
                run_action(inc.report_incident, title=title, category=cat, severity=sev, personal_data_involved=pii, detected_at=datetime.combine(d, t), description=desc or None, reported_by=rep or None, success="Incident reported.")
                st.rerun()

if not opts:
    st.stop()
st.subheader("Incident detail")
iid = st.selectbox("Incident", list(opts), format_func=opts.get)
with session() as s:
    i = s.get(Incident, iid)
    cur = {f: getattr(i, f) for f in inc.FIELDS} | {"status": i.status, "assets": [a.id for a in i.assets], "notified": i.regulator_notified_at, "resolution": i.resolution}
    deadline = inc.notification_deadline(i)
    events = [(fmt_date(e.occurred_at), e.author, e.kind, e.entry) for e in i.events]
    allowed = inc.TRANSITIONS[i.status]
c1, c2, c3 = st.columns(3)
c1.metric("Status", cur["status"] + (f" ({cur['resolution']})" if cur["resolution"] else ""))
c2.metric("Severity", cur["severity"])
c3.metric("Regulator notification", fmt_date(cur["notified"]) if cur["notified"] else (f"due {fmt_date(deadline)}" if deadline else "not required / unknown"))

st.markdown("**Timeline** (entries cannot be edited)")
table({"When (UTC)": w, "By": a, "Kind": k, "Entry": e} for w, a, k, e in events)

if editable:
    with st.form("note", clear_on_submit=True):
        note = st.text_input("Add a timeline entry")
        if st.form_submit_button("Add entry"):
            run_action(inc.add_note, iid, note, success="Entry added.")
            st.rerun()
    c1, c2, c3 = st.columns([2, 2, 1])
    target = c1.selectbox("Move to", allowed)
    res = c2.selectbox("Resolution (when closing)", [None, *RESOLUTIONS], format_func=lambda v: "—" if v is None else v)
    if c3.button("Move"):
        run_action(inc.move, iid, target, res, success=f"Moved to {target}.")
        st.rerun()
    if deadline and not cur["notified"]:
        if st.button("Record regulator notification (now)"):
            run_action(inc.record_notification, iid, success="Notification recorded.")
            st.rerun()
    with st.form("edit"):
        st.markdown("**Details**")
        c1, c2 = st.columns(2)
        sev = c1.selectbox("Severity", SEVERITIES, index=SEVERITIES.index(cur["severity"]))
        with c2:
            owner = select_user("Incident owner", people, cur["owner_id"], "inc_owner")
        c1, c2 = st.columns(2)
        pii = c1.selectbox("Personal data involved?", [None, True, False], index=[None, True, False].index(cur["personal_data_involved"]), format_func=lambda v: tri(v))
        notify = c2.selectbox("Regulator notification required?", [None, True, False], index=[None, True, False].index(cur["notification_required"]), format_func=lambda v: tri(v))
        assets = st.multiselect("Affected assets", list(asset_opts), default=cur["assets"], format_func=asset_opts.get)
        c1, c2 = st.columns(2)
        vendor = c1.selectbox("Vendor involved", list(vendor_opts), index=list(vendor_opts).index(cur["vendor_id"]), format_func=vendor_opts.get)
        rsk = c2.selectbox("Related risk", list(risk_opts), index=list(risk_opts).index(cur["risk_id"]), format_func=risk_opts.get)
        rc = st.text_area("Root cause", cur["root_cause"] or "")
        ll = st.text_area("Lessons learned", cur["lessons_learned"] or "")
        if st.form_submit_button("Save details"):
            run_action(inc.update_incident, iid, asset_ids=assets, severity=sev, owner_id=owner, personal_data_involved=pii, notification_required=notify, vendor_id=vendor, risk_id=rsk, root_cause=rc or None, lessons_learned=ll or None, success="Saved.")
            st.rerun()
