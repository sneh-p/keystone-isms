import streamlit as st

from keystone.frameworks.models import STATUS_LABELS
from keystone.org.service import get_org
from keystone.reporting import dashboard
from keystone.risk.service import load_matrix
from keystone.ui.charts import heat_map
from keystone.ui.common import current_user, fmt_date, guard, session, table

user = guard()
with session() as s:
    o = get_org(s)
    ov = dashboard.overview(s)
    tasks = dashboard.my_tasks(s, current_user())
    scope_ok = bool(o and o.scope_approved_at)

st.title(f"🗝️ {o.name if o else 'Keystone ISMS'}")
if o is None:
    st.info("Start by describing your organisation and ISMS scope on **Organisation & scope**, then load the frameworks on **Frameworks**.")
elif not scope_ok:
    st.warning("The ISMS scope has not been approved yet.")

c = st.columns(6)
c[0].metric("Open risks", ov["open_risks"])
c[1].metric("Critical / High risks", ov["risk_levels"]["Critical"] + ov["risk_levels"]["High"])
c[2].metric("Open incidents", ov["open_incidents"])
c[3].metric("Open nonconformities", ov["open_ncs"])
c[4].metric("Vendors", ov["vendors"])
c[5].metric("Controls audited (3 yrs)", f"{ov['audit_coverage_pct']}%")

left, right = st.columns([3, 2])
with left:
    st.subheader("Needs attention")
    if not ov["attention"]:
        st.success("Nothing overdue.")
    for a in ov["attention"]:
        st.page_link(a["page"], label=f"**{a['count']}** {a['text']}", icon="⚠️")
    st.subheader(f"My tasks ({len(tasks)})")
    if tasks:
        table({"Task": t["what"], "Due": fmt_date(t["due"])} for t in tasks)
    else:
        st.caption("Nothing assigned to you right now.")
with right:
    m = load_matrix()
    heat_map(ov["current_grid"], m.level, m.likelihood, m.impact, "Current risk (open risks)")
    st.caption("Residual level where assessed, otherwise inherent.")

st.subheader("Framework coverage")
st.caption("Share of each framework's requirements whose mapped controls are implemented (partial counts half in progress).")
for name, cov in ov["coverage"]:
    a, b = st.columns([1, 3])
    a.markdown(f"**{name}**")
    b.progress(min(1.0, cov["progress_pct"] / 100), text=f"{cov['implemented_pct']}% implemented · {cov['progress_pct']}% progress · {cov['applicable']} applicable requirements")

st.subheader("Control implementation")
cols = st.columns(len(STATUS_LABELS))
for col, (k, label) in zip(cols, STATUS_LABELS.items()):
    col.metric(label, ov["control_status"].get(k, 0))
