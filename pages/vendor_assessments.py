import streamlit as st

from keystone.tprm import service as tprm
from keystone.tprm.models import VendorAssessment
from keystone.ui.common import person, CALIBRATION_NOTE, can, fmt_date, guard, run_action, session, table, user_options

guard()
st.title("⚖️ Vendor risk assessments")
st.caption("FAIR-based assessment of a loss scenario involving a vendor. " + CALIBRATION_NOTE)
editable = can("vendor.write")

with session() as s:
    people = user_options(s)
    vendors = {v.id: v.name for v in tprm.list_vendors(s)}
    items = tprm.assessments_for(s)
    rows = [{"Ref": a.ref, "Vendor": vendors.get(a.vendor_id, "?"), "Assessment": a.title, "Status": a.status, "Depth": a.integration_depth or "—", "ALE": f"{a.result['ale_mean']:,.0f}" if a.result else "—", "Approved": fmt_date(a.approved_at), "Approver": person(people, a.approved_by_id)} for a in items]
    a_opts = {a.id: f"{a.ref} {vendors.get(a.vendor_id, '?')}: {a.title} ({a.status})" for a in items}

if not vendors:
    st.info("Add vendors first.")
    st.stop()
table(rows)

pick = st.selectbox("Assessment", [None, *a_opts], format_func=lambda k: "(new assessment)" if k is None else a_opts[k])
with session() as s:
    a = s.get(VendorAssessment, pick) if pick else None
    cur = {k: getattr(a, k) for k in (*tprm.ASSESSMENT_FIELDS, "vendor_id", "status", "result", "run_at", "created_by_id")} if a else {}
    vendor_id = cur.get("vendor_id")

if pick:
    st.session_state["va_vendor"] = vendor_id
    try:
        from keystone.ui import exposure_panel  # added with the Entra exposure module
        exposure_panel.render(pick, vendor_id)
    except ImportError:
        pass

status = cur.get("status", "draft")
locked = status != "draft" or not editable
DEFAULTS = {"tef": {"min": 0.1, "ml": 0.5, "max": 2}, "tcap": {"min": 0.4, "ml": 0.6, "max": 0.9}, "control_strength": {"min": 0.4, "ml": 0.6, "max": 0.8}, "plm": {"min": 20000, "ml": 100000, "max": 500000}, "slef": {"min": 0.05, "ml": 0.2, "max": 0.5}, "slm": {"min": 10000, "ml": 50000, "max": 300000}}
LABELS = {"tef": ("Threat event frequency / year", None), "tcap": ("Threat capability (0-1)", 1.0), "control_strength": ("Control strength (0-1)", 1.0), "plm": ("Primary loss magnitude", None), "slef": ("Secondary loss event probability (0-1)", 1.0), "slm": ("Secondary loss magnitude", None)}

with st.form("va"):
    vid = st.selectbox("Vendor", list(vendors), format_func=vendors.get, index=list(vendors).index(vendor_id) if vendor_id in vendors else 0, disabled=bool(pick))
    title = st.text_input("Title", cur.get("title") or "", disabled=locked)
    scenario = st.text_area("Loss scenario", cur.get("scenario") or "", disabled=locked)
    depth = st.text_input("Integration depth", cur.get("integration_depth") or "", disabled=locked)
    ranges = {}
    for key, (label, maxv) in LABELS.items():
        d = cur.get(key) or DEFAULTS[key]
        c1, c2, c3 = st.columns(3)
        step = 0.05 if maxv else (0.1 if key == "tef" else 1000.0)
        ranges[key] = {
            "min": c1.number_input(f"{label}: min", 0.0, maxv, float(d["min"]), step, key=f"{pick}_{key}_min", disabled=locked),
            "ml": c2.number_input("most likely", 0.0, maxv, float(d["ml"]), step, key=f"{pick}_{key}_ml", disabled=locked),
            "max": c3.number_input("max", 0.0, maxv, float(d["max"]), step, key=f"{pick}_{key}_max", disabled=locked),
        }
    if st.form_submit_button("Save assessment", disabled=locked, type="primary"):
        res = run_action(tprm.save_assessment, vid, pick, title=title, scenario=scenario or None, integration_depth=depth or None, **ranges, success="Assessment saved.")
        st.rerun()

if pick:
    c1, c2, c3 = st.columns(3)
    if c1.button("Run FAIR simulation", disabled=locked):
        run_action(tprm.run_assessment, pick, success="Simulation complete.")
        st.rerun()
    if c2.button("Submit for approval", disabled=locked):
        run_action(tprm.submit_assessment, pick, success="Submitted.")
        st.rerun()
    res = cur.get("result")
    if res:
        m = st.columns(4)
        m[0].metric("Expected annual loss", f"{res['ale_mean']:,.0f}")
        m[1].metric("P50", f"{res['ale_p50']:,.0f}")
        m[2].metric("P90", f"{res['ale_p90']:,.0f}")
        m[3].metric("Vulnerability", f"{res['vulnerability']:.0%}")
        st.caption(f"Run {fmt_date(cur.get('run_at'))}")
    if status == "in_review" and can("vendor.approve"):
        with st.form("approve"):
            concl = st.text_area("Conclusion")
            a1, a2 = st.columns(2)
            if a1.form_submit_button("Approve"):
                run_action(tprm.approve_assessment, pick, concl, success="Assessment approved.")
                st.rerun()
            if a2.form_submit_button("Return to draft"):
                run_action(tprm.return_assessment, pick, success="Returned to draft.")
                st.rerun()
    elif cur.get("conclusion"):
        st.info(f"Conclusion: {cur['conclusion']}")
