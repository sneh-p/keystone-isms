import streamlit as st

from keystone.assets.service import list_assets
from keystone.risk.service import list_risks
from keystone.tprm.exposure.inventory import vendor_presence
from keystone.tprm import service as tprm
from keystone.tprm.models import ACCESS_LEVELS, CRITICALITY, SENSITIVITY, VENDOR_STATUSES, Vendor
from keystone.ui.common import can, fmt_date, guard, run_action, select_user, session, table, user_options

guard()
st.title("🤝 Vendors")
cfg = tprm.load_config()
editable = can("vendor.write")

with session() as s:
    people = user_options(s)
    vendors = tprm.list_vendors(s, include_terminated=st.toggle("Include terminated vendors"))
    att = tprm.vendor_attention(s)
    rows = []
    for v in vendors:
        a = tprm.latest_approved_assessment(s, v.id)
        rows.append({
            "Ref": v.ref, "Vendor": v.name, "Tier": f"{v.tier} {cfg.tier_label(v.tier)}" + (" (override)" if v.tier_override else ""),
            "Status": v.status, "Data": v.data_sensitivity, "Access": v.access_level, "Personal data": v.processes_personal_data,
            "DPA": v.dpa_signed, "Owner": people.get(v.owner_id), "Contract end": fmt_date(v.contract_end), "Next review": fmt_date(v.next_review_date),
            "Last approved assessment": fmt_date(a.approved_at) if a else "—",
            "Entra tenants": len(vendor_presence(s, v.id)),
        })
    opts = {v.id: f"{v.ref} {v.name}" for v in vendors}
    asset_opts = {a.id: a.name for a in list_assets(s)}
    risk_opts = {r.id: f"{r.ref} {r.title}" for r in list_risks(s)}

c = st.columns(5)
labels = {"review_overdue": "Reviews overdue", "contract_ending": "Contracts ending soon", "needs_assessment": "Tier 1-2 needing assessment", "no_dpa": "Personal data without DPA", "questionnaire_overdue": "Questionnaires overdue"}
for col, (k, label) in zip(c, labels.items()):
    col.metric(label, len(att[k]))
table(rows)

if editable:
    st.subheader("Add or edit a vendor")
    pick = st.selectbox("Vendor", [None, *opts], format_func=lambda k: "(new vendor)" if k is None else opts[k])
    with session() as s:
        v = s.get(Vendor, pick) if pick else None
        cur = {f: getattr(v, f) for f in tprm.VENDOR_FIELDS} if v else {}
        cur_assets = [a.id for a in v.assets] if v else []
        cur_risks = [r.id for r in v.risks] if v else []
    with st.form("vendor"):
        c1, c2 = st.columns(2)
        name = c1.text_input("Name", cur.get("name", ""))
        website = c2.text_input("Website", cur.get("website") or "")
        services = st.text_area("Services provided", cur.get("services") or "")
        c1, c2, c3 = st.columns(3)
        status = c1.selectbox("Status", VENDOR_STATUSES, index=VENDOR_STATUSES.index(cur.get("status", "prospective")))
        category = c2.text_input("Category", cur.get("category") or "")
        with c3:
            owner = select_user("Relationship owner", people, cur.get("owner_id"), "ven_owner")
        st.markdown("**Tiering inputs**")
        c1, c2, c3 = st.columns(3)
        sens = c1.selectbox("Most sensitive data they handle", SENSITIVITY, index=SENSITIVITY.index(cur.get("data_sensitivity", "none")))
        crit = c2.selectbox("Operational criticality", CRITICALITY, index=CRITICALITY.index(cur.get("operational_criticality", "low")))
        acc = c3.selectbox("Access to our systems", ACCESS_LEVELS, index=ACCESS_LEVELS.index(cur.get("access_level", "none")))
        c1, c2 = st.columns(2)
        pii = c1.checkbox("Processes personal data", cur.get("processes_personal_data", False))
        dpa = c2.checkbox("Data processing agreement signed", cur.get("dpa_signed", False))
        st.caption(f"Computed tier: **{tprm.compute_tier(sens, crit, acc, pii)}** (updates when saved). Tiering rules are calibration starting points in config/tprm.yaml.")
        c1, c2 = st.columns(2)
        T = [None, 1, 2, 3, 4]
        override = c1.selectbox("Tier override", T, index=T.index(cur.get("tier_override")), format_func=lambda t: "—" if t is None else f"{t} {cfg.tier_label(t)}")
        reason = c2.text_input("Override reason", cur.get("tier_override_reason") or "")
        c1, c2 = st.columns(2)
        cs = c1.date_input("Contract start", value=cur.get("contract_start"))
        ce = c2.date_input("Contract end", value=cur.get("contract_end"))
        sel_assets = st.multiselect("Assets they support or hold", list(asset_opts), default=cur_assets, format_func=asset_opts.get)
        sel_risks = st.multiselect("Related risks", list(risk_opts), default=cur_risks, format_func=risk_opts.get)
        notes = st.text_area("Notes", cur.get("notes") or "")
        if st.form_submit_button("Save vendor", type="primary"):
            run_action(
                tprm.save_vendor, pick, asset_ids=sel_assets, risk_ids=sel_risks,
                name=name, website=website or None, services=services or None, status=status, category=category or None, owner_id=owner,
                data_sensitivity=sens, operational_criticality=crit, access_level=acc, processes_personal_data=pii, dpa_signed=dpa,
                tier_override=override, tier_override_reason=reason or None, contract_start=cs, contract_end=ce, notes=notes or None,
                success="Vendor saved.",
            )
            st.rerun()
    if pick and st.button("Record a vendor review"):
        run_action(tprm.mark_vendor_reviewed, pick, success="Review recorded.")
        st.rerun()
