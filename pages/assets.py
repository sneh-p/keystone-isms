import streamlit as st

from keystone.assets import service as assets
from keystone.assets.models import ASSET_STATUSES, ASSET_TYPES, CIA_LABELS, CLASSIFICATIONS
from keystone.ui.common import can, guard, run_action, select_user, session, table, user_options

guard()
st.title("🗄️ Asset inventory")
editable = can("asset.write")

with session() as s:
    people = user_options(s)
    show_retired = st.toggle("Show retired assets")
    items = assets.list_assets(s, include_retired=show_retired)
    rows = [
        {
            "Ref": a.ref, "Name": a.name, "Type": a.asset_type, "Owner": people.get(a.owner_id),
            "Classification": a.classification, "C": a.confidentiality, "I": a.integrity, "A": a.availability,
            "Criticality": a.criticality, "Personal data": a.contains_personal_data, "Location": a.location, "Status": a.status,
        }
        for a in items
    ]
    snap = {a.id: {f: getattr(a, f) for f in assets.FIELDS} | {"ref": a.ref} for a in items}

c1, c2 = st.columns([2, 1])
ftype = c1.multiselect("Type", ASSET_TYPES)
fclass = c2.multiselect("Classification", CLASSIFICATIONS)
table(r for r in rows if (not ftype or r["Type"] in ftype) and (not fclass or r["Classification"] in fclass))

if editable:
    st.subheader("Add or edit an asset")
    pick = st.selectbox("Asset", [None, *snap], format_func=lambda k: "(new asset)" if k is None else f"{snap[k]['ref']} {snap[k]['name']}")
    cur = snap.get(pick, {})
    with st.form("asset"):
        name = st.text_input("Name", cur.get("name", ""))
        c1, c2, c3 = st.columns(3)
        atype = c1.selectbox("Type", ASSET_TYPES, index=ASSET_TYPES.index(cur.get("asset_type", "information")))
        cls = c2.selectbox("Classification", CLASSIFICATIONS, index=CLASSIFICATIONS.index(cur.get("classification", "internal")))
        status = c3.selectbox("Status", ASSET_STATUSES, index=ASSET_STATUSES.index(cur.get("status", "active")))
        owner = select_user("Owner", people, cur.get("owner_id"), "asset_owner")
        c1, c2, c3 = st.columns(3)
        conf = c1.select_slider("Confidentiality", options=[1, 2, 3, 4, 5], value=cur.get("confidentiality", 3), format_func=lambda v: f"{v} {CIA_LABELS[v]}")
        integ = c2.select_slider("Integrity", options=[1, 2, 3, 4, 5], value=cur.get("integrity", 3), format_func=lambda v: f"{v} {CIA_LABELS[v]}")
        avail = c3.select_slider("Availability", options=[1, 2, 3, 4, 5], value=cur.get("availability", 3), format_func=lambda v: f"{v} {CIA_LABELS[v]}")
        pii = st.checkbox("Contains personal data", value=cur.get("contains_personal_data", False))
        c1, c2 = st.columns(2)
        location = c1.text_input("Location", cur.get("location") or "")
        custodian = c2.text_input("Custodian", cur.get("custodian") or "")
        desc = st.text_area("Description", cur.get("description") or "")
        tags = st.text_input("Tags (comma separated)", cur.get("tags") or "")
        if st.form_submit_button("Save asset", type="primary"):
            run_action(assets.save_asset, pick, name=name, asset_type=atype, classification=cls, status=status, owner_id=owner, confidentiality=conf, integrity=integ, availability=avail, contains_personal_data=pii, location=location or None, custodian=custodian or None, description=desc or None, tags=tags or None, success="Asset saved.")
            st.rerun()
