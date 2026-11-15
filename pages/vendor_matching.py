import streamlit as st

from keystone.tprm import service as tprm
from keystone.tprm.exposure import inventory, vendor_matching as vm
from keystone.ui.common import badge, can, fmt_date, guard, run_action, session, table

guard()
st.title("🔗 Vendor matching")
st.caption("Map each app owner organisation (the vendor's own Entra tenant) to a Keystone vendor. One confirmed mapping applies to every tenant. Suggestions are never applied without confirmation.")
editable = can("exposure.confirm")

if can("exposure.import") and st.button("Refresh suggestions"):
    n = run_action(vm.refresh_suggestions, success="Suggestions refreshed.")
    st.rerun()

with session() as s:
    vendors = {v.id: v.name for v in tprm.list_vendors(s)}
    q = vm.queue(s)
    queue = [
        {
            "oid": o.owner_org_id, "names": sorted(o.names), "domains": sorted(o.domains), "apps": [a.display_name for a in o.apps],
            "worst": inventory.worst(o.level_by_tenant.values()), "tenants": len(o.level_by_tenant),
            "cands": (m.match_signals or {}).get("candidates", []) if m else [],
        }
        for o, m in q
    ]
    decided = [{"Owner org": m.owner_org_id, "Status": m.status, "Vendor": vendors.get(m.vendor_id, "—"), "By": m.confirmed_by, "On": fmt_date(m.confirmed_at)} for m in inventory.mappings(s).values() if m.status != "suggested"]

st.subheader(f"Queue ({len(queue)})")
if not queue:
    st.success("Every third-party owner organisation has a decision.")
for item in queue:
    with st.expander(f"{badge(item['worst'])} · {', '.join(item['apps'][:3])} · {item['tenants']} tenant(s)"):
        st.write(f"Owner org `{item['oid']}`")
        st.write("Names: " + "; ".join(item["names"]))
        st.write("Domains: " + (", ".join(item["domains"]) or "—"))
        if item["cands"]:
            table({"Vendor": c["vendor"], "Name score": c["name_score"], "Domain match": c["domain_match"], "Strength": c["strength"]} for c in item["cands"])
        else:
            st.caption("No candidate vendors. Add the vendor first, or ignore.")
        if editable and vendors:
            default = item["cands"][0]["vendor_id"] if item["cands"] else None
            keys = list(vendors)
            c1, c2, c3 = st.columns([3, 1, 1])
            vid = c1.selectbox("Vendor", keys, index=keys.index(default) if default in keys else 0, format_func=vendors.get, key=f"v_{item['oid']}")
            if c2.button("Confirm", key=f"c_{item['oid']}", type="primary"):
                run_action(vm.confirm, item["oid"], vid, success="Mapping confirmed.")
                st.rerun()
            if c3.button("Ignore", key=f"i_{item['oid']}"):
                run_action(vm.ignore, item["oid"], success="Owner organisation ignored.")
                st.rerun()

st.subheader("Decisions")
table(decided)
if editable and decided:
    oid = st.selectbox("Undo a decision", [d["Owner org"] for d in decided])
    if st.button("Reset to undecided"):
        run_action(vm.reset, oid, success="Decision removed.")
        st.rerun()
