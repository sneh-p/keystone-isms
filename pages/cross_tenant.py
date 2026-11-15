import streamlit as st

from keystone.tprm.exposure import importer, inventory
from keystone.tprm.exposure.scoring import LEVEL_ORDER
from keystone.ui.common import badge, guard, session, table

guard()
st.title("🔀 Cross-tenant view")
st.caption("Vendors (via confirmed mappings) and other third-party owner organisations across your Entra tenants, using each tenant's latest snapshot.")

with session() as s:
    tenants = {t.id: t.name for t in importer.tenants(s)}
    orgs = inventory.owner_orgs(s)
    maps = inventory.mappings(s)
    from keystone.tprm.models import Vendor
    vnames = {v.id: v.name for v in s.query(Vendor).all()}
    rows = {}
    for oid, o in orgs.items():
        m = maps.get(oid)
        if m and m.status == "ignored":
            continue
        key = f"🤝 {vnames[m.vendor_id]}" if m and m.status == "confirmed" and m.vendor_id else f"{o.label} (unmapped)"
        row = rows.setdefault(key, {})
        for tid, level in o.level_by_tenant.items():
            row[tid] = inventory.worst([row.get(tid), level])

if not tenants:
    st.info("Import exposure data first.")
    st.stop()
data = []
for name, levels in rows.items():
    ch = sum(1 for lv in levels.values() if lv in ("Critical", "High"))
    worst = max(levels.values(), key=LEVEL_ORDER.index)
    data.append({"Vendor / owner org": name, "Tenants Critical/High": ch, "Present in": len(levels), **{tenants[t]: badge(levels[t]) if t in levels else "—" for t in tenants}, "_w": LEVEL_ORDER.index(worst)})
data.sort(key=lambda r: (-r["Tenants Critical/High"], -r["_w"], r["Vendor / owner org"]))
table([{k: v for k, v in r.items() if k != "_w"} for r in data])
