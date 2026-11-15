import streamlit as st

from keystone.tprm.exposure import diff, importer, inventory
from keystone.tprm.exposure.models import EXPOSURE_LEVELS, OWNER_CLASSES, ExposureSnapshot, TenantApp
from keystone.ui.common import badge, fmt_date, guard, session, table, tri

guard()
st.title("🗺️ Exposure map")

with session() as s:
    tenants = {t.id: t.name for t in importer.tenants(s)}
if not tenants:
    st.info("Import a collected.json first.")
    st.stop()
tid = st.selectbox("Tenant", list(tenants), format_func=tenants.get)

with session() as s:
    snaps = importer.latest_snapshots(s, tid, 1)
    snap = snaps[0]
    es = snap.endpoint_status
    cp = snap.consent
    hdr = (fmt_date(snap.collected_at_utc), snap.operator_upn, snap.entra_p1_available, snap.write_scopes_present, cp.users_can_consent if cp else None, cp.admin_consent_workflow_enabled if cp else None)
    bad = [(k, v) for k, v in es.items() if v["status"] != "ok"]
    apps = inventory.latest_apps(s, OWNER_CLASSES, tid)
    rows = []
    for a in apps:
        ex = a.exposure
        rows.append({
            "id": a.id, "App": a.display_name, "Owner": a.owner_class + (" (review)" if a.needs_review else ""), "Publisher": a.verified_publisher_name or a.publisher_name or "—",
            "Verified": a.publisher_verified, "Exposure": badge(ex.exposure_level) + (" ⚠ partial data" if ex.incomplete_data else ""), "level": ex.exposure_level,
            "App-only": ex.has_app_only, "Admin consent": ex.admin_consented, "Users consented": ex.user_consent_count,
            "Dormant": tri(ex.dormant), "dormant": ex.dormant, "Last sign-in": fmt_date(a.last_sign_in_utc) if a.sign_in_data_available else "unknown",
            "Rule": ex.reasons[0]["rule_id"] if ex.reasons else "",
        })
    d = diff.latest_diff(s, tid)

c = st.columns(5)
c[0].metric("Collected", hdr[0][:10], help=f"{hdr[0]} UTC")
c[1].metric("Entra ID P1/P2", tri(hdr[2]))
c[2].metric("Users can consent", tri(hdr[4]))
c[3].metric("Admin consent workflow", tri(hdr[5], "Enabled", "Disabled"))
c[4].metric("Collected by", hdr[1].split("@")[0])
if hdr[3]:
    st.warning("Write-capable scopes were present on the collector's token (standing consent to Graph Command Line Tools).")
for k, v in bad:
    msg = f"**{k}**: {v['status']}" + (f" (HTTP {v['http_status']})" if v["http_status"] else "") + (f": {v['message']}" if v["message"] else "")
    (st.warning if v["status"] in ("unavailable_license", "skipped") else st.error)(msg + ". Results that depend on it are shown as unknown, never as safe.")

f1, f2, f3, f4, f5 = st.columns([2, 2, 1, 1, 1])
classes = f1.multiselect("Owner class", OWNER_CLASSES, default=["third_party", "unknown"])
levels = f2.multiselect("Exposure", EXPOSURE_LEVELS, default=list(EXPOSURE_LEVELS))
only_app = f3.checkbox("App-only")
only_dormant = f4.checkbox("Dormant")
only_unverified = f5.checkbox("Unverified")
shown = [r for r in rows if r["Owner"].split(" ")[0] in classes and r["level"] in levels and (not only_app or r["App-only"]) and (not only_dormant or r["dormant"] is True) and (not only_unverified or not r["Verified"])]
table([{k: v for k, v in r.items() if k not in ("id", "level", "dormant")} for r in shown])

if shown:
    st.subheader("App detail")
    pick = st.selectbox("App", [r["id"] for r in shown], format_func=lambda i: next(r["App"] for r in shown if r["id"] == i))
    with session() as s:
        a = s.get(TenantApp, pick)
        st.markdown(f"**{a.display_name}** · app ID `{a.app_id}` · owner org `{a.owner_org_id or 'unknown'}` · {a.owner_class}")
        st.markdown("**Why this level**")
        for r in a.exposure.reasons:
            st.markdown(f"- `{r['rule_id']}` {r['text']}")
        st.markdown("**Permissions**")
        table({"Type": p.permission_type, "Permission": p.value, "Resource": p.resource_name, "Tier": p.tier, "Consent": p.consent_type, "Users": p.user_count if p.user_count is not None else ""} for p in a.permissions)
        st.markdown("**Credentials**")
        if a.exposure.credential_flags is None:
            st.warning("Credential data could not be collected for this tenant: unknown.")
        else:
            table({"On": c.owner_type, "Type": c.credential_type, "Name": c.display_name, "Start": fmt_date(c.start_utc), "End": fmt_date(c.end_utc), "Lifetime (days)": c.lifetime_days, "Status": c.status} for c in a.credentials)
        st.caption("Reply URL domains: " + (", ".join(a.reply_url_domains) or "—"))

st.subheader("Changes since the previous snapshot")
if d is None:
    st.caption("Only one snapshot so far.")
else:
    if d.not_comparable:
        st.warning("Not comparable (failed in one of the two snapshots): " + ", ".join(d.not_comparable))
    c1, c2 = st.columns(2)
    c1.markdown("**New third-party apps**: " + (", ".join(d.new_apps) or "none"))
    c2.markdown("**Removed apps**: " + (", ".join(d.removed_apps) or "none"))
    st.markdown("**New permissions** (app-only critical/high first)")
    table({"": "🔴" if p.app_only_high else "", "App": p.app, "Type": p.permission_type, "Permission": p.value, "Tier": p.tier, "Consent": p.consent_type} for p in d.new_permissions)
    if d.consent_changes:
        st.markdown("**Consent posture changes**: " + "; ".join(f"{k}: {tri(a)} → {tri(b)}" for k, a, b in d.consent_changes))
    if d.new_credentials:
        st.markdown("**New credentials**: " + "; ".join(f"{a} ({t}: {n})" for a, t, n in d.new_credentials))
