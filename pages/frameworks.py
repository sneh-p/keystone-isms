import streamlit as st

from keystone.frameworks import loader, service
from keystone.frameworks.models import STATUS_LABELS
from keystone.ui.common import can, guard, run_action, session, table

guard()
st.title("📚 Frameworks")
st.caption("Keystone implements one common control set and maps it to each framework. The crosswalk is a starting point: verify it against the source documents.")

with session() as s:
    fws = service.frameworks(s, enabled_only=False)
    fw_info = [(f.id, f.code, f"{f.name} {f.version}", f.license, f.text_level, f.notice, f.enabled) for f in fws]

if not fw_info:
    st.info("No framework content is loaded yet.")
    if can("framework.write") and st.button("Load bundled frameworks and common controls", type="primary"):
        res = run_action(loader.seed_content, success="Framework content loaded.")
        st.rerun()
    st.stop()

if can("framework.write"):
    with st.expander("Content management"):
        if st.button("Re-apply bundled content (safe; keeps your own mappings and status)"):
            run_action(loader.seed_content, success="Bundled content re-applied.")
            st.rerun()
        for fid, code, name, *_rest, enabled in fw_info:
            new = st.checkbox(f"Use {name}", value=enabled, key=f"en_{code}")
            if new != enabled:
                run_action(service.set_framework_enabled, fid, new, success="Updated.")
                st.rerun()
        st.markdown("**Import licensed text.** If you own the standard, upload CSV (`ref,text`) or YAML/JSON (`[{ref, text}]`). The text is stored only in your database and is never written to Keystone's files.")
        target = st.selectbox("Framework", [c for _, c, *_ in fw_info if c != "NIST_CSF_2_0"])
        up = st.file_uploader("Licensed text file", type=["csv", "yaml", "yml", "json"])
        if up and st.button("Import"):
            rows = loader.parse_licensed_file(up.name, up.getvalue())
            res = run_action(loader.import_licensed_text, target, rows)
            if res:
                st.success(f"Updated {res['updated']} requirements.")
                if res["unknown_refs"]:
                    st.warning("Unknown refs: " + ", ".join(res["unknown_refs"][:50]))

tab_fw, tab_ctl = st.tabs(["Browse a framework", "Look up a control"])

with tab_fw:
    choice = st.selectbox("Framework", fw_info, format_func=lambda f: f[2])
    fid, code, name, lic, level, notice, _ = choice
    if notice:
        st.caption(f"Licence: {lic} · {notice}")
    with session() as s:
        rows = service.coverage(s, fid)
        summary = service.coverage_summary(rows)
        reqs = {r.ref: r for r in service.framework_by_code(s, code).requirements}
        data = [
            {
                "Ref": r.requirement.ref,
                "Group": r.requirement.parent_ref or "",
                "Requirement": r.requirement.title,
                "Official text": "✔" if r.requirement.licensed_text else "",
                "Keystone controls": ", ".join(c.code for c in r.controls),
                "Status": r.status.replace("_", " "),
            }
            for r in rows
        ]
    c1, c2, c3 = st.columns(3)
    c1.metric("Requirements", summary["total"])
    c2.metric("Implemented", f"{summary['implemented_pct']}%")
    c3.metric("Progress (partial = ½)", f"{summary['progress_pct']}%")
    q = st.text_input("Filter", key="fw_filter")
    if q:
        data = [d for d in data if q.lower() in (d["Ref"] + d["Requirement"] + d["Keystone controls"]).lower()]
    table(data)
    groups = [r for r in reqs.values() if not r.is_leaf]
    with st.expander("Groupings (functions, categories, themes)"):
        table({"Ref": g.ref, "Title": g.title, "Description": g.description or ""} for g in groups)

with tab_ctl:
    with session() as s:
        ctls = service.controls(s)
        options = {c.code: f"{c.code} · {c.title}" for c in ctls}
        pick = st.selectbox("Control", list(options), format_func=options.get)
        ctl = next(c for c in ctls if c.code == pick)
        st.write(ctl.description)
        st.caption(f"Domain: {ctl.domain} · Status: {STATUS_LABELS[ctl.status]}")
        for fw_code, reqs_ in service.requirements_for_control(ctl).items():
            st.markdown(f"**{fw_code}**: " + ", ".join(f"`{r.ref}` {r.title[:70]}" for r in reqs_))
