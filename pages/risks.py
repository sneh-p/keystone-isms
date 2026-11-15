from datetime import date

import streamlit as st

from keystone.assets.service import list_assets
from keystone.frameworks.service import controls as all_controls
from keystone.risk import service as risk
from keystone.risk.models import ACTION_STATUSES, RISK_CATEGORIES, RISK_STATUSES, TREATMENT_OPTIONS, Risk
from keystone.ui.charts import heat_map
from keystone.ui.common import CALIBRATION_NOTE, badge, can, fmt_date, guard, run_action, select_user, session, table, user_options

guard()
st.title("⚠️ Risk register")
m = risk.load_matrix()
editable = can("risk.write")

with session() as s:
    people = user_options(s)
    include_closed = st.toggle("Include closed risks")
    risks = risk.list_risks(s, include_closed=include_closed)
    attention = risk.needs_attention(risks)
    grid_i, grid_r = risk.heat_map(risks, "inherent"), risk.heat_map(risks, "residual")
    reg = [
        {
            "Ref": r.ref, "Risk": r.title, "Category": r.category, "Owner": people.get(r.owner_id),
            "Inherent": badge(risk.inherent_level(r)), "Residual": badge(risk.residual_level(r)) if risk.residual_level(r) else "—",
            "Treatment": r.treatment_option or "—", "Status": r.status, "Next review": fmt_date(r.review_date),
            "ALE (FAIR)": f"{r.fair_result['ale_mean']:,.0f}" if r.fair_result else "—",
        }
        for r in risks
    ]
    risk_opts = {r.id: f"{r.ref} {r.title}" for r in risks}
    asset_opts = {a.id: a.name for a in list_assets(s)}
    control_opts = {c.id: f"{c.code} {c.title}" for c in all_controls(s)}

c = st.columns(4)
c[0].metric("Open risks", sum(1 for r in risks if r.status != "closed"))
c[1].metric("Above appetite, untreated", len(attention["above_appetite_untreated"]))
c[2].metric("Reviews overdue", len(attention["review_overdue"]))
c[3].metric("Treatment actions overdue", len(attention["actions_overdue"]))
st.caption(f"Risk appetite: residual risk up to **{m.appetite_max_level}**. {CALIBRATION_NOTE}")

tab_reg, tab_hm, tab_edit, tab_detail = st.tabs(["Register", "Heat maps", "Add / edit", "Treat, accept, quantify"])

with tab_reg:
    table(reg)

with tab_hm:
    a, b = st.columns(2)
    with a:
        heat_map(grid_i, m.level, m.likelihood, m.impact, "Inherent risk")
    with b:
        heat_map(grid_r, m.level, m.likelihood, m.impact, "Residual risk")

with tab_edit:
    if not editable:
        st.info("Your role cannot edit risks.")
    else:
        pick = st.selectbox("Risk", [None, *risk_opts], format_func=lambda k: "(new risk)" if k is None else risk_opts[k], key="edit_pick")
        with session() as s:
            r = s.get(Risk, pick) if pick else None
            cur = {f: getattr(r, f) for f in risk.EDITABLE} if r else {}
            cur_assets = [a.id for a in r.assets] if r else []
            cur_controls = [c.id for c in r.controls] if r else []
        L = [None, 1, 2, 3, 4, 5]
        with st.form("risk"):
            title = st.text_input("Title", cur.get("title", ""))
            c1, c2 = st.columns(2)
            cat = c1.selectbox("Category", RISK_CATEGORIES, index=RISK_CATEGORIES.index(cur.get("category", "operational")))
            with c2:
                owner = select_user("Risk owner", people, cur.get("owner_id"), "risk_owner")
            desc = st.text_area("Description", cur.get("description") or "")
            c1, c2, c3 = st.columns(3)
            threat = c1.text_area("Threat", cur.get("threat") or "")
            vuln = c2.text_area("Vulnerability", cur.get("vulnerability") or "")
            cons = c3.text_area("Consequence", cur.get("consequence") or "")
            st.markdown("**Inherent risk** (before controls)")
            c1, c2 = st.columns(2)
            il = c1.selectbox("Likelihood", L, index=L.index(cur.get("inherent_likelihood")), format_func=lambda v: "—" if v is None else f"{v} {m.likelihood[v]}", key="il")
            ii = c2.selectbox("Impact", L, index=L.index(cur.get("inherent_impact")), format_func=lambda v: "—" if v is None else f"{v} {m.impact[v]}", key="ii")
            st.markdown("**Residual risk** (with current and planned controls)")
            c1, c2 = st.columns(2)
            rl = c1.selectbox("Likelihood", L, index=L.index(cur.get("residual_likelihood")), format_func=lambda v: "—" if v is None else f"{v} {m.likelihood[v]}", key="rl")
            ri = c2.selectbox("Impact", L, index=L.index(cur.get("residual_impact")), format_func=lambda v: "—" if v is None else f"{v} {m.impact[v]}", key="ri")
            T = [None, *TREATMENT_OPTIONS]
            topt = st.selectbox("Treatment option", T, index=T.index(cur.get("treatment_option")), format_func=lambda v: "—" if v is None else v)
            trat = st.text_area("Treatment rationale", cur.get("treatment_rationale") or "")
            sel_assets = st.multiselect("Affected assets", list(asset_opts), default=cur_assets, format_func=asset_opts.get)
            sel_controls = st.multiselect("Treating controls", list(control_opts), default=cur_controls, format_func=control_opts.get)
            review = st.date_input("Next review", value=cur.get("review_date"))
            if st.form_submit_button("Save risk", type="primary"):
                run_action(
                    risk.save_risk, pick, asset_ids=sel_assets, control_ids=sel_controls,
                    title=title, category=cat, owner_id=owner, description=desc or None, threat=threat or None, vulnerability=vuln or None, consequence=cons or None,
                    inherent_likelihood=il, inherent_impact=ii, residual_likelihood=rl, residual_impact=ri, treatment_option=topt, treatment_rationale=trat or None, review_date=review,
                    success="Risk saved.",
                )
                st.rerun()

with tab_detail:
    if not risk_opts:
        st.info("No risks yet.")
        st.stop()
    pick = st.selectbox("Risk", list(risk_opts), format_func=risk_opts.get, key="detail_pick")
    with session() as s:
        r = s.get(Risk, pick)
        info = {
            "status": r.status, "owner": people.get(r.owner_id), "inh": risk.inherent_level(r), "res": risk.residual_level(r),
            "acc": [(a.id, a.level_at_acceptance, people.get(a.accepted_by_id), fmt_date(a.accepted_at), fmt_date(a.expires_on), a.justification, a.revoked_at) for a in r.acceptances],
            "actions": [(a.id, a.title, a.status, people.get(a.owner_id), a.due_date, a.common_control_id) for a in r.actions],
            "fair_inputs": r.fair_inputs, "fair_result": r.fair_result, "fair_run_at": r.fair_run_at, "owner_id": r.owner_id,
        }
    st.write(f"Status **{info['status']}** · owner {info['owner']} · inherent {badge(info['inh'])} · residual {badge(info['res']) if info['res'] else '—'}")

    if editable:
        allowed = [x for x in RISK_STATUSES if x not in ("accepted", info["status"])]
        c1, c2, c3 = st.columns([2, 1, 1])
        new_status = c1.selectbox("Move to status", allowed)
        if c2.button("Change status"):
            run_action(risk.set_status, pick, new_status, success="Status changed.")
            st.rerun()
        if c3.button("Mark reviewed"):
            run_action(risk.mark_reviewed, pick, success="Review recorded.")
            st.rerun()

    st.subheader("Treatment actions")
    table({"Action": t[1], "Status": t[2], "Owner": t[3], "Due": fmt_date(t[4])} for t in info["actions"])
    if editable:
        acts = {t[0]: t[1] for t in info["actions"]}
        apick = st.selectbox("Action", [None, *acts], format_func=lambda k: "(new action)" if k is None else acts[k])
        with st.form("action", clear_on_submit=True):
            at = st.text_input("Title", acts.get(apick, ""))
            c1, c2 = st.columns(2)
            ast = c1.selectbox("Status", ACTION_STATUSES)
            due = c2.date_input("Due", value=None)
            with c1:
                aown = select_user("Owner", people, None, "act_owner")
            actl = c2.selectbox("Control implemented", [None, *control_opts], format_func=lambda k: "—" if k is None else control_opts[k])
            if st.form_submit_button("Save action"):
                fields = dict(title=at, status=ast, owner_id=aown, common_control_id=actl)
                if due:
                    fields["due_date"] = due
                run_action(risk.save_action, pick, apick, success="Action saved.", **fields)
                st.rerun()

    st.subheader("Risk acceptance")
    table({"Level": a[1], "Accepted by": a[2], "On": a[3], "Expires": a[4], "Justification": a[5], "Revoked": "yes" if a[6] else ""} for a in info["acc"])
    if can("risk.accept"):
        with st.form("accept"):
            just = st.text_area("Justification")
            exp = st.date_input("Expires on", value=None, help=f"Default and maximum for risks above appetite: {m.max_acceptance_days} days.")
            st.caption("Segregation of duties: you cannot accept a risk you own.")
            if st.form_submit_button("Accept risk"):
                run_action(risk.accept_risk, pick, just, exp, success="Risk accepted.")
                st.rerun()

    st.subheader("Quantify with FAIR")
    st.caption("Monte Carlo estimate of annualised loss. Ranges are min / most likely / max. " + CALIBRATION_NOTE)
    prev = info["fair_inputs"] or {"tef": {"min": 0.5, "ml": 2, "max": 6}, "tcap": {"min": 0.3, "ml": 0.6, "max": 0.9}, "cs": {"min": 0.4, "ml": 0.6, "max": 0.8}, "plm": {"min": 10000, "ml": 50000, "max": 250000}}

    def rng_input(label, key, default, step, maxv=None):
        d = prev.get(key) or default
        c1, c2, c3 = st.columns(3)
        lo = c1.number_input(f"{label} min", 0.0, maxv, float(d["min"]), step, key=f"{key}_min")
        ml = c2.number_input(f"{label} most likely", 0.0, maxv, float(d["ml"]), step, key=f"{key}_ml")
        hi = c3.number_input(f"{label} max", 0.0, maxv, float(d["max"]), step, key=f"{key}_max")
        return {"min": lo, "ml": ml, "max": hi}

    with st.form("fair"):
        tef = rng_input("Threat events / year", "tef", prev["tef"], 0.1)
        tcap = rng_input("Threat capability (0-1)", "tcap", {"min": 0.3, "ml": 0.6, "max": 0.9}, 0.05, 1.0)
        cs = rng_input("Control strength (0-1)", "cs", {"min": 0.4, "ml": 0.6, "max": 0.8}, 0.05, 1.0)
        plm = rng_input("Primary loss per event", "plm", prev["plm"], 1000.0)
        use_sec = st.checkbox("Include secondary loss", value=bool(prev.get("slef")))
        slef = rng_input("Secondary loss event probability (0-1)", "slef", {"min": 0.05, "ml": 0.2, "max": 0.5}, 0.05, 1.0)
        slm = rng_input("Secondary loss per event", "slm", {"min": 5000, "ml": 25000, "max": 150000}, 1000.0)
        iters = st.select_slider("Iterations", [1000, 5000, 10000, 50000], value=10000)
        disabled = not editable
        if st.form_submit_button("Run simulation", disabled=disabled):
            inputs = {"tef": tef, "tcap": tcap, "cs": cs, "plm": plm} | ({"slef": slef, "slm": slm} if use_sec else {})
            if run_action(risk.run_fair, pick, inputs, iters, success="Simulation saved."):
                st.rerun()
    res = info["fair_result"]
    if res:
        c = st.columns(4)
        c[0].metric("Expected annual loss", f"{res['ale_mean']:,.0f}")
        c[1].metric("Median (P50)", f"{res['ale_p50']:,.0f}")
        c[2].metric("P90", f"{res['ale_p90']:,.0f}")
        c[3].metric("Vulnerability", f"{res['vulnerability']:.0%}")
        st.caption(f"Loss event frequency {res['lef_mean']:.2f}/year · chance of any loss in a year {res['prob_any_loss']:.0%} · {res['iterations']:,} iterations · run {fmt_date(info['fair_run_at'])}")
        st.markdown("**Loss exceedance curve**: chance that annual loss reaches at least a given amount")
        st.line_chart({"Annual loss": [x for x, _ in res["exceedance"]], "Probability of reaching it": [p for _, p in res["exceedance"]]}, x="Annual loss", y="Probability of reaching it", height=260)
