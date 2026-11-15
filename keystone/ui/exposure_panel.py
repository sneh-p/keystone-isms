"""Exposure panel shown on a vendor assessment: presence, Entra scope and FAIR suggestions."""

from __future__ import annotations

import streamlit as st

from keystone.tprm import service as tprm
from keystone.tprm.exposure import fair_mapping, importer, inventory
from keystone.tprm.models import VendorAssessment

from .common import CALIBRATION_NOTE, badge, can, fmt_date, run_action, session, table


FIELD_LABELS = {"integration_depth": "Integration depth", "plm": "Primary loss magnitude", "slm": "Secondary loss magnitude", "control_strength": "Control strength", "tef": "Threat event frequency"}


def _num(x: float) -> str:
    return f"{x:,.0f}" if abs(x) >= 1000 else f"{x:g}"


def _fmt(v) -> str:
    if v is None:
        return "—"
    if isinstance(v, dict):
        return f"{_num(v['min'])} / {_num(v['ml'])} / {_num(v['max'])}"
    return str(v)


def render(assessment_id: int, vendor_id: int) -> None:
    with session() as s:
        presence = inventory.vendor_presence(s, vendor_id)
        tenants = {t.id: t.name for t in importer.tenants(s)}
        a = s.get(VendorAssessment, assessment_id)
        status, scope = a.status, a.entra_tenant_id
        ex = fair_mapping.summarize(s, vendor_id, scope) if scope else None
        sugg = [(x.id, x.field, x.current_value, x.suggested_value, x.reasons, x.status, x.decided_by) for x in fair_mapping.suggestions_for(s, assessment_id)]
    with st.expander(f"Entra exposure · present in {len(presence)} tenant(s)", expanded=bool(presence)):
        if presence:
            st.write(" · ".join(f"{t}: {badge(lv)}" for t, lv in presence.items()))
        else:
            st.caption("No confirmed vendor mapping yet (see Vendor matching).")
        editable = can("vendor.write") and status == "draft"
        if tenants and editable:
            keys = [None, *tenants]
            new_scope = st.selectbox("Scope this assessment to tenant", keys, index=keys.index(scope) if scope in keys else 0, format_func=lambda k: "—" if k is None else tenants[k], key=f"scope_{assessment_id}")
            if new_scope != scope and st.button("Set scope", key=f"setscope_{assessment_id}"):
                run_action(lambda s_, u: tprm.save_assessment(s_, u, vendor_id, assessment_id, entra_tenant_id=new_scope), success="Scope set.")
                st.rerun()
        if ex:
            st.markdown(f"Apps: {', '.join(ex.app_names)} · worst exposure {badge(ex.worst_level)} · {ex.integration_depth}")
            if editable and st.button("Generate FAIR suggestions from exposure", key=f"gen_{assessment_id}"):
                run_action(fair_mapping.generate, assessment_id, success="Suggestions generated.")
                st.rerun()
        pending = [x for x in sugg if x[5] == "pending"]
        if sugg:
            st.caption("Suggestions never change the assessment until accepted. " + CALIBRATION_NOTE)
            for sid, field, cur, new, reasons, st_, by in sugg:
                c1, c2, c3 = st.columns([3, 1, 1])
                c1.markdown(f"**{FIELD_LABELS.get(field, field)}** (min / most likely / max): {_fmt(cur)} → **{_fmt(new)}** ({st_}{' by ' + by if by else ''})" if isinstance(new, dict) else f"**{FIELD_LABELS.get(field, field)}**: {_fmt(cur)} → **{_fmt(new)}** ({st_}{' by ' + by if by else ''})")
                c1.caption(" ".join(f"`{r['rule_id']}` {r['text']}" for r in reasons))
                if st_ == "pending" and editable:
                    if c2.button("Accept", key=f"acc_{sid}"):
                        run_action(fair_mapping.accept, sid, success=f"{FIELD_LABELS.get(field, field)} updated.")
                        st.rerun()
                    if c3.button("Reject", key=f"rej_{sid}"):
                        run_action(fair_mapping.reject, sid, success="Suggestion rejected.")
                        st.rerun()
            if pending and editable and st.button("Accept all pending", key=f"all_{assessment_id}"):
                run_action(fair_mapping.accept_all, assessment_id, success="All suggestions accepted.")
                st.rerun()
