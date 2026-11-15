import streamlit as st
from sqlalchemy import select

from keystone.org import service as org
from keystone.org.models import InterestedParty, IsmsRoleAssignment, SecurityObjective
from keystone.ui.common import can, fmt_date, guard, run_action, select_user, session, table, user_options

guard()
st.title("🏢 Organisation & ISMS scope")
editable = can("org.write")

with session() as s:
    o = org.get_org(s)
    people = user_options(s)
    vals = {f: (getattr(o, f) if o else "") or "" for f in org.ORG_FIELDS}
    approved = (o.scope_approved_at, people.get(o.scope_approved_by_id)) if o and o.scope_approved_at else None
    parties = s.scalars(select(InterestedParty).order_by(InterestedParty.name)).all()
    roles = s.scalars(select(IsmsRoleAssignment).order_by(IsmsRoleAssignment.title)).all()
    objectives = s.scalars(select(SecurityObjective).order_by(SecurityObjective.due_date)).all()
    party_rows = [{"Name": p.name, "Type": p.party_type, "Needs & expectations": p.needs, "How addressed": p.addressed_by} for p in parties]
    role_rows = [{"Role": r.title, "Holder": people.get(r.user_id), "Deputy": people.get(r.deputy_user_id), "Responsibilities": r.responsibilities} for r in roles]
    obj_rows = [{"Ref": x.ref, "Objective": x.title, "Measure": x.measure, "Target": x.target, "Current": x.current_value, "Owner": people.get(x.owner_id), "Due": fmt_date(x.due_date), "Status": x.status} for x in objectives]
    obj_map = {x.id: f"{x.ref} {x.title}" for x in objectives}

tabs = st.tabs(["Context (4.1)", "Scope (4.3)", "Interested parties (4.2)", "ISMS roles (5.3)", "Objectives (6.2)"])

with tabs[0]:
    with st.form("context"):
        name = st.text_input("Organisation name", vals["name"], disabled=not editable)
        legal = st.text_input("Legal name", vals["legal_name"], disabled=not editable)
        industry = st.text_input("Industry", vals["industry"], disabled=not editable)
        desc = st.text_area("Description", vals["description"], disabled=not editable)
        internal = st.text_area("Internal issues", vals["internal_issues"], disabled=not editable)
        external = st.text_area("External issues", vals["external_issues"], disabled=not editable)
        appetite = st.text_area("Risk appetite statement", vals["risk_appetite"], disabled=not editable)
        if st.form_submit_button("Save context", disabled=not editable):
            run_action(org.save_org, name=name, legal_name=legal, industry=industry, description=desc, internal_issues=internal, external_issues=external, risk_appetite=appetite, success="Saved.")
            st.rerun()

with tabs[1]:
    if approved:
        st.success(f"Scope approved {fmt_date(approved[0])} by {approved[1]}.")
    else:
        st.warning("The ISMS scope is not approved. Editing the scope clears any approval.")
    with st.form("scope"):
        stmt = st.text_area("Scope statement", vals["scope_statement"], disabled=not editable)
        inc = st.text_area("Inclusions (locations, units, systems)", vals["scope_inclusions"], disabled=not editable)
        exc = st.text_area("Exclusions and justification", vals["scope_exclusions"], disabled=not editable)
        itf = st.text_area("Interfaces and dependencies", vals["scope_interfaces"], disabled=not editable)
        if st.form_submit_button("Save scope", disabled=not editable):
            run_action(org.save_org, name=vals["name"] or "My organisation", scope_statement=stmt, scope_inclusions=inc, scope_exclusions=exc, scope_interfaces=itf, success="Scope saved.")
            st.rerun()
    if editable and not approved and st.button("Approve scope"):
        run_action(org.approve_scope, success="Scope approved.")
        st.rerun()

with tabs[2]:
    table(party_rows)
    if editable:
        with st.form("party", clear_on_submit=True):
            n = st.text_input("Name")
            t = st.selectbox("Type", ["external", "internal"])
            needs = st.text_area("Needs and expectations")
            how = st.text_area("How the ISMS addresses them")
            if st.form_submit_button("Add interested party"):
                run_action(org.add_interested_party, name=n, party_type=t, needs=needs, addressed_by=how, success="Added.")
                st.rerun()

with tabs[3]:
    table(role_rows)
    if editable:
        with st.form("role", clear_on_submit=True):
            t = st.text_input("Role title", placeholder="e.g. Information Security Officer")
            holder = select_user("Holder", people, None, "role_holder")
            deputy = select_user("Deputy", people, None, "role_deputy")
            resp = st.text_area("Responsibilities and authorities")
            if st.form_submit_button("Add role"):
                run_action(org.add_isms_role, title=t, user_id=holder, deputy_user_id=deputy, responsibilities=resp, success="Role added.")
                st.rerun()

with tabs[4]:
    table(obj_rows)
    if editable:
        target_id = st.selectbox("Edit objective", [None, *obj_map], format_func=lambda k: "(new objective)" if k is None else obj_map[k])
        with st.form("objective", clear_on_submit=True):
            title = st.text_input("Objective")
            measure = st.text_input("How it is measured")
            c1, c2, c3 = st.columns(3)
            target = c1.text_input("Target")
            current = c2.text_input("Current value")
            status = c3.selectbox("Status", org.OBJECTIVE_STATUSES)
            owner = select_user("Owner", people, None, "obj_owner")
            due = st.date_input("Due date", value=None)
            if st.form_submit_button("Save objective"):
                fields = {k: v for k, v in dict(title=title, measure=measure, target=target, current_value=current, status=status, owner_id=owner, due_date=due).items() if v not in ("", None) or k == "status"}
                run_action(org.save_objective, target_id, success="Objective saved.", **fields)
                st.rerun()
