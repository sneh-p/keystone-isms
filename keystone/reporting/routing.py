"""Who is told about each piece of work the ISMS needs.

Every "needs attention" item goes to a person:
- items on an owned record go to its owner (risk, control, vendor, policy, nonconformity, incident);
- approval and verification queues go to the people who hold that permission, never to the person whose work is
  being checked (segregation of duties);
- items on records without an owner go to the ISMS managers (administrators if there are none), summarised per
  category so they are told once, not hundreds of times.

Items are dicts like dashboard.my_tasks: {"what", "due", "page"}. They feed "My tasks" and the notification inbox.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.auth import User, expired
from keystone.core.rbac import Role, has_permission
from keystone.core.services import today


def routed_items(session: Session, on: date | None = None) -> dict[int, list[dict]]:
    from keystone.audits.models import Audit, AuditRequest
    from keystone.controls import service as ctl
    from keystone.frameworks.models import CommonControl
    from keystone.improvement import service as imp
    from keystone.incidents import service as inc
    from keystone.policies import service as pol
    from keystone.risk import service as risk
    from keystone.tasks import service as tsk
    from keystone.tprm import service as tprm
    from keystone.tprm.models import Vendor, VendorAssessment

    on = on or today()
    users = [u for u in session.scalars(select(User).where(User.active.is_(True))) if not expired(u) and u.role != Role.EMPLOYEE.value]
    active = {u.id for u in users}
    managers = [u.id for u in users if u.role == Role.ISMS_MANAGER.value] or [u.id for u in users if u.role == Role.ADMIN.value]
    out: dict[int, list[dict]] = defaultdict(list)
    unowned: dict[str, dict] = {}

    def item(what: str, page: str, due: date | None = None) -> dict:
        return {"what": what, "due": due, "page": page}

    def to_owner(owner_id: int | None, it: dict, category: str, summary: str, summary_page: str) -> None:
        if owner_id in active:
            out[owner_id].append(it)
        else:  # nobody owns it: one summary line per category for the ISMS managers
            s = unowned.setdefault(category, {"n": 0, "summary": summary, "page": summary_page})
            s["n"] += 1

    def to_holders(permission: str, it: dict, exclude: set[int | None] = frozenset()) -> None:
        for u in users:
            if has_permission(u, permission) and u.id not in exclude:
                out[u.id].append(it)

    # Risks
    ratt = risk.needs_attention(risk.list_risks(session), on)
    for r in ratt["above_appetite_untreated"]:
        to_owner(r.owner_id, item(f"Decide how to treat {r.ref} {r.title}: it is above risk appetite", f"/risks?open={r.id}"), "risk_appetite", "risk(s) above appetite without an owner", "/risks")
    for r in ratt["acceptance_expired"]:
        to_owner(r.owner_id, item(f"Risk acceptance expired for {r.ref} {r.title}: re-accept or treat it", f"/risks?open={r.id}"), "risk_acceptance", "expired risk acceptance(s) on risks without an owner", "/risks")

    # Controls and evidence
    catt = ctl.control_attention(session, on)
    owners = {c.id: c for c in session.scalars(select(CommonControl))}
    for c in catt["implemented_without_evidence"]:
        to_owner(c.owner_id, item(f"Add current evidence for {c.code} {c.title}", f"/controls?open={c.id}"), "no_evidence", "implemented control(s) without evidence and without an owner", "/controls?owner=none&flag=no_evidence")
    for key, verb in (("evidence_expiring", "expires"), ("evidence_expired", "expired")):
        for e in catt[key]:
            c = owners.get(e.common_control_id)
            when = f" on {e.valid_until:%d %b %Y}" if e.valid_until else ""
            to_owner(c.owner_id if c else None, item(f"Evidence {verb}{when}: {e.title} ({c.code if c else 'control'})", f"/controls?open={e.common_control_id}", e.valid_until),
                     key, f"evidence item(s) {'expiring' if verb == 'expires' else 'expired'} on controls without an owner", "/evidence")

    # Nonconformities and corrective actions
    natt = imp.nc_attention(session, on)
    for n in natt["overdue"]:
        to_owner(n.owner_id, item(f"Nonconformity {n.ref} {n.title} is past its target date", f"/nonconformities?open={n.id}", n.due_date), "nc_overdue", "overdue nonconformity(ies) without an owner", "/nonconformities")
    for a in natt["awaiting_verification"]:
        to_holders("nc.verify", item(f"Check the effectiveness of a corrective action ({a.description[:80]})", f"/nonconformities?open={a.nonconformity_id}"), exclude={a.owner_id})

    # Incidents
    iatt = inc.incident_attention(session)
    for i in iatt["notification_overdue"]:
        to_owner(i.owner_id, item(f"Regulator notification overdue for {i.ref} {i.title}", f"/incidents?open={i.id}"), "notification", "incident(s) past the notification deadline without an owner", "/incidents")
    for i in iatt["containment_overdue"]:
        to_owner(i.owner_id, item(f"Containment overdue for {i.ref} {i.title}", f"/incidents?open={i.id}"), "containment", "incident(s) with overdue containment and no owner", "/incidents")

    # Vendors
    vatt = tprm.vendor_attention(session, on)
    texts = {"review_overdue": "Review vendor {name}: the periodic review is due", "contract_ending": "Contract with {name} ends soon: renew or exit",
             "needs_assessment": "Assess vendor {name}: tier 1-2 without a current approved assessment", "no_dpa": "Get a data processing agreement signed with {name}",
             "questionnaire_overdue": "Chase {name}: their questionnaire is overdue"}
    for key, items in vatt.items():
        for v in items:
            vendor = v if isinstance(v, Vendor) else session.get(Vendor, getattr(v, "vendor_id", None))
            if vendor is None:
                continue
            to_owner(vendor.owner_id, item(texts.get(key, "Vendor {name} needs attention").format(name=vendor.name), f"/vendors?open={vendor.id}"),
                     f"vendor_{key}", "vendor item(s) needing attention on vendors without an owner", "/vendors")
    for a in session.scalars(select(VendorAssessment).where(VendorAssessment.status == "in_review")):
        to_holders("vendor.approve", item(f"Approve the vendor assessment {a.title}", f"/assessments?open={a.id}"), exclude={a.created_by_id})

    # Policies
    patt = pol.policy_attention(session, on)
    for d in patt["review_overdue"]:
        to_owner(d.owner_id, item(f"Review policy {d.code} {d.title}: the review date has passed", f"/policies?open={d.id}", d.next_review_date), "policy_review", "policy review(s) overdue on policies without an owner", "/policies")
    drafts: dict[int | None, int] = defaultdict(int)
    for d in patt["never_approved"]:
        drafts[d.owner_id if d.owner_id in active else None] += 1
    for owner_id, n in drafts.items():
        it = item(f"{n} draft polic{'ies' if n != 1 else 'y'} to finish and send for approval", "/policies")
        if owner_id is not None:
            out[owner_id].append(it)
        else:
            unowned["policy_drafts"] = {"n": n, "summary": "draft policy(ies) without an owner", "page": "/policies"}
    for d in patt["acknowledgement_incomplete"]:
        a = pol.ack_status(session, d)
        missing = (a.total - a.acknowledged) if a else 0
        to_owner(d.owner_id, item(f"{missing} people haven't accepted {d.code} {d.title} yet", f"/policies?open={d.id}"), "policy_ack", "policy(ies) without an owner still awaiting acceptance", "/policies")

    # Trust Center access requests and customer questionnaire answers
    from keystone.answers.models import QuestionnaireItem, SecurityQuestionnaire
    from keystone.trust.models import AccessRequest

    for r in session.scalars(select(AccessRequest).where(AccessRequest.status == "pending")):
        to_holders("trust.manage", item(f"Trust Center access request from {r.name} ({r.company})", "/trust-center"))
    drafted: dict[int, int] = defaultdict(int)
    for it in session.scalars(select(QuestionnaireItem).where(QuestionnaireItem.status == "drafted")):
        drafted[it.questionnaire_id] += 1
    for qid, n in drafted.items():
        q = session.get(SecurityQuestionnaire, qid)
        if q is not None and q.status == "open":
            to_holders("questionnaire.approve", item(f"{n} answer(s) to review in {q.title}", f"/security-questionnaires/{qid}", q.due_date))

    # Auditor evidence requests: the owner of the requested control, else the ISMS managers
    reqs = session.execute(select(AuditRequest, Audit).join(Audit, Audit.id == AuditRequest.audit_id).where(AuditRequest.status == "open", Audit.status != "closed"))
    for r, a in reqs:
        c = owners.get(r.common_control_id) if r.common_control_id else None
        it = item(f"The auditor asked for: {r.title} ({a.title})", f"/audits?open={a.id}", r.due_date)
        if c is not None and c.owner_id in active:
            out[c.owner_id].append(it)
        else:
            for m in managers:
                out[m].append(it)

    # Work nobody is assigned to
    unassigned = [t for t in tsk.list_tasks(session, include_closed=False) if t.assignee_id is None and t.status in ("todo", "in_progress")]
    if unassigned:
        unowned["tasks"] = {"n": len(unassigned), "summary": "open task(s) without an assignee", "page": "/tasks?assignee=none"}

    for s in unowned.values():
        for m in managers:
            out[m].append(item(f"{s['n']} {s['summary']}", s["page"]))
    return out
