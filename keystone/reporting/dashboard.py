"""Cross-module overview and personal task list."""

from __future__ import annotations

from datetime import date

from sqlalchemy.orm import Session

from keystone.audits import service as aud
from keystone.controls import service as ctl
from keystone.frameworks import service as fw
from keystone.improvement import service as imp
from keystone.incidents import service as inc
from keystone.policies import service as pol
from keystone.risk import service as risk
from keystone.tprm import service as tprm


def overview(session: Session, on: date | None = None) -> dict:
    on = on or date.today()
    risks = risk.list_risks(session)
    ratt = risk.needs_attention(risks, on)
    open_risks = [r for r in risks if r.status != "closed"]
    levels = {lv: 0 for lv in ("Critical", "High", "Medium", "Low")}
    for r in open_risks:
        lv = risk.current_level(r)
        if lv:
            levels[lv] += 1
    catt = ctl.control_attention(session, on)
    iatt = inc.incident_attention(session)
    natt = imp.nc_attention(session, on)
    vatt = tprm.vendor_attention(session, on)
    patt = pol.policy_attention(session, on)
    coverage = [(f.name + " " + f.version, fw.coverage_summary(fw.coverage(session, f.id))) for f in fw.frameworks(session)]
    attention = []

    def add(n, text, page):
        if n:
            attention.append({"count": n, "text": text, "page": page})

    add(len(iatt["notification_overdue"]), "incident(s) past the regulator notification deadline", "pages/incidents.py")
    add(len(iatt["notification_due"]) - len(iatt["notification_overdue"]), "incident(s) with a regulator notification still to make", "pages/incidents.py")
    add(len(ratt["above_appetite_untreated"]), "risk(s) above appetite without treatment or acceptance", "pages/risks.py")
    add(len(ratt["acceptance_expired"]), "risk acceptance(s) expired", "pages/risks.py")
    add(len(ratt["actions_overdue"]), "risk(s) with overdue treatment actions", "pages/risks.py")
    add(len(ratt["review_overdue"]), "risk review(s) overdue", "pages/risks.py")
    add(len(natt["overdue"]), "nonconformity(ies) past their target date", "pages/nonconformities.py")
    add(len(natt["awaiting_verification"]), "corrective action(s) awaiting an effectiveness check", "pages/nonconformities.py")
    add(len(catt["implemented_without_evidence"]), "implemented control(s) without current evidence", "pages/controls.py")
    add(len(catt["evidence_expired"]), "evidence item(s) expired", "pages/evidence.py")
    add(len(catt["review_overdue"]), "control review(s) overdue", "pages/controls.py")
    add(len(vatt["needs_assessment"]), "tier 1-2 vendor(s) without a current approved assessment", "pages/vendors.py")
    add(len(vatt["no_dpa"]), "vendor(s) processing personal data without a DPA", "pages/vendors.py")
    add(len(vatt["contract_ending"]), "vendor contract(s) ending soon", "pages/vendors.py")
    add(len(patt["review_overdue"]), "policy review(s) overdue", "pages/policies.py")
    add(len(patt["awaiting_approval"]), "policy version(s) awaiting approval", "pages/policies.py")
    from keystone.tasks import service as tsk

    open_tasks = tsk.list_tasks(session, include_closed=False)
    add(sum(1 for t in open_tasks if tsk.overdue(t, on)), "task(s) overdue", "/tasks")
    add(sum(1 for t in open_tasks if t.status == "in_review"), "task(s) waiting for review", "/tasks")
    return {
        "open_risks": len(open_risks),
        "risk_levels": levels,
        "current_grid": risk.heat_map(open_risks, "current"),
        "inherent_grid": risk.heat_map(open_risks, "inherent"),
        "control_status": ctl.status_counts(session),
        "coverage": coverage,
        "open_incidents": len(iatt["open"]),
        "open_ncs": len(natt["open"]),
        "vendors": len(tprm.list_vendors(session)),
        "audit_coverage_pct": aud.control_coverage(session, on)["pct"],
        "attention": attention,
    }


def my_tasks(session: Session, user, on: date | None = None) -> list[dict]:
    """Things assigned to this user that need action."""
    on = on or date.today()
    out = []
    for v in pol.pending_for(session, user):
        out.append({"what": f"Acknowledge {v.document.code} {v.document.title} v{v.version_label}", "due": None, "page": "pages/policies.py"})
    for r in risk.list_risks(session):
        if r.owner_id == user.id and r.review_date and r.review_date <= on:
            out.append({"what": f"Review risk {r.ref} {r.title}", "due": r.review_date, "page": "pages/risks.py"})
        for a in r.actions:
            if a.owner_id == user.id and a.status in ("open", "in_progress"):
                out.append({"what": f"Treatment action: {a.title} ({r.ref})", "due": a.due_date, "page": "pages/risks.py"})
    for n in imp.list_ncs(session, include_closed=False):
        for a in n.actions:
            if a.owner_id == user.id and a.status == "open":
                out.append({"what": f"Corrective action: {a.description[:80]} ({n.ref})", "due": a.due_date, "page": "pages/nonconformities.py"})
    for c in fw.controls(session):
        if c.owner_id == user.id and c.next_review_date and c.next_review_date <= on and c.status != "not_applicable":
            out.append({"what": f"Review control {c.code} {c.title}", "due": c.next_review_date, "page": "pages/controls.py"})
    for i in inc.list_incidents(session, include_closed=False):
        if i.owner_id == user.id:
            out.append({"what": f"Incident {i.ref} {i.title} ({i.status})", "due": inc.notification_deadline(i).date() if inc.notification_deadline(i) else None, "page": "pages/incidents.py"})
    for d in pol.documents(session):
        v = pol.open_version(d)
        if v and v.status == "in_review" and v.author_id != user.id:
            from keystone.core.rbac import has_permission

            if has_permission(user, "policy.approve"):
                out.append({"what": f"Approve {d.code} {d.title} v{v.version_label}", "due": None, "page": "pages/policies.py"})
    from keystone.core.rbac import has_permission as _has
    from keystone.tasks import service as tsk

    for t in tsk.list_tasks(session, include_closed=False):
        if t.assignee_id == user.id and t.status in ("todo", "in_progress"):
            out.append({"what": f"Task: {t.title}", "due": t.due_date, "page": "/tasks"})
        elif t.status == "in_review" and _has(user, "task.approve") and user.id not in (t.assignee_id, t.submitted_by_id):
            out.append({"what": f"Review task: {t.title}", "due": t.due_date, "page": "/tasks"})
    out.sort(key=lambda t: (t["due"] is None, t["due"] or date.max))
    return out
