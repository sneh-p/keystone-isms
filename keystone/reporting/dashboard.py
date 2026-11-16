"""Cross-module overview and personal task list."""

from __future__ import annotations

from datetime import date, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from keystone.audits import service as aud
from keystone.controls import service as ctl
from keystone.frameworks import service as fw
from keystone.improvement import service as imp
from keystone.incidents import service as inc
from keystone.policies import service as pol
from keystone.reporting.models import MetricSnapshot
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
    audit_cov = aud.control_coverage(session, on)
    attention = []

    def add(n, text, page):
        if n:
            attention.append({"count": n, "text": text, "page": page})

    add(len(iatt["notification_overdue"]), "incident(s) past the regulator notification deadline", "/incidents")
    add(len(iatt["notification_due"]) - len(iatt["notification_overdue"]), "incident(s) with a regulator notification still to make", "/incidents")
    add(len(ratt["above_appetite_untreated"]), "risk(s) above appetite without treatment or acceptance", "/risks")
    add(len(ratt["acceptance_expired"]), "risk acceptance(s) expired", "/risks")
    add(len(ratt["actions_overdue"]), "risk(s) with overdue treatment actions", "/risks")
    add(len(ratt["review_overdue"]), "risk review(s) overdue", "/risks")
    add(len(natt["overdue"]), "nonconformity(ies) past their target date", "/nonconformities")
    add(len(natt["awaiting_verification"]), "corrective action(s) awaiting an effectiveness check", "/nonconformities")
    add(len(catt["implemented_without_evidence"]), "implemented control(s) without current evidence", "/controls")
    add(len(catt["evidence_expired"]), "evidence item(s) expired", "/evidence")
    add(len(catt["review_overdue"]), "control review(s) overdue", "/controls")
    add(len(vatt["needs_assessment"]), "tier 1-2 vendor(s) without a current approved assessment", "/vendors")
    add(len(vatt["no_dpa"]), "vendor(s) processing personal data without a DPA", "/vendors")
    add(len(vatt["contract_ending"]), "vendor contract(s) ending soon", "/vendors")
    add(len(patt["review_overdue"]), "policy review(s) overdue", "/policies")
    add(len(patt["awaiting_approval"]), "policy version(s) awaiting approval", "/policies")
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
        "audit_coverage_pct": audit_cov["pct"],
        "audit_coverage": {"audited": audit_cov["audited"], "applicable": audit_cov["applicable"]},
        "attention": attention,
    }


def next_steps(session: Session, limit: int = 4) -> list[dict]:
    """The most useful things to do next, from real gaps in the ISMS, in setup order. Each has a count and a page."""
    from keystone.frameworks.models import CommonControl
    from keystone.integrations.models import Integration
    from keystone.org.service import get_org
    from keystone.people import service as ppl
    from keystone.trust.models import TrustSettings

    steps: list[dict] = []

    def add(n: int, key: str, title: str, detail: str, page: str) -> None:
        if n:
            steps.append({"key": key, "count": n, "title": title, "detail": detail, "page": page})

    org = get_org(session)
    add(int(bool(org and not org.scope_approved_at)), "scope", "Approve the ISMS scope", "The scope statement is the first thing an auditor reads.", "/settings/organisation")
    unowned = session.scalar(select(func.count()).select_from(CommonControl).where(CommonControl.owner_id.is_(None), CommonControl.status != "not_applicable")) or 0
    add(unowned, "owners", f"Assign owners to {unowned} control{'s' if unowned != 1 else ''}", "Every applicable control needs someone accountable for it.", "/controls?owner=none")
    patt = pol.policy_attention(session)
    drafts = len(patt["never_approved"])
    add(drafts, "policies", f"Finish and approve {drafts} draft polic{'ies' if drafts != 1 else 'y'}", "Policies count towards readiness once approved.", "/policies")
    add(len(patt["awaiting_approval"]), "approvals", f"Review {len(patt['awaiting_approval'])} policy version{'s' if len(patt['awaiting_approval']) != 1 else ''} awaiting approval", "Someone other than the author must approve.", "/policies")
    no_ev = len(ctl.control_attention(session)["implemented_without_evidence"])
    add(no_ev, "evidence", f"Upload evidence for {no_ev} implemented control{'s' if no_ev != 1 else ''}", "Without current evidence, implemented controls don't count as passing.", "/controls?flag=no_evidence")
    has_integration = session.scalar(select(func.count()).select_from(Integration)) or 0
    add(int(not has_integration), "integrations", "Connect an integration", "Automated checks collect evidence for you (GitHub, AWS, website).", "/integrations")
    not_ready = sum(1 for _, st in ppl.people_overview(session) if st is not None and not st.complete)
    add(not_ready, "people", f"Follow up {not_ready} employee{'s' if not_ready != 1 else ''} with portal tasks open", "Policies to accept, training or a device check outstanding.", "/people")
    trust = session.scalar(select(TrustSettings))
    add(int(trust is None or not trust.published), "trust", "Publish your Trust Center", "Share your security posture with customers and handle document requests.", "/trust-center")
    return steps[:limit]


# ---- trends --------------------------------------------------------------------------------------

TREND_POINTS = 12


def metrics(session: Session, on: date | None = None, ov: dict | None = None) -> dict[str, float]:
    """Headline numbers for one day. Stored daily so the dashboard can show how they moved."""
    ov = ov or overview(session, on)
    cov = [c for _, c in ov["coverage"]]
    from keystone.tasks import service as tsk

    on = on or date.today()
    return {
        "open_risks": ov["open_risks"],
        "high_risks": ov["risk_levels"]["Critical"] + ov["risk_levels"]["High"],
        "open_incidents": ov["open_incidents"],
        "open_ncs": ov["open_ncs"],
        "vendors": ov["vendors"],
        "controls_audited": ov["audit_coverage"]["audited"],
        "controls_implemented": ov["control_status"].get("implemented", 0),
        "readiness_pct": round(sum(c["progress_pct"] for c in cov) / len(cov), 1) if cov else 0.0,
        "tasks_overdue": sum(1 for t in tsk.list_tasks(session, include_closed=False) if tsk.overdue(t, on)),
    }


def take_snapshot(session: Session, on: date | None = None) -> MetricSnapshot:
    """Record today's metrics (idempotent: re-running the same day replaces that day's values)."""
    on = on or date.today()
    values = metrics(session, on)
    snap = session.scalar(select(MetricSnapshot).where(MetricSnapshot.day == on))
    if snap is None:
        snap = MetricSnapshot(day=on, values=values, taken_at=datetime.now())
        session.add(snap)
    else:
        snap.values, snap.taken_at = values, datetime.now()
    session.flush()
    return snap


def trend(session: Session, current: dict[str, float], on: date | None = None, points: int = TREND_POINTS) -> dict:
    """Weekly series (the last snapshot in each of the previous weeks) ending with today's live values."""
    on = on or date.today()
    week_start = on - timedelta(days=on.weekday())
    since = week_start - timedelta(weeks=points - 1)
    weekly: dict[date, MetricSnapshot] = {}
    for s in session.scalars(select(MetricSnapshot).where(MetricSnapshot.day >= since, MetricSnapshot.day < week_start).order_by(MetricSnapshot.day)):
        weekly[s.day - timedelta(days=s.day.weekday())] = s
    days = [s.day.isoformat() for s in weekly.values()] + [on.isoformat()]
    series = {k: [s.values.get(k) for s in weekly.values()] + [v] for k, v in current.items()}
    return {"days": days, "series": series}


def my_tasks(session: Session, user, on: date | None = None, routed: dict[int, list[dict]] | None = None) -> list[dict]:
    """Things assigned to this user that need action: their own records and tasks, plus every attention item routed
    to them (keystone/reporting/routing.py). Pass `routed` when building lists for many users."""
    from keystone.reporting.routing import routed_items

    on = on or date.today()
    out = list((routed if routed is not None else routed_items(session, on)).get(user.id, []))
    for v in pol.pending_for(session, user):
        out.append({"what": f"Acknowledge {v.document.code} {v.document.title} v{v.version_label}", "due": None, "page": "/policies"})
    for r in risk.list_risks(session):
        if r.owner_id == user.id and r.review_date and r.review_date <= on:
            out.append({"what": f"Review risk {r.ref} {r.title}", "due": r.review_date, "page": "/risks"})
        for a in r.actions:
            if a.owner_id == user.id and a.status in ("open", "in_progress"):
                out.append({"what": f"Treatment action: {a.title} ({r.ref})", "due": a.due_date, "page": "/risks"})
    for n in imp.list_ncs(session, include_closed=False):
        for a in n.actions:
            if a.owner_id == user.id and a.status == "open":
                out.append({"what": f"Corrective action: {a.description[:80]} ({n.ref})", "due": a.due_date, "page": "/nonconformities"})
    for c in fw.controls(session):
        if c.owner_id == user.id and c.next_review_date and c.next_review_date <= on and c.status != "not_applicable":
            out.append({"what": f"Review control {c.code} {c.title}", "due": c.next_review_date, "page": "/controls"})
    for i in inc.list_incidents(session, include_closed=False):
        if i.owner_id == user.id:
            out.append({"what": f"Incident {i.ref} {i.title} ({i.status})", "due": inc.notification_deadline(i).date() if inc.notification_deadline(i) else None, "page": "/incidents"})
    for d in pol.documents(session):
        v = pol.open_version(d)
        if v and v.status == "in_review" and v.author_id != user.id:
            from keystone.core.rbac import has_permission

            if has_permission(user, "policy.approve"):
                out.append({"what": f"Approve {d.code} {d.title} v{v.version_label}", "due": None, "page": "/policies"})
    from keystone.core.rbac import has_permission as _has
    from keystone.tasks import service as tsk

    for t in tsk.list_tasks(session, include_closed=False):
        if t.assignee_id == user.id and t.status in ("todo", "in_progress"):
            out.append({"what": f"Task: {t.title}", "due": t.due_date, "page": "/tasks"})
        elif t.status == "in_review" and _has(user, "task.approve") and user.id not in (t.assignee_id, t.submitted_by_id):
            out.append({"what": f"Review task: {t.title}", "due": t.due_date, "page": "/tasks"})
    out.sort(key=lambda t: (t["due"] is None, t["due"] or date.max))
    return out
