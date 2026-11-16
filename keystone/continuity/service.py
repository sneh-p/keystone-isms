"""Business continuity: BIA, plans and tests.

- Recovery objectives must be consistent: RTO no longer than the MTPD.
- A completed test records, per process, how long recovery took and how much data was lost; each is compared with the
  RTO and RPO. A completed test files evidence on KC-ORG-29 and KC-ORG-30 (security during disruption, ICT continuity
  readiness). A failed test, or one that missed an objective, can raise a nonconformity in one step.
- A plan is due for testing test_interval_months after its last completed test (or at once if never tested).
"""

from __future__ import annotations

from datetime import date, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.services import add_months, apply_fields, authorize, get_or_404, require_text, today

from .models import CRITICALITY, IMPACT_AREAS, TEST_OUTCOMES, TEST_TYPES, BusinessProcess, ContinuityPlan, ContinuityTest

PROCESS_FIELDS = ("name", "description", "owner_id", "criticality", "impact", "mtpd_hours", "rto_hours", "rpo_hours", "asset_ids", "vendor_ids",
                  "minimum_staff", "workarounds", "status", "next_review_date")
PLAN_FIELDS = ("title", "process_ids", "owner_id", "strategy", "activation", "policy_id", "test_interval_months", "status")
TEST_FIELDS = ("plan_id", "title", "test_type", "planned_on", "participants", "objectives")
EVIDENCE_CONTROLS = ("KC-ORG-29", "KC-ORG-30")


def _ids(v, label: str) -> None:
    if v is not None and (not isinstance(v, list) or len(v) > 200 or not all(isinstance(x, int) for x in v)):
        raise ValueError(f"{label} must be a list of ids.")


def _hours(v, label: str) -> None:
    if v is not None and (not isinstance(v, int | float) or v < 0 or v > 24 * 365):
        raise ValueError(f"{label} is a number of hours (up to a year).")


# ---- business impact analysis --------------------------------------------------------------------------------------

def processes(session: Session, actor) -> list[BusinessProcess]:
    authorize(session, actor, "read")
    rows = session.scalars(select(BusinessProcess))
    return sorted(rows, key=lambda p: (p.status != "active", CRITICALITY.index(p.criticality) if p.criticality in CRITICALITY else 9, p.name.lower()))


def save_process(session: Session, actor, process_id: int | None = None, **fields) -> BusinessProcess:
    authorize(session, actor, "continuity.write")
    p = get_or_404(session, BusinessProcess, process_id) if process_id else BusinessProcess(criticality="medium", status="active")
    apply_fields(p, fields, PROCESS_FIELDS)
    require_text(p.name, "Name")
    if p.criticality not in CRITICALITY or p.status not in ("active", "retired"):
        raise ValueError("Choose a criticality and status from the lists.")
    for label, v in (("MTPD", p.mtpd_hours), ("RTO", p.rto_hours), ("RPO", p.rpo_hours)):
        _hours(v, label)
    if p.rto_hours is not None and p.mtpd_hours is not None and p.rto_hours > p.mtpd_hours:
        raise ValueError("The RTO can't be longer than the maximum tolerable period of disruption.")
    if p.impact is not None:
        if not isinstance(p.impact, dict) or set(p.impact) - set(IMPACT_AREAS) or not all(v in (1, 2, 3, 4, 5) for v in p.impact.values()):
            raise ValueError("Impact is rated 1-5 for financial, operational, legal and reputational.")
    _ids(p.asset_ids, "Systems")
    _ids(p.vendor_ids, "Suppliers")
    if p.next_review_date is None:
        p.next_review_date = today() + timedelta(days=365)
    session.add(p)
    session.flush()
    return p


# ---- plans and tests -------------------------------------------------------------------------------------------------

def plans(session: Session, actor) -> list[ContinuityPlan]:
    authorize(session, actor, "read")
    return list(session.scalars(select(ContinuityPlan).order_by(ContinuityPlan.status, ContinuityPlan.title)))


def save_plan(session: Session, actor, plan_id: int | None = None, **fields) -> ContinuityPlan:
    authorize(session, actor, "continuity.write")
    p = get_or_404(session, ContinuityPlan, plan_id) if plan_id else ContinuityPlan(test_interval_months=12, status="active")
    apply_fields(p, fields, PLAN_FIELDS)
    require_text(p.title, "Title")
    _ids(p.process_ids, "Processes")
    if not 1 <= (p.test_interval_months or 0) <= 36:
        raise ValueError("Test at least every 36 months.")
    if p.status not in ("active", "retired"):
        raise ValueError("Unknown status.")
    session.add(p)
    session.flush()
    return p


def last_test(session: Session, plan_id: int) -> ContinuityTest | None:
    return session.scalars(select(ContinuityTest).where(ContinuityTest.plan_id == plan_id, ContinuityTest.status == "completed")
                           .order_by(ContinuityTest.performed_on.desc()).limit(1)).first()


def due_on(session: Session, p: ContinuityPlan) -> date:
    """When the plan is next due for a test: interval after its last completed test, or now if never tested."""
    t = last_test(session, p.id)
    return add_months(t.performed_on, p.test_interval_months) if t and t.performed_on else today()


def tests(session: Session, actor, plan_id: int | None = None) -> list[ContinuityTest]:
    authorize(session, actor, "read")
    q = select(ContinuityTest).order_by(ContinuityTest.planned_on.desc().nulls_last(), ContinuityTest.id.desc())
    if plan_id:
        q = q.where(ContinuityTest.plan_id == plan_id)
    return list(session.scalars(q))


def plan_test(session: Session, actor, **fields) -> ContinuityTest:
    authorize(session, actor, "continuity.write")
    get_or_404(session, ContinuityPlan, fields.get("plan_id") or 0)
    t = ContinuityTest(status="planned", test_type="tabletop")
    apply_fields(t, fields, TEST_FIELDS)
    require_text(t.title, "Title")
    if t.test_type not in TEST_TYPES:
        raise ValueError("Choose a test type from the list.")
    session.add(t)
    session.flush()
    return t


def assess_results(session: Session, results: list[dict]) -> list[dict]:
    """Validate per-process results and mark whether each met its RTO and RPO."""
    if not isinstance(results, list) or len(results) > 100:
        raise ValueError("Results must be a list.")
    out = []
    for r in results:
        if not isinstance(r, dict):
            raise ValueError("Each result is an object.")
        proc = get_or_404(session, BusinessProcess, int(r.get("process_id") or 0))
        rec, loss = r.get("recovered_hours"), r.get("data_loss_hours")
        _hours(rec, "Recovery time")
        _hours(loss, "Data loss")
        out.append({"process_id": proc.id, "recovered_hours": rec, "data_loss_hours": loss,
                    "met_rto": None if rec is None or proc.rto_hours is None else rec <= proc.rto_hours,
                    "met_rpo": None if loss is None or proc.rpo_hours is None else loss <= proc.rpo_hours})
    return out


def complete_test(session: Session, actor, test_id: int, *, performed_on: date, outcome: str, findings: str | None = None,
                  results: list[dict] | None = None, raise_nc: bool = False) -> ContinuityTest:
    authorize(session, actor, "continuity.write")
    t = get_or_404(session, ContinuityTest, test_id)
    if t.status == "completed":
        raise ValueError("This test is already recorded.")
    if outcome not in TEST_OUTCOMES:
        raise ValueError("Choose passed, passed with issues or failed.")
    if performed_on > today():
        raise ValueError("The test date can't be in the future.")
    t.results = assess_results(session, results or [])
    missed = [r for r in t.results if r["met_rto"] is False or r["met_rpo"] is False]
    if outcome == "passed" and missed:
        raise ValueError("A recovery objective was missed, so the test can't be recorded as passed.")
    t.performed_on, t.outcome, t.findings, t.status = performed_on, outcome, (findings or "").strip() or None, "completed"
    if outcome != "passed" and not t.findings:
        raise ValueError("Describe what went wrong.")
    if raise_nc and outcome != "passed":
        from keystone.improvement import service as imp

        nc = imp.raise_nc(session, actor, title=f"Continuity test {t.ref}: {t.title}"[:300], description=t.findings, source="self_identified",
                          severity="major" if outcome == "failed" else "minor")
        t.nonconformity_id = nc.id
    _evidence(session, t)
    session.flush()
    return t


def _evidence(session: Session, t: ContinuityTest) -> None:
    from keystone.controls.models import Evidence
    from keystone.frameworks.models import CommonControl

    plan = session.get(ContinuityPlan, t.plan_id)
    desc = f"{t.test_type.replace('_', ' ').title()} of {plan.title if plan else 'a continuity plan'} on {t.performed_on}: {t.outcome.replace('_', ' ') if t.outcome else ''}."
    if t.results:
        desc += " " + "; ".join(f"process {r['process_id']}: recovered in {r['recovered_hours']} h" + ("" if r["met_rto"] is not False else " (RTO missed)") for r in t.results if r["recovered_hours"] is not None)
    for code in EVIDENCE_CONTROLS:
        c = session.scalar(select(CommonControl).where(CommonControl.code == code))
        if c is not None:
            session.add(Evidence(common_control_id=c.id, title=f"Continuity test {t.ref}: {t.title}"[:300], kind="note", description=desc[:4000],
                                 collected_on=t.performed_on or today(), valid_until=(t.performed_on or today()) + timedelta(days=400)))


# ---- attention -------------------------------------------------------------------------------------------------------

def attention(session: Session, on: date | None = None) -> dict:
    on = on or today()
    active = [p for p in session.scalars(select(BusinessProcess).where(BusinessProcess.status == "active"))]
    plans_ = [p for p in session.scalars(select(ContinuityPlan).where(ContinuityPlan.status == "active"))]
    covered = {pid for p in plans_ for pid in (p.process_ids or [])}
    return {
        "processes_without_plan": [p for p in active if p.criticality in ("critical", "high") and p.id not in covered],
        "processes_without_objectives": [p for p in active if p.rto_hours is None or p.rpo_hours is None],
        "plans_test_due": [p for p in plans_ if due_on(session, p) <= on],
        "process_review_overdue": [p for p in active if p.next_review_date and p.next_review_date < on],
    }
