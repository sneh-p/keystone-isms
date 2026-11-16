"""Business continuity: business impact analysis, plans and tests."""

from datetime import date

from fastapi import APIRouter, Depends
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.continuity import service as bc

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(prefix="/continuity", tags=["continuity"])
PROCESS = ("id", "name", "description", "owner_id", "criticality", "impact", "mtpd_hours", "rto_hours", "rpo_hours", "asset_ids", "vendor_ids", "minimum_staff",
           "workarounds", "status", "next_review_date", "updated_at")
PLAN = ("id", "title", "process_ids", "owner_id", "strategy", "activation", "policy_id", "test_interval_months", "status", "updated_at")
TEST = ("id", "plan_id", "title", "test_type", "planned_on", "performed_on", "participants", "objectives", "results", "findings", "outcome", "status", "nonconformity_id")
T = Field(default=None, max_length=4000)
H = Field(default=None, ge=0, le=24 * 365)


class ProcessIn(In):
    name: str | None = Field(default=None, max_length=200)
    description: str | None = T
    owner_id: int | None = None
    criticality: str | None = None
    impact: dict[str, int] | None = None
    mtpd_hours: float | None = H
    rto_hours: float | None = H
    rpo_hours: float | None = H
    asset_ids: list[int] | None = Field(default=None, max_length=200)
    vendor_ids: list[int] | None = Field(default=None, max_length=200)
    minimum_staff: int | None = Field(default=None, ge=0, le=100000)
    workarounds: str | None = T
    status: str | None = None
    next_review_date: date | None = None


@router.get("/processes")
def processes(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [ser(p, PROCESS) for p in bc.processes(db, user)]


@router.post("/processes")
def create_process(body: ProcessIn, user=Depends(perm("continuity.write")), db: Session = Depends(get_db)):
    return ser(bc.save_process(db, user, **body.model_dump(exclude_unset=True)), PROCESS)


@router.patch("/processes/{pid}")
def update_process(pid: int, body: ProcessIn, user=Depends(perm("continuity.write")), db: Session = Depends(get_db)):
    return ser(bc.save_process(db, user, pid, **body.model_dump(exclude_unset=True)), PROCESS)


class PlanIn(In):
    title: str | None = Field(default=None, max_length=300)
    process_ids: list[int] | None = Field(default=None, max_length=200)
    owner_id: int | None = None
    strategy: str | None = T
    activation: str | None = T
    policy_id: int | None = None
    test_interval_months: int | None = Field(default=None, ge=1, le=36)
    status: str | None = None


@router.get("/plans")
def plans(user=Depends(perm("read")), db: Session = Depends(get_db)):
    out = []
    for p in bc.plans(db, user):
        last = bc.last_test(db, p.id)
        out.append(ser(p, PLAN, last_tested_on=last.performed_on if last else None, last_outcome=last.outcome if last else None, test_due_on=bc.due_on(db, p)))
    return out


@router.post("/plans")
def create_plan(body: PlanIn, user=Depends(perm("continuity.write")), db: Session = Depends(get_db)):
    return ser(bc.save_plan(db, user, **body.model_dump(exclude_unset=True)), PLAN)


@router.patch("/plans/{pid}")
def update_plan(pid: int, body: PlanIn, user=Depends(perm("continuity.write")), db: Session = Depends(get_db)):
    return ser(bc.save_plan(db, user, pid, **body.model_dump(exclude_unset=True)), PLAN)


@router.get("/tests")
def tests(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [ser(t, TEST) for t in bc.tests(db, user)]


class TestIn(In):
    plan_id: int
    title: str = Field(min_length=1, max_length=300)
    test_type: str = Field(default="tabletop", max_length=20)
    planned_on: date | None = None
    participants: str | None = T
    objectives: str | None = T


@router.post("/tests")
def plan_test(body: TestIn, user=Depends(perm("continuity.write")), db: Session = Depends(get_db)):
    return ser(bc.plan_test(db, user, **body.model_dump()), TEST)


class ResultIn(In):
    process_id: int
    recovered_hours: float | None = H
    data_loss_hours: float | None = H


class CompleteIn(In):
    performed_on: date
    outcome: str = Field(max_length=20)
    findings: str | None = T
    results: list[ResultIn] = Field(default_factory=list, max_length=100)
    raise_nc: bool = False


@router.post("/tests/{tid}/complete")
def complete_test(tid: int, body: CompleteIn, user=Depends(perm("continuity.write")), db: Session = Depends(get_db)):
    d = body.model_dump()
    return ser(bc.complete_test(db, user, tid, **d), TEST)
