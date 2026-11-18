"""Security indicators and maturity assessments."""

from datetime import date

from fastapi import APIRouter, Depends
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.indicators import service as kri
from keystone.maturity import service as mat

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(tags=["indicators and maturity"])
IND = ("id", "name", "description", "metric_key", "unit", "higher_is_better", "amber", "red", "owner_id", "active", "last_value", "last_state", "last_measured_on")


@router.get("/indicators")
def indicators(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return {"indicators": [ser(i, IND, ref=i.ref, history=[{"day": v.measured_on, "value": v.value} for v in kri.history(db, user, i.id, 90)]) for i in kri.indicators(db, user)],
            "metrics": {k: {"label": label, "unit": unit, "higher_is_better": up} for k, (label, unit, up) in kri.METRICS.items()}}


class IndicatorIn(In):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(None, max_length=2000)
    metric_key: str | None = Field(None, max_length=60)
    unit: str | None = Field(None, max_length=20)
    higher_is_better: bool = False
    amber: float = Field(ge=-1e9, le=1e9)
    red: float = Field(ge=-1e9, le=1e9)
    owner_id: int | None = None
    active: bool = True


@router.post("/indicators")
def create_indicator(body: IndicatorIn, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    return ser(kri.save(db, user, **body.model_dump()), IND)


@router.put("/indicators/{iid}")
def update_indicator(iid: int, body: IndicatorIn, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    return ser(kri.save(db, user, iid, **body.model_dump()), IND)


@router.post("/indicators/recommended")
def recommended_indicators(user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    return {"added": len(kri.add_recommended(db, user))}


class ValueIn(In):
    value: float = Field(ge=-1e9, le=1e9)
    measured_on: date | None = None
    note: str | None = Field(None, max_length=500)


@router.post("/indicators/{iid}/values")
def record_indicator_value(iid: int, body: ValueIn, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    return ser(kri.record(db, user, iid, **body.model_dump()), IND)


# ---- maturity -----------------------------------------------------------------------------------------------------

MAT = ("id", "title", "assessed_on", "scores", "summary", "status", "created_by_id")


@router.get("/maturity")
def maturity(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return {"categories": mat.categories(), "tiers": mat.TIERS,
            "assessments": [ser(a, MAT, ref=a.ref, functions=mat.by_function(a)) for a in mat.assessments(db, user)]}


class AssessmentIn(In):
    title: str | None = Field(None, min_length=1, max_length=200)
    assessed_on: date | None = None
    scores: dict[str, dict] | None = Field(None, max_length=40)
    summary: str | None = Field(None, max_length=4000)


@router.post("/maturity")
def create_assessment(body: AssessmentIn, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    return ser(mat.save(db, user, **body.model_dump(exclude_unset=True)), MAT)


@router.patch("/maturity/{aid}")
def update_assessment(aid: int, body: AssessmentIn, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    return ser(mat.save(db, user, aid, **body.model_dump(exclude_unset=True)), MAT)


@router.post("/maturity/{aid}/final")
def finalise_assessment(aid: int, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    return ser(mat.finalise(db, user, aid), MAT)


class CopyIn(In):
    title: str = Field(min_length=1, max_length=200)


@router.post("/maturity/{aid}/copy")
def copy_assessment(aid: int, body: CopyIn, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    return ser(mat.copy(db, user, aid, body.title), MAT)


@router.delete("/maturity/{aid}")
def delete_assessment(aid: int, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    mat.delete(db, user, aid)
    return {"ok": True}
