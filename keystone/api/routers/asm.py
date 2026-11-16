"""Attack surface management: overview, devices, identities, settings, findings, baselines, exceptions."""

from datetime import date

from fastapi import APIRouter, Depends, Query
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.asm import baselines as bl
from keystone.asm import service as asm

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(prefix="/asm", tags=["attack-surface"])
BASELINE = ("id", "name", "entity", "property", "operator", "value", "scope", "severity", "controls", "missing", "enabled")


@router.get("/overview")
def overview(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return asm.overview(db, user)


@router.get("/devices")
def devices(include_retired: bool = False, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return asm.devices(db, user, include_retired)


@router.get("/devices/{did}")
def device(did: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return asm.device(db, user, did)


@router.get("/identities")
def identities(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return asm.identities(db, user)


@router.get("/settings")
def settings(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return asm.settings(db, user)


@router.get("/findings")
def findings(status: str | None = Query("open", max_length=12), severity: str | None = Query(None, max_length=10), baseline_id: int | None = None,
             user=Depends(perm("read")), db: Session = Depends(get_db)):
    return asm.findings(db, user, status=status or None, severity=severity, baseline_id=baseline_id)


@router.get("/baselines")
def baselines(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return {"baselines": [{**ser(b, BASELINE), "rule": bl.describe(b)} for b in asm.baselines_list(db, user)], "properties": asm.vocabulary(), "operators": bl.OPERATORS}


class BaselineIn(In):
    name: str | None = Field(default=None, max_length=200)
    entity: str | None = None
    property: str | None = Field(default=None, max_length=60)
    operator: str | None = None
    value: str | None = Field(default=None, max_length=20)
    scope: dict | None = None
    severity: str | None = None
    controls: list[str] | None = Field(default=None, max_length=20)
    missing: str | None = None
    enabled: bool | None = None


@router.post("/baselines")
def create_baseline(body: BaselineIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    b = bl.save_baseline(db, user, **body.model_dump(exclude_unset=True))
    bl.evaluate(db, user)
    return ser(b, BASELINE)


@router.patch("/baselines/{bid}")
def update_baseline(bid: int, body: BaselineIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    b = bl.save_baseline(db, user, bid, **body.model_dump(exclude_unset=True))
    bl.evaluate(db, user)
    return ser(b, BASELINE)


@router.post("/baselines/recommended")
def recommended(user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    added = bl.add_recommended(db, user)
    bl.evaluate(db, user)
    return {"added": len(added)}


@router.post("/evaluate")
def evaluate(user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return bl.evaluate(db, user)


class ExceptionIn(In):
    reason: str = Field(max_length=2000)
    until: date


@router.post("/findings/{fid}/exception")
def exception(fid: int, body: ExceptionIn, user=Depends(perm("risk.accept")), db: Session = Depends(get_db)):
    bl.grant_exception(db, user, fid, body.reason, body.until)
    return {"ok": True}


@router.post("/findings/{fid}/revoke-exception")
def revoke(fid: int, user=Depends(perm("risk.accept")), db: Session = Depends(get_db)):
    bl.revoke_exception(db, user, fid)
    return {"ok": True}
