"""Attack surface management: overview, devices, identities, settings, findings, baselines, exceptions, vulnerability
priorities."""

from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.asm import baselines as bl
from keystone.asm import external as ext
from keystone.asm import service as asm
from keystone.asm import vulnintel as vi
from keystone.integrations.http import ConnectorError

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


# ---- vulnerability prioritisation (CISA KEV, EPSS, fix-by deadlines) ---------------------------------------------

@router.get("/vulnerabilities")
def vulnerabilities(priority: str | None = Query(None, pattern="^P[1-4]$"), overdue: bool = False, kev: bool = False, device_id: int | None = None,
                    user=Depends(perm("read")), db: Session = Depends(get_db)):
    return {"items": vi.vulnerabilities(db, user, priority=priority, overdue=overdue, kev_only=kev, device_id=device_id), "summary": vi.summary(db)}


@router.get("/vuln-policy")
def vuln_policy(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return vi.policy_view(vi.policy(db))


class VulnPolicyIn(In):
    kev_enabled: bool | None = None
    epss_enabled: bool | None = None
    epss_threshold: float | None = Field(default=None, gt=0, le=1)
    sla_critical: int | None = Field(default=None, ge=1, le=730)
    sla_high: int | None = Field(default=None, ge=1, le=730)
    sla_medium: int | None = Field(default=None, ge=1, le=730)
    sla_low: int | None = Field(default=None, ge=1, le=730)
    sla_kev: int | None = Field(default=None, ge=1, le=730)


@router.put("/vuln-policy")
def update_vuln_policy(body: VulnPolicyIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return vi.policy_view(vi.update_policy(db, user, **body.model_dump(exclude_unset=True)))


@router.post("/vuln-intel/refresh")
def refresh_vuln_intel(user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    try:
        return vi.refresh(db, user)
    except ConnectorError as e:
        db.commit()  # keep what did refresh and the recorded error
        raise HTTPException(502, str(e)) from None


# ---- external attack surface (verified domains only; passive) -----------------------------------------------------

@router.get("/external")
def external_view(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return ext.view(db, user)


class DomainIn(In):
    name: str = Field(min_length=4, max_length=253)


@router.post("/external/domains")
def add_domain(body: DomainIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    d = ext.add_domain(db, user, body.name)
    return {"id": d.id, "name": d.name}


@router.delete("/external/domains/{did}")
def remove_domain(did: int, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    ext.remove_domain(db, user, did)
    return {"ok": True}


@router.post("/external/domains/{did}/verify")
def verify_domain(did: int, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    try:
        d = ext.verify(db, user, did)
    except ext.NotVerified as e:
        raise HTTPException(409, str(e)) from None
    return {"id": d.id, "verified": True}


@router.post("/external/domains/{did}/scan")
def scan_domain(did: int, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    try:
        return ext.scan(db, user, did)
    except ext.NotVerified as e:
        db.commit()  # record that verification lapsed
        raise HTTPException(409, str(e)) from None


class HostIn(In):
    host: str = Field(min_length=4, max_length=253)


@router.post("/external/domains/{did}/hosts")
def add_host(did: int, body: HostIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    h = ext.add_host(db, user, did, body.host)
    return {"id": h.id, "host": h.host}
