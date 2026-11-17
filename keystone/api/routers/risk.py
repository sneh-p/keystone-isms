from datetime import date

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from keystone.assets import service as assets
from keystone.core.services import get_or_404
from keystone.risk import service as risk
from keystone.risk.models import Risk

from ..deps import get_db, perm
from ..serialize import ser
from .common import In, xlsx_response

router = APIRouter(tags=["risk"])
ASSET = ("id", "name", "asset_type", "description", "owner_id", "custodian", "location", "classification", "confidentiality", "integrity", "availability", "contains_personal_data", "status", "tags",
         "review_date", "last_reviewed_at", "acquired_on", "disposed_on")


class AssetIn(In):
    name: str | None = None
    asset_type: str | None = None
    description: str | None = None
    owner_id: int | None = None
    custodian: str | None = None
    location: str | None = None
    classification: str | None = None
    confidentiality: int | None = None
    integrity: int | None = None
    availability: int | None = None
    contains_personal_data: bool | None = None
    status: str | None = None
    tags: str | None = None
    review_date: date | None = None
    acquired_on: date | None = None
    disposed_on: date | None = None


@router.get("/assets")
def list_assets(include_retired: bool = False, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [ser(a, ASSET, criticality=a.criticality) for a in assets.list_assets(db, include_retired)]


@router.post("/assets")
def create_asset(body: AssetIn, user=Depends(perm("asset.write")), db: Session = Depends(get_db)):
    a = assets.save_asset(db, user, **body.model_dump(exclude_unset=True))
    return ser(a, ASSET, criticality=a.criticality)


@router.get("/assets/{aid}")
def get_asset(aid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    from keystone.assets.models import Asset
    from keystone.core.services import get_or_404

    a = get_or_404(db, Asset, aid)
    return ser(a, ASSET, criticality=a.criticality, links=assets.links(db, a.id))


@router.post("/assets/{aid}/review")
def review_asset(aid: int, user=Depends(perm("asset.write")), db: Session = Depends(get_db)):
    a = assets.mark_reviewed(db, user, aid)
    return ser(a, ASSET, criticality=a.criticality)


class DeviceLinkIn(In):
    device_id: int
    linked: bool = True


@router.post("/assets/{aid}/devices")
def link_device(aid: int, body: DeviceLinkIn, user=Depends(perm("asset.write")), db: Session = Depends(get_db)):
    assets.link_device(db, user, aid, body.device_id, body.linked)
    return {"ok": True}


@router.patch("/assets/{aid}")
def update_asset(aid: int, body: AssetIn, user=Depends(perm("asset.write")), db: Session = Depends(get_db)):
    a = assets.save_asset(db, user, aid, **body.model_dump(exclude_unset=True))
    return ser(a, ASSET, criticality=a.criticality)


# ---- risks -----------------------------------------------------------------------------

RISK = ("id", "title", "description", "category", "threat", "vulnerability", "consequence", "owner_id", "inherent_likelihood", "inherent_impact", "residual_likelihood", "residual_impact", "treatment_option", "treatment_rationale", "status", "review_date", "last_reviewed_at", "fair_inputs", "fair_result", "fair_run_at")


def risk_out(r: Risk, detail: bool = False) -> dict:
    acc = risk.active_acceptance(r)
    d = ser(r, RISK, inherent_level=risk.inherent_level(r), residual_level=risk.residual_level(r), current_level=risk.current_level(r),
            asset_ids=[a.id for a in r.assets], control_ids=[c.id for c in r.controls], controls=[{"id": c.id, "code": c.code, "title": c.title} for c in r.controls],
            accepted_until=acc.expires_on if acc else None)
    if detail:
        from sqlalchemy.orm import object_session

        from keystone.incidents.models import Incident
        from keystone.tprm.models import Vendor, vendor_risks

        db = object_session(r)
        if db is not None:
            d["incidents"] = [{"id": i.id, "ref": i.ref, "title": i.title, "status": i.status} for i in db.query(Incident).filter(Incident.risk_id == r.id)]
            d["vendors"] = [{"id": v.id, "name": v.name} for v in db.query(Vendor).join(vendor_risks, vendor_risks.c.vendor_id == Vendor.id).filter(vendor_risks.c.risk_id == r.id)]
        d["actions"] = [ser(a, ("id", "title", "description", "common_control_id", "owner_id", "due_date", "status", "completed_at")) for a in r.actions]
        d["acceptances"] = [ser(a, ("id", "level_at_acceptance", "justification", "accepted_by_id", "accepted_at", "expires_on", "revoked_at")) for a in r.acceptances]
        d["assets"] = [{"id": a.id, "name": a.name} for a in r.assets]
    return d


@router.get("/risk-matrix")
def matrix(user=Depends(perm("read"))):
    m = risk.load_matrix()
    return {"likelihood": m.likelihood, "impact": m.impact, "levels": [{"level": lv, "min": mn} for lv, mn in m.levels], "appetite_max_level": m.appetite_max_level, "max_acceptance_days": m.max_acceptance_days,
            "grid": [[m.level(lk, im) for lk in range(1, 6)] for im in range(1, 6)]}


@router.get("/risks")
def list_risks(include_closed: bool = False, user=Depends(perm("read")), db: Session = Depends(get_db)):
    rs = risk.list_risks(db, include_closed)
    att = risk.needs_attention(rs)
    return {
        "risks": [risk_out(r) for r in rs],
        "attention": {k: [r.id for r in v] for k, v in att.items()},
        "heat_map": {"inherent": risk.heat_map(rs, "inherent"), "residual": risk.heat_map(rs, "residual"), "current": risk.heat_map(rs, "current")},
    }


@router.get("/risks/treatment-plan.xlsx")
def treatment_plan(user=Depends(perm("read")), db: Session = Depends(get_db)):
    from keystone.core.audit import log_event
    from keystone.reporting.exports import xlsx

    headers, rows = risk.treatment_plan(db, user)
    log_event(db, user, "export", "Risk", None, "Risk treatment plan exported")
    return xlsx_response(xlsx({"Treatment plan": (headers, rows)}, title="Risk treatment plan"), "risk-treatment-plan.xlsx")


@router.get("/risks/{rid}")
def get_risk(rid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return risk_out(get_or_404(db, Risk, rid), detail=True)


class RiskIn(In):
    title: str | None = None
    description: str | None = None
    category: str | None = None
    threat: str | None = None
    vulnerability: str | None = None
    consequence: str | None = None
    owner_id: int | None = None
    inherent_likelihood: int | None = None
    inherent_impact: int | None = None
    residual_likelihood: int | None = None
    residual_impact: int | None = None
    treatment_option: str | None = None
    treatment_rationale: str | None = None
    review_date: date | None = None
    asset_ids: list[int] | None = None
    control_ids: list[int] | None = None


@router.post("/risks")
def create_risk(body: RiskIn, user=Depends(perm("risk.write")), db: Session = Depends(get_db)):
    return risk_out(risk.save_risk(db, user, **body.model_dump(exclude_unset=True)), True)


@router.patch("/risks/{rid}")
def update_risk(rid: int, body: RiskIn, user=Depends(perm("risk.write")), db: Session = Depends(get_db)):
    return risk_out(risk.save_risk(db, user, rid, **body.model_dump(exclude_unset=True)), True)


class StatusIn(In):
    status: str


@router.post("/risks/{rid}/status")
def risk_status(rid: int, body: StatusIn, user=Depends(perm("risk.write")), db: Session = Depends(get_db)):
    return risk_out(risk.set_status(db, user, rid, body.status), True)


@router.post("/risks/{rid}/review")
def risk_review(rid: int, user=Depends(perm("risk.write")), db: Session = Depends(get_db)):
    return risk_out(risk.mark_reviewed(db, user, rid), True)


class AcceptIn(In):
    justification: str
    expires_on: date | None = None


@router.post("/risks/{rid}/accept")
def risk_accept(rid: int, body: AcceptIn, user=Depends(perm("risk.accept")), db: Session = Depends(get_db)):
    risk.accept_risk(db, user, rid, body.justification, body.expires_on)
    return risk_out(get_or_404(db, Risk, rid), True)


@router.post("/risk-acceptances/{aid}/revoke")
def revoke(aid: int, user=Depends(perm("risk.accept")), db: Session = Depends(get_db)):
    risk.revoke_acceptance(db, user, aid)
    return {"ok": True}


class ActionIn(In):
    title: str | None = None
    description: str | None = None
    common_control_id: int | None = None
    owner_id: int | None = None
    due_date: date | None = None
    status: str | None = None


@router.post("/risks/{rid}/actions")
def add_action(rid: int, body: ActionIn, user=Depends(perm("risk.write")), db: Session = Depends(get_db)):
    risk.save_action(db, user, rid, None, **body.model_dump(exclude_unset=True))
    return risk_out(get_or_404(db, Risk, rid), True)


@router.patch("/risks/{rid}/actions/{action_id}")
def edit_action(rid: int, action_id: int, body: ActionIn, user=Depends(perm("risk.write")), db: Session = Depends(get_db)):
    risk.save_action(db, user, rid, action_id, **body.model_dump(exclude_unset=True))
    return risk_out(get_or_404(db, Risk, rid), True)


class FairIn(In):
    inputs: dict
    iterations: int = 10_000


@router.post("/risks/{rid}/fair")
def run_fair(rid: int, body: FairIn, user=Depends(perm("risk.write")), db: Session = Depends(get_db)):
    risk.run_fair(db, user, rid, body.inputs, body.iterations)
    return risk_out(get_or_404(db, Risk, rid), True)


# ---- deleting records created in error (keystone/core/deletion.py: refused while anything depends on them)


@router.delete("/assets/{aid}")
def delete_asset(aid: int, user=Depends(perm("asset.write")), db: Session = Depends(get_db)):
    from keystone.core.deletion import delete_record

    delete_record(db, user, "asset", aid)
    return {"ok": True}


@router.delete("/risks/{rid}")
def delete_risk(rid: int, user=Depends(perm("risk.write")), db: Session = Depends(get_db)):
    from keystone.core.deletion import delete_record

    delete_record(db, user, "risk", rid)
    return {"ok": True}
