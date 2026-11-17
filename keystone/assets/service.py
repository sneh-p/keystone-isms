from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.services import apply_fields, authorize, get_or_404, require_text

from .models import ASSET_STATUSES, ASSET_TYPES, CLASSIFICATIONS, Asset

FIELDS = {"name", "asset_type", "description", "owner_id", "custodian", "location", "classification", "confidentiality", "integrity", "availability", "contains_personal_data", "status", "tags",
          "review_date", "acquired_on", "disposed_on"}
REVIEW_MONTHS = 12


def _validate(a: Asset) -> None:
    require_text(a.name, "Asset name")
    if a.asset_type not in ASSET_TYPES:
        raise ValueError(f"asset_type must be one of {ASSET_TYPES}")
    if a.classification not in CLASSIFICATIONS:
        raise ValueError(f"classification must be one of {CLASSIFICATIONS}")
    if a.status not in ASSET_STATUSES:
        raise ValueError(f"status must be one of {ASSET_STATUSES}")
    for f in ("confidentiality", "integrity", "availability"):
        if not 1 <= int(getattr(a, f)) <= 5:
            raise ValueError(f"{f} must be 1-5")
    if a.acquired_on and a.disposed_on and a.disposed_on < a.acquired_on:
        raise ValueError("The disposal date is before the acquisition date.")
    if a.disposed_on and a.status != "retired":
        raise ValueError("Only retired assets have a disposal date.")


def save_asset(session: Session, actor, asset_id: int | None = None, **fields) -> Asset:
    authorize(session, actor, "asset.write")
    a = get_or_404(session, Asset, asset_id) if asset_id else Asset(asset_type="information", classification="internal", confidentiality=3, integrity=3, availability=3, status="active", contains_personal_data=False)
    apply_fields(a, fields, FIELDS)
    _validate(a)
    session.add(a)
    session.flush()
    return a


def list_assets(session: Session, include_retired: bool = False) -> list[Asset]:
    q = select(Asset).order_by(Asset.name)
    if not include_retired:
        q = q.where(Asset.status != "retired")
    return list(session.scalars(q))


def mark_reviewed(session: Session, actor, asset_id: int) -> Asset:
    """The owner (or anyone with asset.write) confirms the entry is accurate; the next review is a year on."""
    from keystone.core.db import utcnow
    from keystone.core.services import add_months, today

    authorize(session, actor, "asset.write")
    a = get_or_404(session, Asset, asset_id)
    a.last_reviewed_at, a.review_date = utcnow(), add_months(today(), REVIEW_MONTHS)
    session.flush()
    return a


def links(session: Session, asset_id: int) -> dict:
    """Everything that points at this asset, for its page."""
    from keystone.asm.models import AsmDevice
    from keystone.configcheck import service as cfg
    from keystone.configcheck.models import ConfigTarget
    from keystone.continuity.models import BusinessProcess
    from keystone.incidents.models import Incident, incident_assets
    from keystone.risk import service as risk
    from keystone.risk.models import Risk, risk_assets
    from keystone.tprm.models import Vendor, vendor_assets

    a = get_or_404(session, Asset, asset_id)
    risks = session.scalars(select(Risk).join(risk_assets, risk_assets.c.risk_id == Risk.id).where(risk_assets.c.asset_id == a.id))
    incidents = session.scalars(select(Incident).join(incident_assets, incident_assets.c.incident_id == Incident.id).where(incident_assets.c.asset_id == a.id))
    vendors = session.scalars(select(Vendor).join(vendor_assets, vendor_assets.c.vendor_id == Vendor.id).where(vendor_assets.c.asset_id == a.id))
    processes = [p for p in session.scalars(select(BusinessProcess)) if a.id in (p.asset_ids or [])]
    devices = list(session.scalars(select(AsmDevice).where(AsmDevice.asset_id == a.id)))
    targets = list(session.scalars(select(ConfigTarget).where(ConfigTarget.asset_id == a.id)))
    linked = {d.id for d in devices}
    short = a.name.lower().split(".")[0]
    suggestions = [d for d in session.scalars(select(AsmDevice).where(AsmDevice.asset_id.is_(None), AsmDevice.retired.is_(False)))
                   if d.id not in linked and short in {(d.hostname or "").lower(), d.name.lower().split(".")[0], (d.serial or "").lower()}][:5]
    return {
        "risks": [{"id": r.id, "ref": r.ref, "title": r.title, "level": risk.current_level(r), "status": r.status} for r in risks],
        "incidents": [{"id": i.id, "ref": i.ref, "title": i.title, "status": i.status, "severity": i.severity} for i in incidents],
        "vendors": [{"id": v.id, "name": v.name, "status": v.status} for v in vendors],
        "processes": [{"id": p.id, "name": p.name, "rto_hours": p.rto_hours} for p in processes],
        "devices": [{"id": d.id, "name": d.name, "os": d.os, "last_seen": d.last_seen} for d in devices],
        "device_suggestions": [{"id": d.id, "name": d.name} for d in suggestions],
        "config_targets": [{"id": t.id, "name": t.name, "platform": t.platform, **{k: v for k, v in cfg.summary(session, t).items() if k in ("state", "counts", "stale")}} for t in targets],
    }


def link_device(session: Session, actor, asset_id: int, device_id: int, linked: bool = True) -> None:
    """Tie a device the attack surface tools report to this asset register entry (or untie it)."""
    from keystone.asm.models import AsmDevice
    from keystone.core.audit import log_event

    authorize(session, actor, "asset.write")
    a = get_or_404(session, Asset, asset_id)
    d = get_or_404(session, AsmDevice, device_id)
    if linked:
        d.asset_id = a.id
    elif d.asset_id == a.id:
        d.asset_id = None
    session.flush()
    log_event(session, actor, "update", "Asset", a.id, f"{'Linked' if linked else 'Unlinked'} device {d.name}")


def assets_of_user(session: Session, user_id: int) -> list[Asset]:
    """Assets a person owns: to hand back or reassign when they leave (A.5.11)."""
    return list(session.scalars(select(Asset).where(Asset.owner_id == user_id, Asset.status != "retired").order_by(Asset.name)))


def review_due(session: Session, on=None) -> list[Asset]:
    from datetime import timedelta

    from keystone.core.services import today

    on = on or today()
    return [a for a in session.scalars(select(Asset).where(Asset.status == "active", Asset.review_date.is_not(None))) if a.review_date and a.review_date <= on + timedelta(days=14)]
