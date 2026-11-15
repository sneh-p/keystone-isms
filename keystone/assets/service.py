from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.services import apply_fields, authorize, get_or_404, require_text

from .models import ASSET_STATUSES, ASSET_TYPES, CLASSIFICATIONS, Asset

FIELDS = {"name", "asset_type", "description", "owner_id", "custodian", "location", "classification", "confidentiality", "integrity", "availability", "contains_personal_data", "status", "tags"}


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
