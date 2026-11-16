"""Queries across the latest snapshot of every Entra tenant."""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from .models import EntraTenant, ExposureSnapshot, TenantApp, VendorAppMapping
from .scoring import LEVEL_ORDER

VENDOR_CLASSES = ("third_party", "unknown")


def latest_snapshot_ids(session: Session) -> dict[int, int]:
    """{tenant_id: latest snapshot id}"""
    sub = select(ExposureSnapshot.tenant_id, func.max(ExposureSnapshot.collected_at_utc).label("m")).group_by(ExposureSnapshot.tenant_id).subquery()
    rows = session.execute(select(ExposureSnapshot.tenant_id, ExposureSnapshot.id).join(sub, (sub.c.tenant_id == ExposureSnapshot.tenant_id) & (sub.c.m == ExposureSnapshot.collected_at_utc)))
    return {t: s for t, s in rows}


def latest_apps(session: Session, owner_classes=VENDOR_CLASSES, tenant_id: int | None = None) -> list[TenantApp]:
    ids = latest_snapshot_ids(session)
    if tenant_id is not None:
        ids = {tenant_id: ids[tenant_id]} if tenant_id in ids else {}
    if not ids:
        return []
    q = select(TenantApp).where(TenantApp.snapshot_id.in_(ids.values())).options(selectinload(TenantApp.permissions), selectinload(TenantApp.credentials), selectinload(TenantApp.exposure))
    if owner_classes:
        q = q.where(TenantApp.owner_class.in_(owner_classes))
    return list(session.scalars(q.order_by(TenantApp.display_name)))


def worst(levels) -> str | None:
    levels = [lv for lv in levels if lv]
    return max(levels, key=LEVEL_ORDER.index) if levels else None


@dataclass
class OwnerOrg:
    owner_org_id: str
    names: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    apps: list[TenantApp] = field(default_factory=list)
    level_by_tenant: dict[int, str | None] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return sorted(self.names, key=len)[0] if self.names else self.owner_org_id


def owner_orgs(session: Session) -> dict[str, OwnerOrg]:
    out: dict[str, OwnerOrg] = {}
    for app in latest_apps(session, ("third_party",)):
        if not app.owner_org_id:  # third-party apps always carry one; skip a malformed row rather than group under None
            continue
        o = out.setdefault(app.owner_org_id, OwnerOrg(app.owner_org_id))
        o.names |= {n for n in (app.verified_publisher_name, app.publisher_name, app.display_name) if n}
        o.domains |= set(app.reply_url_domains or [])
        if app.homepage:
            from .vendor_matching import host_of

            h = host_of(app.homepage)
            if h:
                o.domains.add(h)
        o.apps.append(app)
        tid = app.snapshot.tenant_id
        o.level_by_tenant[tid] = worst([o.level_by_tenant.get(tid), app.exposure.exposure_level if app.exposure else None])
    return out


def mappings(session: Session) -> dict[str, VendorAppMapping]:
    return {m.owner_org_id: m for m in session.scalars(select(VendorAppMapping))}


def vendor_presence(session: Session, vendor_id: int) -> dict[str, str]:
    """{tenant name: worst exposure level} for a vendor, via confirmed owner-org mappings."""
    confirmed = {m.owner_org_id for m in mappings(session).values() if m.vendor_id == vendor_id and m.status == "confirmed"}
    names = {t.id: t.name for t in session.scalars(select(EntraTenant))}
    out: dict[str, str] = {}
    for oid, org in owner_orgs(session).items():
        if oid in confirmed:
            for tid, level in org.level_by_tenant.items():
                lv = worst([out.get(names[tid]), level])
                if lv:
                    out[names[tid]] = lv
    return out
