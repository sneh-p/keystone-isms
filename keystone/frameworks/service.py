"""Queries over frameworks, controls and the crosswalk."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from .models import CommonControl, ControlMapping, Framework, Requirement


def frameworks(session: Session, enabled_only: bool = True) -> list[Framework]:
    q = select(Framework).order_by(Framework.name)
    if enabled_only:
        q = q.where(Framework.enabled.is_(True))
    return list(session.scalars(q))


def framework_by_code(session: Session, code: str) -> Framework | None:
    return session.scalar(select(Framework).where(Framework.code == code))


def controls(session: Session) -> list[CommonControl]:
    return list(session.scalars(select(CommonControl).order_by(CommonControl.code).options(selectinload(CommonControl.mappings).selectinload(ControlMapping.requirement).selectinload(Requirement.framework))))


def control_by_code(session: Session, code: str) -> CommonControl | None:
    return session.scalar(select(CommonControl).where(CommonControl.code == code))


def requirements_for_control(control: CommonControl) -> dict[str, list[Requirement]]:
    """{framework_code: [requirements]} satisfied (in part) by this control."""
    out: dict[str, list[Requirement]] = {}
    for m in control.mappings:
        out.setdefault(m.requirement.framework.code, []).append(m.requirement)
    for reqs in out.values():
        reqs.sort(key=lambda r: r.sort_order)
    return out


def controls_for_requirement(session: Session, requirement_id: int) -> list[CommonControl]:
    q = select(CommonControl).join(ControlMapping).where(ControlMapping.requirement_id == requirement_id).order_by(CommonControl.code)
    return list(session.scalars(q))


def leaf_requirements(session: Session, framework_id: int) -> list[Requirement]:
    q = select(Requirement).where(Requirement.framework_id == framework_id, Requirement.is_leaf.is_(True)).order_by(Requirement.sort_order).options(selectinload(Requirement.mappings).selectinload(ControlMapping.control))
    return list(session.scalars(q))


@dataclass
class CoverageRow:
    requirement: Requirement
    controls: list[CommonControl]
    status: str  # implemented | partial | not_implemented | not_applicable | unmapped


def derive_status(statuses: list[str]) -> str:
    """Requirement status from its mapped controls' implementation statuses."""
    if not statuses:
        return "unmapped"
    applicable = [s for s in statuses if s != "not_applicable"]
    if not applicable:
        return "not_applicable"
    if all(s == "implemented" for s in applicable):
        return "implemented"
    if any(s in ("implemented", "partial") for s in applicable):
        return "partial"
    return "not_implemented"


def coverage(session: Session, framework_id: int) -> list[CoverageRow]:
    rows = []
    for req in leaf_requirements(session, framework_id):
        ctls = sorted((m.control for m in req.mappings), key=lambda c: c.code)
        rows.append(CoverageRow(req, ctls, derive_status([c.status for c in ctls])))
    return rows


def coverage_summary(rows: list[CoverageRow]) -> dict:
    counts: dict[str, int] = {}
    for r in rows:
        counts[r.status] = counts.get(r.status, 0) + 1
    applicable = len(rows) - counts.get("not_applicable", 0)
    implemented = counts.get("implemented", 0)
    partial = counts.get("partial", 0)
    return {
        "total": len(rows),
        "applicable": applicable,
        "counts": counts,
        "implemented_pct": round(100 * implemented / applicable, 1) if applicable else 0.0,
        "progress_pct": round(100 * (implemented + 0.5 * partial) / applicable, 1) if applicable else 0.0,
    }


def add_user_mapping(session: Session, actor, control_id: int, requirement_id: int) -> ControlMapping:
    from keystone.core.services import authorize

    authorize(session, actor, "framework.write")
    existing = session.scalar(select(ControlMapping).where(ControlMapping.common_control_id == control_id, ControlMapping.requirement_id == requirement_id))
    if existing:
        return existing
    req = session.get(Requirement, requirement_id)
    if req is None or not req.is_leaf:
        raise ValueError("Map controls to individual requirements, not groupings.")
    m = ControlMapping(common_control_id=control_id, requirement_id=requirement_id, source="user")
    session.add(m)
    session.flush()
    return m


def remove_mapping(session: Session, actor, mapping_id: int) -> None:
    from keystone.core.services import authorize

    authorize(session, actor, "framework.write")
    m = session.get(ControlMapping, mapping_id)
    if m:
        session.delete(m)
        session.flush()


def set_framework_enabled(session: Session, actor, framework_id: int, enabled: bool) -> None:
    from keystone.core.services import authorize

    authorize(session, actor, "framework.write")
    session.get(Framework, framework_id).enabled = enabled
    session.flush()
