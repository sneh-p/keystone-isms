from __future__ import annotations

from datetime import date

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.db import utcnow
from keystone.core.services import apply_fields, authorize, get_or_404, require_text, today

from .models import NC_SEVERITIES, NC_SOURCES, CorrectiveAction, Nonconformity

NC_FIELDS = {"title", "description", "source", "severity", "requirement_id", "common_control_id", "incident_id", "owner_id", "containment", "root_cause", "due_date"}


def raise_nc(session: Session, actor, **fields) -> Nonconformity:
    """Anyone who can write NCs, or record audit findings, may raise one."""
    from keystone.core.rbac import has_permission

    authorize(session, actor, "nc.write" if has_permission(actor, "nc.write") else "audit.findings")
    nc = Nonconformity(status="open", source="self_identified", severity="minor")
    apply_fields(nc, fields, NC_FIELDS)
    _validate(nc)
    session.add(nc)
    session.flush()
    return nc


def _validate(nc: Nonconformity) -> None:
    require_text(nc.title, "Title")
    if nc.source not in NC_SOURCES:
        raise ValueError(f"source must be one of {NC_SOURCES}")
    if nc.severity not in NC_SEVERITIES:
        raise ValueError(f"severity must be one of {NC_SEVERITIES}")


def update_nc(session: Session, actor, nc_id: int, **fields) -> Nonconformity:
    authorize(session, actor, "nc.write")
    nc = get_or_404(session, Nonconformity, nc_id)
    if nc.status == "closed":
        raise ValueError("Closed nonconformities cannot be edited.")
    apply_fields(nc, fields, NC_FIELDS - {"source"})
    _validate(nc)
    session.flush()
    return nc


def add_action(session: Session, actor, nc_id: int, description: str, owner_id: int | None = None, due_date: date | None = None) -> CorrectiveAction:
    authorize(session, actor, "nc.write")
    nc = get_or_404(session, Nonconformity, nc_id)
    if nc.status == "closed":
        raise ValueError("The nonconformity is closed.")
    ca = CorrectiveAction(nonconformity=nc, description=require_text(description, "Action"), owner_id=owner_id, due_date=due_date, status="open")
    session.add(ca)
    session.flush()
    return ca


def plan(session: Session, actor, nc_id: int) -> Nonconformity:
    authorize(session, actor, "nc.write")
    nc = get_or_404(session, Nonconformity, nc_id)
    if nc.status != "open":
        raise ValueError("Only open nonconformities can move to action planned.")
    if not (nc.root_cause or "").strip():
        raise ValueError("Record the root cause first.")
    if not [a for a in nc.actions if a.status in ("open", "done")]:
        raise ValueError("Add at least one corrective action first.")
    nc.status = "action_planned"
    session.flush()
    return nc


def complete_action(session: Session, actor, action_id: int, notes: str) -> CorrectiveAction:
    authorize(session, actor, "nc.write")
    ca = get_or_404(session, CorrectiveAction, action_id)
    if ca.status != "open":
        raise ValueError("Only open actions can be completed.")
    ca.status, ca.completed_at, ca.completion_notes = "done", utcnow(), require_text(notes, "What was done")
    nc = ca.nonconformity
    if nc.status == "action_planned" and all(a.status in ("done", "verified", "ineffective") for a in nc.actions):
        nc.status = "verification"
    session.flush()
    return ca


def verify_action(session: Session, actor, action_id: int, effective: bool, notes: str) -> CorrectiveAction:
    """Effectiveness check (ISO 27001 10.2 d). The verifier must not be the action owner."""
    authorize(session, actor, "nc.verify")
    ca = get_or_404(session, CorrectiveAction, action_id)
    if ca.status != "done":
        raise ValueError("Only completed actions can be verified.")
    if ca.owner_id == actor.id:
        raise ValueError("Segregation of duties: the action owner cannot verify their own action.")
    ca.status = "verified" if effective else "ineffective"
    ca.verified_by_id, ca.verified_at, ca.effectiveness_notes = actor.id, utcnow(), require_text(notes, "Effectiveness evidence")
    nc = ca.nonconformity
    if not effective:
        nc.status = "open"  # needs a new action and re-planning
    session.flush()
    return ca


def close(session: Session, actor, nc_id: int) -> Nonconformity:
    authorize(session, actor, "nc.verify")
    nc = get_or_404(session, Nonconformity, nc_id)
    if nc.status != "verification":
        raise ValueError("Only nonconformities in verification can be closed.")
    live = [a for a in nc.actions if a.status != "ineffective"]
    if not live or any(a.status != "verified" for a in live):
        raise ValueError("Every corrective action must be verified as effective before closing.")
    nc.status, nc.closed_at, nc.closed_by_id = "closed", utcnow(), actor.id
    session.flush()
    return nc


def list_ncs(session: Session, include_closed: bool = True) -> list[Nonconformity]:
    q = select(Nonconformity).order_by(Nonconformity.id.desc())
    if not include_closed:
        q = q.where(Nonconformity.status != "closed")
    return list(session.scalars(q))


def nc_attention(session: Session, on: date | None = None) -> dict[str, list]:
    on = on or today()
    ncs = list_ncs(session, include_closed=False)
    return {
        "open": ncs,
        "overdue": [n for n in ncs if n.due_date and n.due_date < on],
        "actions_overdue": [a for n in ncs for a in n.actions if a.status == "open" and a.due_date and a.due_date < on],
        "awaiting_verification": [a for n in ncs for a in n.actions if a.status == "done"],
    }
