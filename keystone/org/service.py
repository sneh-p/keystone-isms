from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.db import utcnow
from keystone.core.services import apply_fields, authorize, get_or_404, require_text

from .models import InterestedParty, IsmsRoleAssignment, Organisation, SecurityObjective

ORG_FIELDS = {
    "name", "legal_name", "industry", "description", "internal_issues", "external_issues",
    "scope_statement", "scope_inclusions", "scope_exclusions", "scope_interfaces", "risk_appetite",
}
SCOPE_FIELDS = {"scope_statement", "scope_inclusions", "scope_exclusions", "scope_interfaces"}
OBJECTIVE_STATUSES = ("on_track", "at_risk", "achieved", "missed")


def get_org(session: Session) -> Organisation | None:
    return session.scalar(select(Organisation).limit(1))


def save_org(session: Session, actor, **fields) -> Organisation:
    authorize(session, actor, "org.write")
    org = get_org(session)
    if org is None:
        org = Organisation(name=require_text(fields.get("name"), "Organisation name"))
        session.add(org)
    if SCOPE_FIELDS & set(fields) and any(getattr(org, f) != fields[f] for f in SCOPE_FIELDS & set(fields)):
        # Changing the scope invalidates its approval.
        org.scope_approved_by_id = None
        org.scope_approved_at = None
    apply_fields(org, fields, ORG_FIELDS)
    session.flush()
    return org


def approve_scope(session: Session, actor) -> Organisation:
    authorize(session, actor, "org.write")
    org = get_org(session)
    if org is None or not (org.scope_statement or "").strip():
        raise ValueError("Write the ISMS scope statement before approving it.")
    org.scope_approved_by_id = actor.id
    org.scope_approved_at = utcnow()
    session.flush()
    return org


def add_interested_party(session: Session, actor, **fields) -> InterestedParty:
    authorize(session, actor, "org.write")
    require_text(fields.get("name"), "Name")
    if fields.get("party_type", "external") not in ("internal", "external"):
        raise ValueError("party_type must be internal or external")
    p = InterestedParty()
    apply_fields(p, fields, {"name", "party_type", "needs", "addressed_by"})
    session.add(p)
    session.flush()
    return p


def add_isms_role(session: Session, actor, **fields) -> IsmsRoleAssignment:
    authorize(session, actor, "org.write")
    require_text(fields.get("title"), "Role title")
    r = IsmsRoleAssignment()
    apply_fields(r, fields, {"title", "responsibilities", "user_id", "deputy_user_id"})
    session.add(r)
    session.flush()
    return r


def save_objective(session: Session, actor, objective_id: int | None = None, **fields) -> SecurityObjective:
    authorize(session, actor, "org.write")
    obj = get_or_404(session, SecurityObjective, objective_id) if objective_id else SecurityObjective()
    if "status" in fields and fields["status"] not in OBJECTIVE_STATUSES:
        raise ValueError(f"status must be one of {OBJECTIVE_STATUSES}")
    apply_fields(obj, fields, {"title", "measure", "target", "current_value", "owner_id", "due_date", "status"})
    require_text(obj.title, "Objective title")
    session.add(obj)
    session.flush()
    return obj


def delete_record(session: Session, actor, model, obj_id: int) -> None:
    authorize(session, actor, "org.write")
    session.delete(get_or_404(session, model, obj_id))
    session.flush()
