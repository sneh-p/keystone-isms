from datetime import date

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.org import service as org
from keystone.org.models import InterestedParty, IsmsRoleAssignment, SecurityObjective

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(prefix="/org", tags=["organisation"])
ORG_OUT = tuple(sorted(org.ORG_FIELDS)) + ("scope_approved_by_id", "scope_approved_at")


class OrgIn(In):
    name: str | None = None
    legal_name: str | None = None
    industry: str | None = None
    description: str | None = None
    internal_issues: str | None = None
    external_issues: str | None = None
    scope_statement: str | None = None
    scope_inclusions: str | None = None
    scope_exclusions: str | None = None
    scope_interfaces: str | None = None
    risk_appetite: str | None = None


class PartyIn(In):
    name: str
    party_type: str = "external"
    needs: str | None = None
    addressed_by: str | None = None


class RoleIn(In):
    title: str
    responsibilities: str | None = None
    user_id: int | None = None
    deputy_user_id: int | None = None


class ObjectiveIn(In):
    title: str | None = None
    measure: str | None = None
    target: str | None = None
    current_value: str | None = None
    owner_id: int | None = None
    due_date: date | None = None
    status: str | None = None


@router.get("")
def get_org(user=Depends(perm("read")), db: Session = Depends(get_db)):
    o = org.get_org(db)
    return ser(o, ORG_OUT) if o else None


@router.put("")
def save_org(body: OrgIn, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    fields = body.model_dump(exclude_unset=True)
    current = org.get_org(db)
    if current and "name" not in fields:
        fields["name"] = current.name
    return ser(org.save_org(db, user, **fields), ORG_OUT)


@router.post("/approve-scope")
def approve_scope(user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    return ser(org.approve_scope(db, user), ORG_OUT)


@router.get("/parties")
def parties(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [ser(p, ("id", "name", "party_type", "needs", "addressed_by")) for p in db.scalars(select(InterestedParty).order_by(InterestedParty.name))]


@router.post("/parties")
def add_party(body: PartyIn, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    return ser(org.add_interested_party(db, user, **body.model_dump()), ("id", "name"))


@router.delete("/parties/{pid}")
def del_party(pid: int, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    org.delete_record(db, user, InterestedParty, pid)
    return {"ok": True}


@router.get("/roles")
def isms_roles(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [ser(r, ("id", "title", "responsibilities", "user_id", "deputy_user_id")) for r in db.scalars(select(IsmsRoleAssignment).order_by(IsmsRoleAssignment.title))]


@router.post("/roles")
def add_role(body: RoleIn, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    return ser(org.add_isms_role(db, user, **body.model_dump()), ("id", "title"))


@router.delete("/roles/{rid}")
def del_role(rid: int, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    org.delete_record(db, user, IsmsRoleAssignment, rid)
    return {"ok": True}


OBJ = ("id", "title", "measure", "target", "current_value", "owner_id", "due_date", "status")


@router.get("/objectives")
def objectives(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [ser(o, OBJ) for o in db.scalars(select(SecurityObjective).order_by(SecurityObjective.due_date))]


@router.post("/objectives")
def add_objective(body: ObjectiveIn, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    return ser(org.save_objective(db, user, None, **body.model_dump(exclude_unset=True)), OBJ)


@router.patch("/objectives/{oid}")
def edit_objective(oid: int, body: ObjectiveIn, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    return ser(org.save_objective(db, user, oid, **body.model_dump(exclude_unset=True)), OBJ)


# ---- deleting records created in error (keystone/core/deletion.py: refused while anything depends on them)


@router.delete("/objectives/{oid}")
def delete_objective(oid: int, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    from keystone.core.deletion import delete_record

    delete_record(db, user, "objective", oid)
    return {"ok": True}
