"""Declared registers (keystone/registers/spec.py). Every route needs a signed-in staff user; each register's own read
and write permissions, and each workflow step's permission, are checked in the service (SC-AUTHZ-001)."""

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.registers import service as reg

from ..deps import get_db, perm
from .common import In

router = APIRouter(prefix="/registers", tags=["registers"])


def out(e) -> dict:
    return {"id": e.id, "ref": e.ref, "register": e.register, "title": e.title, "status": e.status, "owner_id": e.owner_id, "person_id": e.person_id,
            "due_on": e.due_on, "data": e.data or {}, "decisions": e.decisions or [], "created_by_id": e.created_by_id, "created_at": e.created_at, "updated_at": e.updated_at}


@router.get("")
def registers(user=Depends(perm("read"))):
    return [reg.spec_out(r, user) for r in reg.readable(user)]


@router.get("/{key}")
def register(key: str, user=Depends(perm("read")), db: Session = Depends(get_db)):
    rows = reg.entries(db, user, key)
    return {"register": reg.spec_out(reg.spec(key), user), "entries": [out(e) for e in rows]}


class EntryIn(In):
    title: str | None = Field(None, max_length=300)
    owner_id: int | None = None
    fields: dict[str, Any] = Field(default_factory=dict, max_length=40)


def _values(body: EntryIn) -> dict:
    v = dict(body.fields)
    for k in ("title", "owner_id"):
        if k in body.model_fields_set:
            v[k] = getattr(body, k)
    return v


@router.post("/{key}")
def create_entry(key: str, body: EntryIn, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return out(reg.save(db, user, key, **_values(body)))


@router.patch("/{key}/{eid}")
def update_entry(key: str, eid: int, body: EntryIn, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return out(reg.save(db, user, key, eid, **_values(body)))


class MoveIn(In):
    to: str = Field(max_length=30)
    note: str | None = Field(None, max_length=2000)


@router.post("/{key}/{eid}/move")
def move_entry(key: str, eid: int, body: MoveIn, user=Depends(perm("read")), db: Session = Depends(get_db)):
    r, e = reg.entry(db, user, eid)
    if r.key != key:
        raise LookupError("Not found")
    return out(reg.move(db, user, eid, body.to, body.note))


@router.delete("/{key}/{eid}")
def delete_entry(key: str, eid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    r, e = reg.entry(db, user, eid)
    if r.key != key:
        raise LookupError("Not found")
    reg.delete(db, user, eid)
    return {"ok": True}
