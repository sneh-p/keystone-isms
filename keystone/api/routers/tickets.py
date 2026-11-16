"""Tickets in outside ticketing systems, linked to Keystone records."""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.integrations.http import ConnectorError
from keystone.ticketing import service as tk

from ..deps import get_db, perm
from .common import In

router = APIRouter(prefix="/tickets", tags=["tickets"])
KIND = "^(task|nonconformity|incident|risk|asm_finding|vulnerability)$"


@router.get("/systems")
def systems(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return tk.systems(db, user)


@router.get("")
def links(kind: str = Query(pattern=KIND), ids: str = Query(max_length=8000, pattern=r"^\d+(,\d+)*$"), user=Depends(perm("read")), db: Session = Depends(get_db)):
    return tk.links(db, user, kind, [int(x) for x in ids.split(",")])


class TicketIn(In):
    integration_id: int
    kind: str = Field(pattern=KIND)
    record_id: int


# perm("read") here; the service requires the write permission for the kind of record (task.write, nc.write, ...).
@router.post("")
def create(body: TicketIn, user=Depends(perm("read")), db: Session = Depends(get_db)):
    try:
        link = tk.create_ticket(db, user, body.integration_id, body.kind, body.record_id)
    except ConnectorError as e:
        raise HTTPException(502, f"The ticketing system refused: {e}") from None
    return {"id": link.id, "key": link.external_key, "url": link.url}
