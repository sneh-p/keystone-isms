"""Slack, Teams and webhook destinations (integration.manage). URLs and signing secrets are write-only."""

from fastapi import APIRouter, Depends
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.outbound import service as ob

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(prefix="/outbound", tags=["outbound"])
DEST = ("id", "kind", "name", "url_host", "events", "enabled", "last_status", "last_error", "last_sent_at")
DELIVERY = ("id", "uid", "event", "status", "attempts", "next_attempt_at", "last_error", "created_at", "sent_at")


@router.get("/destinations")
def destinations(user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return {"events": ob.EVENTS, "destinations": [ser(d, DEST, signed=d.kind == "webhook") for d in ob.destinations(db, user)]}


class DestinationIn(In):
    kind: str | None = Field(default=None, pattern="^(slack|teams|webhook)$")
    name: str | None = Field(default=None, max_length=100)
    url: str | None = Field(default=None, max_length=2000)  # write-only
    events: list[str] | None = Field(default=None, max_length=20)
    enabled: bool | None = None


@router.post("/destinations")
def create(body: DestinationIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    d, secret = ob.save_destination(db, user, **body.model_dump(exclude_unset=True))
    return {**ser(d, DEST), **({"signing_secret": secret} if secret else {})}  # the secret is shown once


@router.patch("/destinations/{did}")
def update(did: int, body: DestinationIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    fields = body.model_dump(exclude_unset=True)
    fields.pop("kind", None)  # the kind of a destination can't change
    d, _ = ob.save_destination(db, user, did, **fields)
    return ser(d, DEST)


@router.delete("/destinations/{did}")
def delete(did: int, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    ob.delete_destination(db, user, did)
    return {"ok": True}


@router.post("/destinations/{did}/test")
def test(did: int, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return ser(ob.test_destination(db, user, did), DELIVERY)


@router.get("/destinations/{did}/deliveries")
def deliveries(did: int, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return [ser(x, DELIVERY) for x in ob.recent(db, user, did)]
