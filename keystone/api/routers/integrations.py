from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.services import get_or_404
from keystone.integrations import service as integ
from keystone.integrations.models import Integration

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(tags=["integrations"])
INT = ("id", "provider", "name", "enabled", "config", "schedule_hours", "last_run_at", "last_status", "last_error")


def out(db, i: Integration) -> dict:
    # Secrets are write-only: only whether one is stored is returned.
    return ser(i, INT, secret_set=bool(i.secret_enc), results=[ser(r, ("check_key", "title", "result", "summary", "details", "controls", "run_at")) for r in integ.latest_results(db, i.id)])


@router.get("/integrations")
def catalog(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return {"providers": [p.describe() for p in integ.PROVIDERS.values()], "integrations": [out(db, i) for i in db.scalars(select(Integration).order_by(Integration.name))]}


class IntegrationIn(In):
    provider: str | None = None
    name: str | None = None
    values: dict = {}
    schedule_hours: int | None = None
    enabled: bool | None = None


@router.post("/integrations")
def create(body: IntegrationIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return out(db, integ.save_integration(db, user, provider_key=body.provider, name=body.name, values=body.values, schedule_hours=body.schedule_hours))


@router.patch("/integrations/{iid}")
def update(iid: int, body: IntegrationIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return out(db, integ.save_integration(db, user, iid, name=body.name, values=body.values, schedule_hours=body.schedule_hours, enabled=body.enabled))


@router.post("/integrations/{iid}/run")
def run(iid: int, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    integ.run(db, user, iid)
    return out(db, get_or_404(db, Integration, iid))


@router.get("/integrations/{iid}/history")
def history(iid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [ser(r, ("check_key", "title", "result", "summary", "run_at")) for r in integ.history(db, iid)]
