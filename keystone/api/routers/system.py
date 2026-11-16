"""System health for administrators: scheduled jobs, backups, database and virus scanner; on-demand backups."""

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from keystone.ops import health
from keystone.ops import service as ops

from ..deps import get_db, perm

router = APIRouter(tags=["system"])


@router.get("/system/health")
def system_health(user=Depends(perm("users.manage")), db: Session = Depends(get_db)):
    return health.system_health(db, user)


@router.post("/system/backups", status_code=202)
def run_backup(background: BackgroundTasks, user=Depends(perm("users.manage")), db: Session = Depends(get_db)):
    try:
        ops.check_can_backup(db, user)
    except ops.BackupBusy as e:
        raise HTTPException(409, str(e)) from None
    db.commit()  # release this request's write lock (session activity) before the backup opens its own sessions
    background.add_task(_backup_in_background, user)
    return {"status": "started"}


def _backup_in_background(user) -> None:
    try:
        ops.run_backup(user)
    except ops.BackupBusy:
        return  # another run started in between; its result shows under System health
