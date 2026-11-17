from datetime import date

from fastapi import APIRouter, Depends
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.core.rbac import has_permission
from keystone.org.service import get_org
from keystone.reporting import dashboard, imports, registers

from ..deps import get_db, perm
from ..serialize import ser
from .common import In, xlsx_response

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard")
def overview(user=Depends(perm("read")), db: Session = Depends(get_db)):
    o = get_org(db)
    ov = dashboard.overview(db)
    current = dashboard.metrics(db, ov=ov)
    ov["coverage"] = [{"name": n, **c} for n, c in ov["coverage"]]
    return {
        "org": {"name": o.name, "scope_approved": bool(o.scope_approved_at)} if o else None, **ov,
        "my_tasks": dashboard.my_tasks(db, user),
        "next_steps": dashboard.next_steps(db) if has_permission(user, "control.write") else [],
        "trend": dashboard.trend(db, current),
    }


@router.get("/reports")
def reports(user=Depends(perm("read"))):
    return list(registers.REGISTERS) + (["Audit log"] if has_permission(user, "audit_log.view") else [])


@router.get("/reports/{name}.xlsx")
def export(name: str, user=Depends(perm("read")), db: Session = Depends(get_db)):
    if name not in registers.REGISTERS and name != "Audit log":
        raise LookupError("Unknown report")
    o = get_org(db)
    return xlsx_response(registers.export(db, user, name, o.name if o else ""), f"{name.replace(' ', '_')}.xlsx")


# ---- CSV import (rows parsed in the browser; see keystone/reporting/imports.py) -----------------------

class ImportIn(In):
    rows: list[dict[str, str | None]] = Field(min_length=1, max_length=imports.MAX_ROWS)
    preview: bool = True


def _import_route(name: str, permission: str):
    def spec(user=Depends(perm(permission))):
        return imports.spec(name)

    def run(body: ImportIn, user=Depends(perm(permission)), db: Session = Depends(get_db)):
        if body.preview:
            db.commit()  # release this request's write lock (SQLite) before the dry-run transaction
            return imports.preview(user, name, body.rows)
        return imports.commit(db, user, name, body.rows)

    router.add_api_route(f"/import/{name}", spec, methods=["GET"], name=f"import_spec_{name}")
    router.add_api_route(f"/import/{name}", run, methods=["POST"], name=f"import_{name}")


for _name, _reg in imports.all_registers().items():
    _import_route(_name, _reg.permission)


# ---- scheduled report emails (org.write) ------------------------------------------------------------------------

SCHEDULE = ("id", "name", "report", "frequency", "recipient_ids", "next_run_on", "enabled", "last_sent_at", "last_error", "created_by_id")


@router.get("/report-schedules")
def report_schedules(user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    from keystone.reporting import schedules as sch

    return {"reports": sch.reports(), "schedules": [ser(s, SCHEDULE) for s in sch.schedules(db, user)]}


class ScheduleIn(In):
    name: str | None = Field(default=None, max_length=150)
    report: str | None = Field(default=None, max_length=100)
    frequency: str | None = Field(default=None, pattern="^(weekly|monthly|quarterly)$")
    recipient_ids: list[int] | None = Field(default=None, max_length=25)
    next_run_on: date | None = None
    enabled: bool | None = None


@router.post("/report-schedules")
def create_schedule(body: ScheduleIn, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    from keystone.reporting import schedules as sch

    return ser(sch.save(db, user, **body.model_dump(exclude_unset=True)), SCHEDULE)


@router.patch("/report-schedules/{sid}")
def update_schedule(sid: int, body: ScheduleIn, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    from keystone.reporting import schedules as sch

    return ser(sch.save(db, user, sid, **body.model_dump(exclude_unset=True)), SCHEDULE)


@router.delete("/report-schedules/{sid}")
def delete_schedule(sid: int, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    from keystone.reporting import schedules as sch

    sch.delete(db, user, sid)
    return {"ok": True}


@router.post("/report-schedules/{sid}/send")
def send_schedule(sid: int, user=Depends(perm("org.write")), db: Session = Depends(get_db)):
    from keystone.reporting import schedules as sch

    return ser(sch.send_now(db, user, sid), SCHEDULE)
