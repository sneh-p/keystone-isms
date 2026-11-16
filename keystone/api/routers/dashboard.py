from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from keystone.org.service import get_org
from keystone.reporting import dashboard, registers

from ..deps import get_db, perm
from .common import xlsx_response

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard")
def overview(user=Depends(perm("read")), db: Session = Depends(get_db)):
    o = get_org(db)
    ov = dashboard.overview(db)
    ov["coverage"] = [{"name": n, **c} for n, c in ov["coverage"]]
    return {"org": {"name": o.name, "scope_approved": bool(o.scope_approved_at)} if o else None, **ov, "my_tasks": dashboard.my_tasks(db, user)}


@router.get("/reports")
def reports(user=Depends(perm("read"))):
    from keystone.core.rbac import has_permission

    return list(registers.REGISTERS) + (["Audit log"] if has_permission(user, "audit_log.view") else [])


@router.get("/reports/{name}.xlsx")
def export(name: str, user=Depends(perm("read")), db: Session = Depends(get_db)):
    if name not in registers.REGISTERS and name != "Audit log":
        raise LookupError("Unknown report")
    o = get_org(db)
    return xlsx_response(registers.export(db, user, name, o.name if o else ""), f"{name.replace(' ', '_')}.xlsx")
