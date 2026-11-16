"""Frameworks, controls, evidence, Statement of Applicability."""

from datetime import date

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from fastapi.responses import Response
from pydantic import Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from keystone.controls import service as ctl
from keystone.controls.models import Evidence
from keystone.core.attachments import Attachment, read_attachment
from keystone.core.services import get_or_404
from keystone.frameworks import loader, service as fw
from keystone.frameworks.models import CommonControl, Framework, STATUS_LABELS
from keystone.org.service import get_org
from keystone.reporting import exports
from keystone.risk.models import Risk, risk_controls
from keystone.tasks import service as tsk

from ..deps import get_db, perm
from ..serialize import ser
from .common import In, docx_response, xlsx_response

router = APIRouter(tags=["compliance"])


# ---- frameworks --------------------------------------------------------------------

@router.get("/frameworks")
def frameworks(all: bool = False, user=Depends(perm("read")), db: Session = Depends(get_db)):
    out = []
    for f in fw.frameworks(db, enabled_only=not all):
        out.append(ser(f, ("id", "code", "name", "version", "publisher", "license", "text_level", "notice", "enabled"), coverage=fw.coverage_summary(fw.coverage(db, f.id))))
    return out


@router.post("/frameworks/seed")
def seed(user=Depends(perm("framework.write")), db: Session = Depends(get_db)):
    return loader.seed_content(db, user)


class EnabledIn(In):
    enabled: bool


@router.patch("/frameworks/{code}")
def set_enabled(code: str, body: EnabledIn, user=Depends(perm("framework.write")), db: Session = Depends(get_db)):
    f = fw.framework_by_code(db, code)
    if f is None:
        raise LookupError(f"Framework {code} not found")
    fw.set_framework_enabled(db, user, f.id, body.enabled)
    return {"ok": True}


@router.get("/frameworks/{code}/requirements")
def requirements(code: str, user=Depends(perm("read")), db: Session = Depends(get_db)):
    f = fw.framework_by_code(db, code)
    if f is None:
        raise LookupError(f"Framework {code} not found")
    rows = fw.coverage(db, f.id)
    groups = [ser(r, ("id", "ref", "title", "description", "parent_ref", "kind")) for r in f.requirements if not r.is_leaf]
    return {
        "framework": ser(f, ("id", "code", "name", "version", "license", "notice")),
        "summary": fw.coverage_summary(rows),
        "groups": groups,
        "requirements": [
            {"id": r.requirement.id, "ref": r.requirement.ref, "parent_ref": r.requirement.parent_ref, "title": r.requirement.title, "description": r.requirement.description, "has_licensed_text": bool(r.requirement.licensed_text), "status": r.status, "controls": [{"id": c.id, "code": c.code, "title": c.title, "status": c.status} for c in r.controls]}
            for r in rows
        ],
    }


@router.post("/frameworks/{code}/licensed-text")
async def licensed_text(code: str, file: UploadFile = File(...), user=Depends(perm("framework.write")), db: Session = Depends(get_db)):
    rows = loader.parse_licensed_file(file.filename or "x.csv", await file.read())
    return loader.import_licensed_text(db, user, code, rows)


# ---- controls ------------------------------------------------------------------------

CONTROL = ("id", "code", "domain", "title", "description", "status", "owner_id", "implementation_notes", "na_justification", "review_interval_days", "last_reviewed_at", "next_review_date")


def control_summary(c: CommonControl) -> dict:
    fws = fw.requirements_for_control(c)
    return ser(c, CONTROL, status_label=STATUS_LABELS[c.status], frameworks={k: [r.ref for r in v] for k, v in fws.items()})


@router.get("/controls")
def controls(user=Depends(perm("read")), db: Session = Depends(get_db)):
    att = ctl.control_attention(db)
    no_ev = {c.id for c in att["implemented_without_evidence"]}
    overdue = {c.id for c in att["review_overdue"]}
    current: dict[int, int] = {}
    for e in db.scalars(select(Evidence).where(Evidence.superseded.is_(False))):
        if ctl.evidence_state(e) in ("current", "expiring"):
            current[e.common_control_id] = current.get(e.common_control_id, 0) + 1
    out = []
    for c in fw.controls(db):
        d = control_summary(c)
        d["needs_evidence"] = c.id in no_ev
        d["review_overdue"] = c.id in overdue
        d["evidence_current"] = current.get(c.id, 0)
        d["readiness"] = tsk.control_readiness(db, c).score if c.status != "not_applicable" else None
        out.append(d)
    return out


@router.get("/controls/{cid}")
def control(cid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    c = get_or_404(db, CommonControl, cid)
    d = control_summary(c)
    d["requirements"] = {k: [{"ref": r.ref, "title": r.title} for r in v] for k, v in fw.requirements_for_control(c).items()}
    d["evidence"] = [evidence_out(e) for e in ctl.evidence_for(db, cid)]
    d["risks"] = [{"id": r.id, "ref": r.ref, "title": r.title, "status": r.status} for r in db.query(Risk).join(risk_controls).filter(risk_controls.c.common_control_id == cid)]
    return d


class ControlPatch(In):
    status: str | None = None
    owner_id: int | None = None
    implementation_notes: str | None = None
    na_justification: str | None = None
    review_interval_days: int | None = None


@router.patch("/controls/{cid}")
def update_control(cid: int, body: ControlPatch, user=Depends(perm("control.write")), db: Session = Depends(get_db)):
    return control_summary(ctl.update_control(db, user, cid, **body.model_dump(exclude_unset=True)))


class ControlBulkIn(In):
    ids: list[int] = Field(min_length=1, max_length=500)
    status: str | None = None
    owner_id: int | None = None


@router.post("/controls/bulk")
def bulk_update_controls(body: ControlBulkIn, user=Depends(perm("control.write")), db: Session = Depends(get_db)):
    return {"updated": len(ctl.bulk_update_controls(db, user, body.ids, **body.model_dump(exclude_unset=True, exclude={"ids"})))}


@router.post("/controls/{cid}/review")
def review_control(cid: int, user=Depends(perm("control.write")), db: Session = Depends(get_db)):
    return control_summary(ctl.review_control(db, user, cid))


# ---- evidence ------------------------------------------------------------------------

def evidence_out(e) -> dict:
    return ser(e, ("id", "common_control_id", "title", "kind", "description", "attachment_id", "url", "collected_on", "valid_until", "reviewed_by_id", "reviewed_at", "superseded", "created_by_id"), state=ctl.evidence_state(e))


@router.get("/evidence")
def evidence(response: Response, limit: int = Query(1000, ge=1, le=5000), offset: int = Query(0, ge=0, le=1_000_000), user=Depends(perm("read")), db: Session = Depends(get_db)):
    # SC-ERR-004 / SC-CFG-004: bounded page; the total lets the UI say when the list is truncated.
    response.headers["X-Total-Count"] = str(db.scalar(select(func.count(Evidence.id))))
    return [evidence_out(e) for e in ctl.evidence_for(db, limit=limit, offset=offset)]


@router.post("/evidence")
async def add_evidence(
    control_id: int = Form(...), title: str = Form(..., max_length=300), kind: str = Form(..., max_length=20), description: str | None = Form(None, max_length=20_000), url: str | None = Form(None, max_length=2048),
    collected_on: date | None = Form(None), valid_until: date | None = Form(None), file: UploadFile | None = File(None),
    user=Depends(perm("evidence.write")), db: Session = Depends(get_db),
):
    data = await file.read() if file else None
    e = ctl.add_evidence(db, user, control_id, title=title, kind=kind, description=description, url=url, collected_on=collected_on, valid_until=valid_until, filename=file.filename if file else None, data=data)
    return evidence_out(e)


class EvReview(In):
    superseded: bool = False


@router.post("/evidence/{eid}/review")
def review_evidence(eid: int, body: EvReview, user=Depends(perm("evidence.write")), db: Session = Depends(get_db)):
    return evidence_out(ctl.review_evidence(db, user, eid, body.superseded))


@router.get("/attachments/{aid}")
def download(aid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    a = get_or_404(db, Attachment, aid)
    safe = a.filename.replace('"', "")
    return Response(read_attachment(a), media_type=a.content_type, headers={"Content-Disposition": f'attachment; filename="{safe}"', "X-Content-Type-Options": "nosniff"})


# ---- SoA ---------------------------------------------------------------------------

def _fw(db, code) -> Framework:
    f = fw.framework_by_code(db, code)
    if f is None:
        raise LookupError(f"Framework {code} not found")
    return f


@router.get("/soa/{code}")
def soa(code: str, user=Depends(perm("read")), db: Session = Depends(get_db)):
    f = _fw(db, code)
    rows = ctl.soa_rows(db, f.id)
    return {
        "framework": ser(f, ("id", "code", "name", "version")),
        "rows": [{"requirement_id": r.requirement.id, "ref": r.requirement.ref, "title": r.requirement.title, "applicable": r.applicable, "justification": r.justification, "basis": r.justification_source, "implementation": r.implementation, "controls": r.controls, "risks": r.risks} for r in rows],
        "approvals": [ser(a, ("id", "version", "approved_by_id", "approved_at", "note")) for a in ctl.soa_approvals(db, f.id)],
        "changed_since_approval": ctl.soa_changes_since_approval(db, f.id),
    }


class SoaIn(In):
    applicable: bool
    justification: str | None = None


@router.put("/soa/entries/{requirement_id}")
def set_soa(requirement_id: int, body: SoaIn, user=Depends(perm("soa.write")), db: Session = Depends(get_db)):
    ctl.set_soa_entry(db, user, requirement_id, body.applicable, body.justification)
    return {"ok": True}


@router.delete("/soa/entries/{requirement_id}")
def clear_soa(requirement_id: int, user=Depends(perm("soa.write")), db: Session = Depends(get_db)):
    ctl.clear_soa_entry(db, user, requirement_id)
    return {"ok": True}


class ApproveIn(In):
    note: str | None = None


@router.post("/soa/{code}/approve")
def approve(code: str, body: ApproveIn, user=Depends(perm("soa.write")), db: Session = Depends(get_db)):
    a = ctl.approve_soa(db, user, _fw(db, code).id, body.note)
    return ser(a, ("id", "version", "approved_at"))


@router.get("/soa/{code}/export.{fmt}")
def soa_export(code: str, fmt: str, licensed: bool = False, user=Depends(perm("read")), db: Session = Depends(get_db)):
    f = _fw(db, code)
    rows = ctl.soa_rows(db, f.id)
    approvals = ctl.soa_approvals(db, f.id)
    changed = ctl.soa_changes_since_approval(db, f.id)
    note = f"approved v{approvals[0].version}" if approvals and not changed else "draft"
    o = get_org(db)
    label = f"{f.name} {f.version}"
    from keystone.core.audit import log_event

    log_event(db, user, "export", "SoA", f.id, f"Exported SoA {f.code} ({fmt})")
    if fmt == "xlsx":
        return xlsx_response(exports.soa_xlsx(o.name if o else "", label, rows, note, licensed), f"SoA_{f.code}.xlsx")
    if fmt == "docx":
        return docx_response(exports.soa_docx(o.name if o else "", label, rows, note, licensed), f"SoA_{f.code}.docx")
    raise ValueError("format must be xlsx or docx")
