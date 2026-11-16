import hashlib
import json

from fastapi import APIRouter, Depends, File, Form, Response, UploadFile
from sqlalchemy.orm import Session

from keystone.core.audit import log_event
from keystone.core.services import get_or_404
from keystone.core.settings import PROJECT_ROOT
from keystone.tprm.exposure import diff, exports, fair_mapping, importer, inventory, vendor_matching as vm
from keystone.tprm.exposure.models import OWNER_CLASSES, TenantApp
from keystone.tprm.exposure.schema import CollectedFileInvalid
from keystone.tprm.models import Vendor

from ..deps import get_db, perm
from ..serialize import ser
from .common import In, xlsx_response

router = APIRouter(prefix="/exposure", tags=["entra exposure"])

# The read-only collector technicians run on their workstation (see collector/README.md).
COLLECTOR_DIR = PROJECT_ROOT / "collector"
COLLECTOR_FILES = {"script": "Invoke-VendorExposureCollector.ps1", "tenants-csv": "tenants.example.csv"}


def _collector_file(key: str) -> bytes:
    if key not in COLLECTOR_FILES:
        raise LookupError("Unknown collector file.")
    return (COLLECTOR_DIR / COLLECTOR_FILES[key]).read_bytes()


@router.get("/collector")
def collector(user=Depends(perm("read"))):
    """The collector script's text and SHA-256, so a technician can copy it or verify a download."""
    data = _collector_file("script")
    return {"filename": COLLECTOR_FILES["script"], "sha256": hashlib.sha256(data).hexdigest().upper(), "size": len(data), "script": data.decode("utf-8"),
            "tenants_csv": _collector_file("tenants-csv").decode("utf-8")}


@router.get("/collector/{key}")
def collector_download(key: str, user=Depends(perm("read")), db: Session = Depends(get_db)):
    data = _collector_file(key)
    log_event(db, user, "export", "Collector", None, f"Downloaded {COLLECTOR_FILES[key]}")
    return Response(data, media_type="text/plain; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{COLLECTOR_FILES[key]}"'})


@router.post("/preview")
async def preview(file: UploadFile = File(...), user=Depends(perm("exposure.import")), db: Session = Depends(get_db)):
    try:
        doc = importer.load_document(await file.read())
    except CollectedFileInvalid as e:
        return {"valid": False, "errors": e.errors}
    p = importer.preview(db, doc)
    return {"valid": True, **p.__dict__}


@router.post("/import")
async def do_import(file: UploadFile = File(...), tenant_name: str | None = Form(None, max_length=200), user=Depends(perm("exposure.import")), db: Session = Depends(get_db)):
    doc = importer.load_document(await file.read())
    return importer.import_document(db, user, doc, tenant_name).__dict__


@router.get("/tenants")
def tenants(user=Depends(perm("read")), db: Session = Depends(get_db)):
    out = []
    for t in importer.tenants(db):
        snaps = importer.latest_snapshots(db, t.id, 50)
        out.append(ser(t, ("id", "name", "entra_tenant_id", "default_domain"), snapshots=[ser(s, ("id", "collected_at_utc", "operator_upn", "entra_p1_available", "write_scopes_present")) for s in snaps]))
    return out


def app_out(a: TenantApp) -> dict:
    ex = a.exposure
    return ser(a, ("id", "app_id", "display_name", "owner_org_id", "owner_class", "needs_review", "publisher_name", "verified_publisher_name", "publisher_verified", "account_enabled", "last_sign_in_utc", "sign_in_data_available", "homepage", "reply_url_domains"),
               exposure=None if ex is None else ser(ex, ("exposure_level", "has_app_only", "max_permission_tier", "admin_consented", "user_consent_count", "dormant", "credential_flags", "incomplete_data", "reasons")))


@router.get("/tenants/{tid}")
def tenant_map(tid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    snaps = importer.latest_snapshots(db, tid, 1)
    if not snaps:
        raise LookupError("No snapshots for this tenant")
    s = snaps[0]
    cp = s.consent
    d = diff.latest_diff(db, tid)
    return {
        "snapshot": ser(s, ("id", "collected_at_utc", "operator_upn", "ticket_number", "entra_p1_available", "write_scopes_present", "endpoint_status", "microsoft_owned_skipped_count")),
        "consent": None if cp is None else ser(cp, ("users_can_consent", "admin_consent_workflow_enabled", "permission_grant_policies_raw")),
        "apps": [app_out(a) for a in inventory.latest_apps(db, OWNER_CLASSES, tid)],
        "diff": None if d is None else {"new_apps": d.new_apps, "removed_apps": d.removed_apps, "consent_changes": d.consent_changes, "new_credentials": d.new_credentials, "not_comparable": d.not_comparable,
                                         "new_permissions": [dict(p.__dict__, app_only_high=p.app_only_high) for p in d.new_permissions]},
    }


@router.get("/apps/{app_id}")
def app_detail(app_id: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    a = get_or_404(db, TenantApp, app_id)
    d = app_out(a)
    d["permissions"] = [ser(p, ("permission_type", "value", "resource_name", "tier", "consent_type", "user_count")) for p in a.permissions]
    d["credentials"] = None if a.exposure and a.exposure.credential_flags is None else [ser(c, ("owner_type", "credential_type", "display_name", "start_utc", "end_utc", "lifetime_days", "status")) for c in a.credentials]
    return d


@router.get("/cross-tenant")
def cross_tenant(user=Depends(perm("read")), db: Session = Depends(get_db)):
    maps = inventory.mappings(db)
    names: dict[int | None, str] = {v.id: v.name for v in db.query(Vendor).all()}
    rows = []
    for oid, o in inventory.owner_orgs(db).items():
        m = maps.get(oid)
        if m and m.status == "ignored":
            continue
        rows.append({"owner_org_id": oid, "label": o.label, "vendor": names.get(m.vendor_id) if m and m.status == "confirmed" else None, "levels": {str(k): v for k, v in o.level_by_tenant.items()}})
    return {"tenants": [{"id": t.id, "name": t.name} for t in importer.tenants(db)], "rows": rows}


@router.get("/matching")
def matching(user=Depends(perm("read")), db: Session = Depends(get_db)):
    queue = [{"owner_org_id": o.owner_org_id, "names": sorted(o.names), "domains": sorted(o.domains), "apps": [a.display_name for a in o.apps], "worst": inventory.worst(o.level_by_tenant.values()), "tenants": len(o.level_by_tenant), "candidates": (m.match_signals or {}).get("candidates", []) if m else []} for o, m in vm.queue(db)]
    decided = [ser(m, ("owner_org_id", "status", "vendor_id", "confirmed_by", "confirmed_at")) for m in inventory.mappings(db).values() if m.status != "suggested"]
    return {"queue": queue, "decided": decided}


@router.post("/matching/refresh")
def refresh(user=Depends(perm("exposure.import")), db: Session = Depends(get_db)):
    return {"updated": vm.refresh_suggestions(db, user)}


class ConfirmIn(In):
    vendor_id: int


@router.post("/matching/{owner_org_id}/confirm")
def confirm(owner_org_id: str, body: ConfirmIn, user=Depends(perm("exposure.confirm")), db: Session = Depends(get_db)):
    vm.confirm(db, user, owner_org_id, body.vendor_id)
    return {"ok": True}


@router.post("/matching/{owner_org_id}/ignore")
def ignore(owner_org_id: str, user=Depends(perm("exposure.confirm")), db: Session = Depends(get_db)):
    vm.ignore(db, user, owner_org_id)
    return {"ok": True}


@router.delete("/matching/{owner_org_id}")
def reset(owner_org_id: str, user=Depends(perm("exposure.confirm")), db: Session = Depends(get_db)):
    vm.reset(db, user, owner_org_id)
    return {"ok": True}


@router.get("/remediation")
def remediation(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return exports.remediation_candidates(db)


@router.get("/remediation.xlsx")
def remediation_xlsx(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return xlsx_response(exports.remediation_xlsx(db), "remediation_candidates.xlsx")


@router.post("/assessments/{aid}/suggestions")
def generate(aid: int, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    return [s.id for s in fair_mapping.generate(db, user, aid)]


@router.post("/suggestions/{sid}/accept")
def accept(sid: int, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    fair_mapping.accept(db, user, sid)
    return {"ok": True}


@router.post("/suggestions/{sid}/reject")
def reject(sid: int, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    fair_mapping.reject(db, user, sid)
    return {"ok": True}


@router.post("/assessments/{aid}/suggestions/accept-all")
def accept_all(aid: int, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    return {"accepted": fair_mapping.accept_all(db, user, aid)}
