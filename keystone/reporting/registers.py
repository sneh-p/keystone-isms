"""Register exports (XLSX). Each export is logged in the audit log."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.assets.service import list_assets
from keystone.core.audit import AuditLog, log_event
from keystone.core.auth import list_users
from keystone.core.rbac import require
from keystone.improvement.service import list_ncs
from keystone.incidents.service import list_incidents, notification_deadline
from keystone.risk import service as risk
from keystone.tprm import service as tprm

from .exports import xlsx


def _names(session):
    return {u.id: u.display_name for u in list_users(session)}


def risk_register(session: Session) -> tuple[list, list]:
    n = _names(session)
    rows = []
    for r in risk.list_risks(session, include_closed=True):
        rows.append([r.ref, r.title, r.category, n.get(r.owner_id), r.threat, r.vulnerability, r.inherent_likelihood, r.inherent_impact, risk.inherent_level(r), r.residual_likelihood, r.residual_impact, risk.residual_level(r), r.treatment_option, r.status, r.review_date, ", ".join(c.code for c in r.controls), ", ".join(a.name for a in r.assets), round(r.fair_result["ale_mean"]) if r.fair_result else None])
    return ["Ref", "Risk", "Category", "Owner", "Threat", "Vulnerability", "Inherent L", "Inherent I", "Inherent level", "Residual L", "Residual I", "Residual level", "Treatment", "Status", "Next review", "Controls", "Assets", "FAIR ALE"], rows


def asset_register(session: Session) -> tuple[list, list]:
    n = _names(session)
    return ["Ref", "Asset", "Type", "Owner", "Classification", "C", "I", "A", "Criticality", "Personal data", "Location", "Status"], [[a.ref, a.name, a.asset_type, n.get(a.owner_id), a.classification, a.confidentiality, a.integrity, a.availability, a.criticality, a.contains_personal_data, a.location, a.status] for a in list_assets(session, include_retired=True)]


def vendor_register(session: Session) -> tuple[list, list]:
    n = _names(session)
    rows = []
    for v in tprm.list_vendors(session, include_terminated=True):
        a = tprm.latest_approved_assessment(session, v.id)
        rows.append([v.ref, v.name, v.website, v.status, v.tier, v.data_sensitivity, v.access_level, v.processes_personal_data, v.dpa_signed, n.get(v.owner_id), v.contract_end, v.next_review_date, a.approved_at if a else None, round(a.result["ale_mean"]) if a and a.result else None])
    return ["Ref", "Vendor", "Website", "Status", "Tier", "Data", "Access", "Personal data", "DPA", "Owner", "Contract end", "Next review", "Last approved assessment", "Assessed ALE"], rows


def incident_register(session: Session) -> tuple[list, list]:
    n = _names(session)
    return ["Ref", "Incident", "Category", "Severity", "Status", "Detected", "Owner", "Personal data", "Notify by", "Notified", "Root cause", "Lessons learned", "Closed"], [[i.ref, i.title, i.category, i.severity, i.status, i.detected_at, n.get(i.owner_id), i.personal_data_involved, notification_deadline(i), i.regulator_notified_at, i.root_cause, i.lessons_learned, i.closed_at] for i in list_incidents(session)]


def nc_register(session: Session) -> tuple[list, list]:
    n = _names(session)
    rows = []
    for nc in list_ncs(session):
        rows.append([nc.ref, nc.title, nc.source, nc.severity, nc.status, n.get(nc.owner_id), nc.root_cause, nc.due_date, "; ".join(f"{a.description} [{a.status}]" for a in nc.actions), nc.closed_at])
    return ["Ref", "Nonconformity", "Source", "Severity", "Status", "Owner", "Root cause", "Due", "Corrective actions", "Closed"], rows


def audit_log_rows(session: Session, actor) -> tuple[list, list]:
    require(actor, "audit_log.view")
    rows = [[r.id, r.ts, r.actor_name, r.action, r.entity_type, r.entity_id, r.summary, str(r.changes) if r.changes else "", r.hash] for r in session.scalars(select(AuditLog).order_by(AuditLog.id))]
    return ["#", "When (UTC)", "Actor", "Action", "Record type", "Record id", "Summary", "Changes", "Hash"], rows


REGISTERS = {
    "Risk register": risk_register,
    "Asset register": asset_register,
    "Vendor register": vendor_register,
    "Incident register": incident_register,
    "Nonconformity register": nc_register,
}


def export(session: Session, actor, name: str, org_name: str = "") -> bytes:
    require(actor, "read")
    if name == "Audit log":
        headers, rows = audit_log_rows(session, actor)
    else:
        headers, rows = REGISTERS[name](session)
    data = xlsx({name: (headers, rows)}, title=f"{org_name}: {name}".strip(": "))
    log_event(session, actor, "export", "Report", None, f"Exported {name} ({len(rows)} rows)")
    return data
