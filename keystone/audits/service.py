from __future__ import annotations

from datetime import date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.db import utcnow
from keystone.core.services import apply_fields, authorize, get_or_404, require_text, today
from keystone.frameworks.models import CommonControl
from keystone.improvement import service as imp

from .models import AUDIT_TYPES, FINDING_TYPES, Audit, AuditFinding

AUDIT_FIELDS = {"title", "audit_type", "scope", "criteria", "framework_id", "vendor_id", "lead_auditor_id", "audit_team", "planned_start", "planned_end", "summary", "conclusion"}
NEXT = {"planned": "in_progress", "in_progress": "reporting", "reporting": "closed"}
COVERAGE_MONTHS = 36  # a certification cycle


def save_audit(session: Session, actor, audit_id: int | None = None, *, control_ids: list[int] | None = None, **fields) -> Audit:
    authorize(session, actor, "audit.manage")
    a = get_or_404(session, Audit, audit_id) if audit_id else Audit(status="planned", audit_type="internal")
    if a.status == "closed":
        raise ValueError("Closed audits cannot be changed.")
    apply_fields(a, fields, AUDIT_FIELDS)
    require_text(a.title, "Audit title")
    if a.audit_type not in AUDIT_TYPES:
        raise ValueError(f"audit_type must be one of {AUDIT_TYPES}")
    if a.planned_start and a.planned_end and a.planned_end < a.planned_start:
        raise ValueError("Planned end is before planned start.")
    if control_ids is not None:
        a.controls = list(session.scalars(select(CommonControl).where(CommonControl.id.in_(control_ids))))
    session.add(a)
    session.flush()
    return a


def independence_conflicts(a: Audit) -> list[str]:
    """In-scope controls owned by the lead auditor (ISO 27001 9.2.2: auditors must be objective)."""
    if a.lead_auditor_id is None:
        return []
    return [c.code for c in a.controls if c.owner_id == a.lead_auditor_id]


def advance(session: Session, actor, audit_id: int) -> Audit:
    authorize(session, actor, "audit.manage")
    a = get_or_404(session, Audit, audit_id)
    if a.status not in NEXT:
        raise ValueError("The audit is already closed.")
    target = NEXT[a.status]
    if target == "in_progress":
        if a.lead_auditor_id is None:
            raise ValueError("Assign a lead auditor before starting.")
        conflicts = independence_conflicts(a)
        if conflicts and a.audit_type == "internal":
            raise ValueError("Objectivity: the lead auditor owns in-scope controls " + ", ".join(conflicts) + ". Choose another auditor or change the scope.")
    if target == "closed":
        if not (a.summary or "").strip() or not (a.conclusion or "").strip():
            raise ValueError("Write the audit summary and conclusion before closing.")
        a.closed_at = utcnow()
    a.status = target
    session.flush()
    return a


def add_finding(session: Session, actor, audit_id: int, *, finding_type: str, title: str, description: str | None = None, evidence: str | None = None, requirement_id: int | None = None, common_control_id: int | None = None) -> AuditFinding:
    authorize(session, actor, "audit.findings")
    a = get_or_404(session, Audit, audit_id)
    if a.status not in ("in_progress", "reporting"):
        raise ValueError("Findings can be recorded while the audit is in progress or reporting.")
    if finding_type not in FINDING_TYPES:
        raise ValueError(f"finding_type must be one of {FINDING_TYPES}")
    f = AuditFinding(audit=a, finding_type=finding_type, title=require_text(title, "Finding title"), description=description, evidence=evidence, requirement_id=requirement_id, common_control_id=common_control_id)
    session.add(f)
    session.flush()
    if finding_type in ("major_nc", "minor_nc"):
        nc = imp.raise_nc(
            session, actor, title=f.title, description=(description or "") + (f"\n\nEvidence: {evidence}" if evidence else ""),
            source="internal_audit" if a.audit_type == "internal" else "external_audit", severity="major" if finding_type == "major_nc" else "minor",
            requirement_id=requirement_id, common_control_id=common_control_id,
        )
        f.nonconformity_id = nc.id
        session.flush()
    return f


def list_audits(session: Session) -> list[Audit]:
    return list(session.scalars(select(Audit).order_by(Audit.planned_start.desc().nulls_last(), Audit.id.desc())))


def control_coverage(session: Session, on: date | None = None) -> dict:
    """Share of applicable controls covered by an audit that started in the last COVERAGE_MONTHS."""
    on = on or today()
    since = on - timedelta(days=COVERAGE_MONTHS * 30)
    controls = [c for c in session.scalars(select(CommonControl)) if c.status != "not_applicable"]
    audited: set[int] = set()
    for a in list_audits(session):
        if a.status != "planned" and a.audit_type in ("internal", "external", "certification", "surveillance") and (a.planned_start or on) >= since:
            audited |= {c.id for c in a.controls}
    missing = sorted(c.code for c in controls if c.id not in audited)
    return {"applicable": len(controls), "audited": len(controls) - len(missing), "pct": round(100 * (len(controls) - len(missing)) / len(controls), 1) if controls else 0.0, "not_audited": missing}
