from __future__ import annotations

from datetime import date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.db import utcnow
from keystone.core.services import apply_fields, authorize, get_or_404, require_text, today
from keystone.frameworks.models import CommonControl
from keystone.improvement import service as imp

from .models import AUDIT_TYPES, FINDING_TYPES, REQUEST_STATUSES, Audit, AuditFinding, AuditRequest, AuditRequestComment

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


FINDING_EDITABLE = ("title", "description", "evidence")


def update_finding(session: Session, actor, finding_id: int, **fields) -> AuditFinding:
    """Correct a finding's wording while its audit is open. Its type stays: a nonconformity raised from it would no
    longer match."""
    from .models import AuditFinding

    authorize(session, actor, "audit.findings")
    f = get_or_404(session, AuditFinding, finding_id)
    a = get_or_404(session, Audit, f.audit_id)
    if a.status not in ("in_progress", "reporting"):
        raise ValueError("Findings can be changed while the audit is in progress or reporting.")
    if set(fields) - set(FINDING_EDITABLE):
        raise ValueError("Only the title, description and evidence can change.")
    if "title" in fields:
        fields["title"] = require_text(fields["title"], "Finding title")
    for k, v in fields.items():
        setattr(f, k, v)
    session.flush()
    return f


PROGRAMME_YEARS = 3


def programme(session: Session, on: date | None = None) -> dict:
    """The audit programme (ISO 27001 9.2.2): for each applicable control, when it was last audited and when it is next
    planned, over a three-year cycle. Controls never audited in the cycle and with nothing planned stand out."""
    on = on or today()
    since = on - timedelta(days=365 * PROGRAMME_YEARS)
    audits = [a for a in list_audits(session) if a.audit_type in ("internal", "external", "certification", "surveillance")]
    last: dict[int, Audit] = {}
    nxt: dict[int, Audit] = {}
    for a in audits:
        start = a.planned_start or on
        for c in a.controls:
            if a.status != "planned" and start >= since and (c.id not in last or start > (last[c.id].planned_start or on)):
                last[c.id] = a
            if a.status == "planned" and start >= on and (c.id not in nxt or start < (nxt[c.id].planned_start or on)):
                nxt[c.id] = a
    rows = []
    for c in sorted((c for c in session.scalars(select(CommonControl)) if c.status != "not_applicable"), key=lambda c: c.code):
        la, na = last.get(c.id), nxt.get(c.id)
        rows.append({"id": c.id, "code": c.code, "title": c.title, "domain": c.domain,
                     "last_audited": la.planned_start if la else None, "last_audit": {"id": la.id, "title": la.title} if la else None,
                     "next_planned": na.planned_start if na else None, "next_audit": {"id": na.id, "title": na.title} if na else None,
                     "gap": la is None and na is None})
    covered = sum(1 for r in rows if r["last_audited"])
    return {"years": PROGRAMME_YEARS, "controls": rows, "covered": covered, "planned_only": sum(1 for r in rows if not r["last_audited"] and r["next_planned"]),
            "gaps": sum(1 for r in rows if r["gap"]), "pct": round(100 * covered / len(rows), 1) if rows else 0.0}


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


# ---- evidence request list ("PBC list") -----------------------------------------------------------------
# Auditors (audit.findings) ask and accept; staff who hold evidence.write answer with evidence and a note.

MAX_COMMENT = 5000


def _open_audit(session: Session, audit_id: int) -> Audit:
    a = get_or_404(session, Audit, audit_id)
    if a.status == "closed":
        raise ValueError("This audit is closed.")
    return a


def add_request(session: Session, actor, audit_id: int, *, title: str, description: str | None = None, common_control_id: int | None = None, due_date: date | None = None) -> AuditRequest:
    authorize(session, actor, "audit.findings")
    a = _open_audit(session, audit_id)
    if common_control_id is not None:
        get_or_404(session, CommonControl, common_control_id)
    r = AuditRequest(audit_id=a.id, title=require_text(title, "Request title")[:300], description=(description or "").strip() or None, common_control_id=common_control_id, due_date=due_date, status="open")
    session.add(r)
    session.flush()
    return r


def _comment(session: Session, r: AuditRequest, body: str) -> AuditRequestComment:
    text = require_text(body, "Comment")
    if len(text) > MAX_COMMENT:
        raise ValueError(f"Comments are limited to {MAX_COMMENT} characters.")
    c = AuditRequestComment(request_id=r.id, body=text)
    session.add(c)
    session.flush()
    return c


def comment_request(session: Session, actor, request_id: int, body: str) -> AuditRequestComment:
    authorize(session, actor, "audit.findings")
    r = get_or_404(session, AuditRequest, request_id)
    _open_audit(session, r.audit_id)
    return _comment(session, r, body)


def respond_request(session: Session, actor, request_id: int, *, body: str | None = None, evidence_ids: list[int] | None = None) -> AuditRequest:
    """Staff answer: link existing evidence and/or add a note; the request becomes "provided"."""
    from keystone.controls.models import Evidence

    authorize(session, actor, "evidence.write")
    r = get_or_404(session, AuditRequest, request_id)
    _open_audit(session, r.audit_id)
    if not body and not evidence_ids:
        raise ValueError("Add evidence or a note.")
    if evidence_ids:
        found = list(session.scalars(select(Evidence).where(Evidence.id.in_(set(evidence_ids)))))
        if len(found) != len(set(evidence_ids)):
            raise LookupError("Evidence not found")
        r.evidence = list({e.id: e for e in [*r.evidence, *found]}.values())
    if body:
        _comment(session, r, body)
    if r.status == "open":
        r.status = "provided"
    r.provided_by_id = actor.id
    session.flush()
    return r


def set_request_status(session: Session, actor, request_id: int, status: str) -> AuditRequest:
    authorize(session, actor, "audit.findings")
    if status not in REQUEST_STATUSES:
        raise ValueError(f"status must be one of {REQUEST_STATUSES}")
    r = get_or_404(session, AuditRequest, request_id)
    _open_audit(session, r.audit_id)
    if status == "accepted":
        if r.status != "provided":
            raise ValueError("Only a request that has been provided can be accepted.")
        if r.provided_by_id is not None and r.provided_by_id == actor.id:
            raise ValueError("Segregation of duties: whoever answered this request can't accept it.")
    r.status = status
    session.flush()
    return r


def requests_for(session: Session, audit_id: int) -> list[AuditRequest]:
    get_or_404(session, Audit, audit_id)
    return list(session.scalars(select(AuditRequest).where(AuditRequest.audit_id == audit_id).order_by(AuditRequest.id)))
