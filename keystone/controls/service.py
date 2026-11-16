from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta
from urllib.parse import urlparse

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from keystone.core.attachments import save_attachment
from keystone.core.db import utcnow
from keystone.core.services import authorize, bulk_targets, get_or_404, require_active_user, require_text, today
from keystone.frameworks.models import CONTROL_STATUSES, CommonControl, Framework, Requirement
from keystone.frameworks.service import derive_status, leaf_requirements
from keystone.risk.models import Risk, risk_controls

from .models import EVIDENCE_KINDS, Evidence, SoaApproval, SoaEntry

EXPIRY_WARNING_DAYS = 30


# ---- control implementation ---------------------------------------------------------

def update_control(session: Session, actor, control_id: int, **fields) -> CommonControl:
    authorize(session, actor, "control.write")
    c = get_or_404(session, CommonControl, control_id)
    allowed = {"status", "owner_id", "implementation_notes", "na_justification", "review_interval_days"}
    bad = set(fields) - allowed
    if bad:
        raise ValueError(f"fields not editable here: {', '.join(sorted(bad))}")
    new = {k: (v.strip() if isinstance(v, str) else v) for k, v in fields.items()}
    merged = {k: getattr(c, k) for k in allowed} | new
    # Validate before touching the record, so a rejected change leaves it unchanged.
    if merged["status"] not in CONTROL_STATUSES:
        raise ValueError(f"status must be one of {CONTROL_STATUSES}")
    if merged["status"] == "not_applicable" and not (merged["na_justification"] or "").strip():
        raise ValueError("Explain why the control is not applicable.")
    if not 30 <= int(merged["review_interval_days"]) <= 1095:
        raise ValueError("Review interval must be between 30 and 1095 days.")
    for k, v in new.items():
        setattr(c, k, v)
    if c.next_review_date is None:
        c.next_review_date = today() + timedelta(days=c.review_interval_days)
    session.flush()
    return c


def bulk_update_controls(session: Session, actor, ids: list[int], **fields) -> list[CommonControl]:
    """Set the owner and/or status of many controls at once; all-or-nothing, each change audited per control."""
    authorize(session, actor, "control.write")
    if not fields or set(fields) - {"status", "owner_id"}:
        raise ValueError("Bulk changes can set the owner and the status only.")
    if fields.get("status") == "not_applicable":
        raise ValueError("Mark controls not applicable one at a time, with the reason for each.")
    if "owner_id" in fields:
        require_active_user(session, fields["owner_id"])
    targets = bulk_targets(session, CommonControl, ids)
    for c in targets:
        update_control(session, actor, c.id, **fields)
    return targets


def review_control(session: Session, actor, control_id: int) -> CommonControl:
    authorize(session, actor, "control.write")
    c = get_or_404(session, CommonControl, control_id)
    c.last_reviewed_at = utcnow()
    c.next_review_date = today() + timedelta(days=c.review_interval_days)
    session.flush()
    return c


# ---- evidence ------------------------------------------------------------------------------

def add_evidence(session: Session, actor, control_id: int, *, title: str, kind: str, collected_on: date | None = None, valid_until: date | None = None, description: str | None = None, url: str | None = None, filename: str | None = None, data: bytes | None = None) -> Evidence:
    authorize(session, actor, "evidence.write")
    get_or_404(session, CommonControl, control_id)
    require_text(title, "Evidence title")
    if kind not in EVIDENCE_KINDS:
        raise ValueError(f"kind must be one of {EVIDENCE_KINDS}")
    collected_on = collected_on or today()
    if valid_until and valid_until < collected_on:
        raise ValueError("Valid-until date is before the collection date.")
    ev = Evidence(common_control_id=control_id, title=title.strip(), kind=kind, description=description, collected_on=collected_on, valid_until=valid_until)
    if kind == "link":
        p = urlparse(url or "")
        if p.scheme not in ("https", "http") or not p.netloc:
            raise ValueError("Give a full http(s) link.")
        ev.url = url
    elif kind == "file":
        if not data or not filename:
            raise ValueError("Attach a file.")
        session.add(ev)
        session.flush()
        ev.attachment_id = save_attachment(session, actor, filename, data, "Evidence", ev.id).id
    elif not (description or "").strip():
        raise ValueError("A note needs a description.")
    session.add(ev)
    session.flush()
    return ev


def review_evidence(session: Session, actor, evidence_id: int, superseded: bool = False) -> Evidence:
    authorize(session, actor, "evidence.write")
    ev = get_or_404(session, Evidence, evidence_id)
    ev.reviewed_by_id, ev.reviewed_at, ev.superseded = actor.id, utcnow(), superseded
    session.flush()
    return ev


def evidence_state(ev: Evidence, on: date | None = None) -> str:
    on = on or today()
    if ev.superseded:
        return "superseded"
    if ev.valid_until and ev.valid_until < on:
        return "expired"
    if ev.valid_until and ev.valid_until <= on + timedelta(days=EXPIRY_WARNING_DAYS):
        return "expiring"
    return "current"


def evidence_for(session: Session, control_id: int | None = None, limit: int | None = None, offset: int = 0) -> list[Evidence]:
    q = select(Evidence).order_by(Evidence.collected_on.desc(), Evidence.id.desc())
    if control_id:
        q = q.where(Evidence.common_control_id == control_id)
    if limit is not None:
        q = q.limit(limit).offset(offset)
    return list(session.scalars(q))


def control_attention(session: Session, on: date | None = None) -> dict[str, list]:
    """Controls needing action: overdue reviews, implemented without current evidence, evidence expiring."""
    on = on or today()
    ctls = list(session.scalars(select(CommonControl).order_by(CommonControl.code)))
    evs = evidence_for(session)
    current: dict[int, int] = {}
    for e in evs:
        if evidence_state(e, on) in ("current", "expiring"):
            current[e.common_control_id] = current.get(e.common_control_id, 0) + 1
    return {
        "review_overdue": [c for c in ctls if c.next_review_date and c.next_review_date < on and c.status != "not_applicable"],
        "implemented_without_evidence": [c for c in ctls if c.status in ("implemented", "partial") and not current.get(c.id)],
        "evidence_expiring": [e for e in evs if evidence_state(e, on) == "expiring"],
        "evidence_expired": [e for e in evs if evidence_state(e, on) == "expired"],
    }


def status_counts(session: Session) -> dict[str, int]:
    rows = session.execute(select(CommonControl.status, func.count()).group_by(CommonControl.status)).all()
    return {s: n for s, n in rows}


# ---- Statement of Applicability -----------------------------------------------------------------

@dataclass
class SoaRow:
    requirement: Requirement
    applicable: bool
    justification: str
    justification_source: str  # decision | controls_na | risks | baseline
    implementation: str
    controls: list[str] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)


def soa_rows(session: Session, framework_id: int) -> list[SoaRow]:
    entries = {e.requirement_id: e for e in session.scalars(select(SoaEntry))}
    links = session.execute(select(risk_controls.c.common_control_id, Risk).join(Risk, Risk.id == risk_controls.c.risk_id).where(Risk.status != "closed")).all()
    risks_by_control: dict[int, list[str]] = {}
    for cid, r in links:
        risks_by_control.setdefault(cid, []).append(r.ref)
    rows = []
    for req in leaf_requirements(session, framework_id):
        ctls = sorted((m.control for m in req.mappings), key=lambda c: c.code)
        risks = sorted({ref for c in ctls for ref in risks_by_control.get(c.id, [])})
        impl = derive_status([c.status for c in ctls])
        decision = entries.get(req.id)
        if decision is not None:
            applicable, just, src = decision.applicable, decision.justification or "", "decision"
        elif impl == "not_applicable":
            applicable, src = False, "controls_na"
            just = " ".join(f"{c.code}: {c.na_justification}" for c in ctls if c.na_justification)
        elif risks:
            applicable, just, src = True, "Treats risk(s) " + ", ".join(risks), "risks"
        else:
            applicable, just, src = True, "Baseline control adopted by the organisation", "baseline"
        rows.append(SoaRow(req, applicable, just, src, impl if applicable else "not_applicable", [c.code for c in ctls], risks))
    return rows


def set_soa_entry(session: Session, actor, requirement_id: int, applicable: bool, justification: str | None) -> SoaEntry:
    authorize(session, actor, "soa.write")
    req = get_or_404(session, Requirement, requirement_id)
    if not req.is_leaf:
        raise ValueError("SoA decisions apply to individual requirements.")
    if not applicable and not (justification or "").strip():
        raise ValueError("Excluding a requirement needs a justification.")
    e = session.scalar(select(SoaEntry).where(SoaEntry.requirement_id == requirement_id)) or SoaEntry(requirement_id=requirement_id)
    e.applicable, e.justification = applicable, (justification or "").strip() or None
    session.add(e)
    session.flush()
    return e


def clear_soa_entry(session: Session, actor, requirement_id: int) -> None:
    authorize(session, actor, "soa.write")
    e = session.scalar(select(SoaEntry).where(SoaEntry.requirement_id == requirement_id))
    if e:
        session.delete(e)
        session.flush()


def snapshot(rows: list[SoaRow]) -> list[dict]:
    return [
        {"ref": r.requirement.ref, "title": r.requirement.title, "applicable": r.applicable, "justification": r.justification, "implementation": r.implementation, "controls": r.controls, "risks": r.risks}
        for r in rows
    ]


def approve_soa(session: Session, actor, framework_id: int, note: str | None = None) -> SoaApproval:
    authorize(session, actor, "soa.write")
    get_or_404(session, Framework, framework_id)
    rows = soa_rows(session, framework_id)
    missing = [r.requirement.ref for r in rows if not r.applicable and not r.justification.strip()]
    if missing:
        raise ValueError("Exclusions without justification: " + ", ".join(missing[:20]))
    version = (session.scalar(select(func.max(SoaApproval.version)).where(SoaApproval.framework_id == framework_id)) or 0) + 1
    a = SoaApproval(framework_id=framework_id, version=version, approved_by_id=actor.id, approved_at=utcnow(), note=note, snapshot=snapshot(rows))
    session.add(a)
    session.flush()
    return a


def soa_approvals(session: Session, framework_id: int) -> list[SoaApproval]:
    return list(session.scalars(select(SoaApproval).where(SoaApproval.framework_id == framework_id).order_by(SoaApproval.version.desc())))


def soa_changes_since_approval(session: Session, framework_id: int) -> list[str]:
    """Refs whose applicability, justification or implementation changed since the last approval."""
    approvals = soa_approvals(session, framework_id)
    if not approvals:
        return []
    before = {x["ref"]: x for x in approvals[0].snapshot}
    now = {x["ref"]: x for x in snapshot(soa_rows(session, framework_id))}
    keys = ("applicable", "justification", "implementation")
    return sorted(ref for ref in now if ref not in before or any(now[ref][k] != before[ref][k] for k in keys))
