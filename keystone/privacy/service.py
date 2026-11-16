"""Privacy: records of processing, DPIAs, data subject requests and breach assessments.

Rules worth knowing:
- Data subject requests are due one calendar month after receipt; one extension of up to two further months needs a
  reason (GDPR Art. 12(3)). Requests and the people in them are visible only to users with privacy.write.
- A request's name and contact details are redacted in the audit log, and cleared once the request has been closed
  for REDACT_AFTER_DAYS (data minimisation); the request itself stays as a record that it was handled.
- A DPIA is approved by someone other than the person who submitted it (segregation of duties), with risk.accept,
  because approving it accepts the residual risk to people.
- Every incident involving personal data gets a breach assessment (Art. 33(5)); the incident's own fields hold the
  notification deadline and the date the authority was told.
"""

from __future__ import annotations

import os
from datetime import date, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.db import utcnow
from keystone.core.services import add_months, apply_fields, authorize, get_or_404, require_text, today

from .models import (BREACH_RISK, DPIA_OUTCOMES, LAWFUL_BASES, REQUEST_STATUSES, REQUEST_TYPES, ROLES, TRANSFER_SAFEGUARDS, BreachAssessment, DataSubjectRequest,
                     Dpia, ProcessingActivity)

ACTIVITY_FIELDS = ("name", "purpose", "role", "lawful_basis", "legitimate_interest", "special_category", "special_condition", "data_subjects", "data_categories",
                   "recipients", "vendor_ids", "asset_ids", "transfers", "transfer_safeguard", "retention", "security_measures", "dpia_required", "owner_id",
                   "status", "next_review_date")
DPIA_FIELDS = ("title", "activity_id", "description", "necessity", "risks", "dpo_advice", "outcome", "next_review_date")
REQUEST_FIELDS = ("request_type", "received_on", "channel", "requester_name", "requester_contact", "details", "identity_verified", "assignee_id", "outcome")
BREACH_FIELDS = ("data_categories", "subjects_affected", "records_affected", "consequences", "measures", "risk_level", "rationale", "authority_reference", "subjects_notified_at")


def redact_after_days() -> int:
    raw = os.environ.get("KEYSTONE_DSR_REDACT_DAYS", "365").strip()
    return int(raw) if raw.isdigit() and 30 <= int(raw) <= 3650 else 365


# ---- records of processing ---------------------------------------------------------------------------------------

def _check_activity(a: ProcessingActivity) -> None:
    require_text(a.name, "Name")
    require_text(a.purpose, "Purpose")
    if a.role not in ROLES or a.lawful_basis not in LAWFUL_BASES or a.transfer_safeguard not in TRANSFER_SAFEGUARDS or a.status not in ("active", "retired"):
        raise ValueError("Choose a role, lawful basis, transfer safeguard and status from the lists.")
    if a.lawful_basis == "legitimate_interests" and not (a.legitimate_interest or "").strip():
        raise ValueError("Describe the legitimate interest pursued.")
    if a.special_category and not (a.special_condition or "").strip():
        raise ValueError("Special category data needs an Article 9 condition.")
    if (a.transfers or "").strip() and a.transfer_safeguard == "none":
        raise ValueError("Transfers outside the EEA need a safeguard (adequacy, SCCs, BCRs or a derogation).")
    for field in ("vendor_ids", "asset_ids"):
        v = getattr(a, field)
        if v is not None and (not isinstance(v, list) or not all(isinstance(x, int) for x in v) or len(v) > 200):
            raise ValueError(f"{field} must be a list of ids.")


def activities(session: Session, actor) -> list[ProcessingActivity]:
    authorize(session, actor, "read")
    return list(session.scalars(select(ProcessingActivity).order_by(ProcessingActivity.status, ProcessingActivity.name)))


def save_activity(session: Session, actor, activity_id: int | None = None, **fields) -> ProcessingActivity:
    authorize(session, actor, "privacy.write")
    a = get_or_404(session, ProcessingActivity, activity_id) if activity_id else ProcessingActivity(role="controller", lawful_basis="contract", transfer_safeguard="none", status="active", special_category=False)
    apply_fields(a, fields, ACTIVITY_FIELDS)
    _check_activity(a)
    if a.next_review_date is None:
        a.next_review_date = today() + timedelta(days=365)
    session.add(a)
    session.flush()
    return a


# ---- DPIAs -----------------------------------------------------------------------------------------------------------

def _check_risks(risks) -> list[dict]:
    if risks is None:
        return []
    if not isinstance(risks, list) or len(risks) > 50:
        raise ValueError("Risks must be a list (at most 50).")
    out = []
    for r in risks:
        if not isinstance(r, dict) or not str(r.get("risk") or "").strip():
            raise ValueError("Each risk needs a description.")
        row: dict[str, str | int | None] = {"risk": str(r["risk"]).strip()[:500], "measures": str(r.get("measures") or "").strip()[:1000]}
        for k in ("likelihood", "severity", "residual"):
            v = r.get(k)
            if v not in (1, 2, 3, None):
                raise ValueError("Likelihood, severity and residual risk are 1 (low) to 3 (high).")
            row[k] = v
        out.append(row)
    return out


def dpias(session: Session, actor) -> list[Dpia]:
    authorize(session, actor, "read")
    return list(session.scalars(select(Dpia).order_by(Dpia.id.desc())))


def save_dpia(session: Session, actor, dpia_id: int | None = None, **fields) -> Dpia:
    authorize(session, actor, "privacy.write")
    d = get_or_404(session, Dpia, dpia_id) if dpia_id else Dpia(status="draft")
    if d.status in ("approved", "rejected"):
        raise ValueError("A decided DPIA can't be changed; start a new one (for example at its review).")
    if "risks" in fields:
        fields["risks"] = _check_risks(fields["risks"])
    if fields.get("outcome") not in (None, *DPIA_OUTCOMES):
        raise ValueError("Choose an outcome from the list.")
    if fields.get("activity_id"):
        get_or_404(session, ProcessingActivity, fields["activity_id"])
    apply_fields(d, fields, DPIA_FIELDS)
    require_text(d.title, "Title")
    if d.status == "in_review":
        d.status = "draft"  # changing it after submission sends it back to draft
    session.add(d)
    session.flush()
    return d


def submit_dpia(session: Session, actor, dpia_id: int) -> Dpia:
    authorize(session, actor, "privacy.write")
    d = get_or_404(session, Dpia, dpia_id)
    if d.status != "draft":
        raise ValueError("Only a draft can be submitted.")
    if not d.risks or not d.outcome or not (d.necessity or "").strip():
        raise ValueError("Before submitting, describe necessity and proportionality, list the risks to people, and propose an outcome.")
    d.status, d.submitted_by_id = "in_review", actor.id
    session.flush()
    return d


def decide_dpia(session: Session, actor, dpia_id: int, approve: bool, note: str) -> Dpia:
    authorize(session, actor, "risk.accept")
    d = get_or_404(session, Dpia, dpia_id)
    if d.status != "in_review":
        raise ValueError("Only a submitted DPIA can be decided.")
    if actor.id in (d.submitted_by_id, d.created_by_id):
        raise ValueError("Segregation of duties: someone other than its author must decide a DPIA.")
    d.status = "approved" if approve else "rejected"
    d.decided_by_id, d.decided_at, d.decision_note = actor.id, utcnow(), require_text(note, "Decision note")[:4000]
    if approve and d.next_review_date is None:
        d.next_review_date = today() + timedelta(days=365)
    session.flush()
    return d


def high_residual(d: Dpia) -> bool:
    return any((r.get("residual") or 0) >= 3 for r in d.risks or [])


# ---- data subject requests ------------------------------------------------------------------------------------------

def requests(session: Session, actor, include_closed: bool = True) -> list[DataSubjectRequest]:
    authorize(session, actor, "privacy.write")  # they contain personal data: need to know only
    q = select(DataSubjectRequest).order_by(DataSubjectRequest.due_date)
    if not include_closed:
        q = q.where(DataSubjectRequest.status.not_in(("completed", "refused")))
    return list(session.scalars(q))


def save_request(session: Session, actor, request_id: int | None = None, **fields) -> DataSubjectRequest:
    authorize(session, actor, "privacy.write")
    r = get_or_404(session, DataSubjectRequest, request_id) if request_id else DataSubjectRequest(status="new")
    if r.status in ("completed", "refused"):
        raise ValueError("A closed request can't be changed.")
    if "request_type" in fields and fields["request_type"] not in REQUEST_TYPES:
        raise ValueError("Choose a request type from the list.")
    apply_fields(r, fields, REQUEST_FIELDS)
    if r.received_on is None or r.received_on > today():
        raise ValueError("Enter the date the request was received (not in the future).")
    if not r.request_type:
        raise ValueError("Choose a request type.")
    if not r.extended:
        r.due_date = add_months(r.received_on, 1)
    session.add(r)
    session.flush()
    return r


def extend_request(session: Session, actor, request_id: int, reason: str) -> DataSubjectRequest:
    authorize(session, actor, "privacy.write")
    r = get_or_404(session, DataSubjectRequest, request_id)
    if r.extended:
        raise ValueError("A request can be extended only once.")
    if r.status in ("completed", "refused"):
        raise ValueError("A closed request can't be extended.")
    r.extended, r.extension_reason = True, require_text(reason, "Reason")[:2000]
    r.due_date = add_months(r.received_on, 3)  # one month plus up to two more (Art. 12(3))
    session.flush()
    return r


def move_request(session: Session, actor, request_id: int, status: str, outcome: str | None = None) -> DataSubjectRequest:
    authorize(session, actor, "privacy.write")
    r = get_or_404(session, DataSubjectRequest, request_id)
    if status not in REQUEST_STATUSES:
        raise ValueError("Unknown status.")
    if r.status in ("completed", "refused"):
        raise ValueError("The request is already closed.")
    if status in ("in_progress", "completed") and not r.identity_verified:
        raise ValueError("Verify the requester's identity first.")
    if status in ("completed", "refused"):
        r.outcome = require_text(outcome or r.outcome, "Outcome (what was done, or why it was refused)")[:4000]
        r.closed_on = today()
    r.status = status
    session.flush()
    return r


def redact_closed_requests(session: Session, on: date | None = None) -> int:
    """Clear names and contact details of requests closed more than redact_after_days() ago. Returns how many."""
    cutoff = (on or today()) - timedelta(days=redact_after_days())
    n = 0
    for r in session.scalars(select(DataSubjectRequest).where(DataSubjectRequest.closed_on.is_not(None), DataSubjectRequest.closed_on < cutoff,
                                                             DataSubjectRequest.redacted_at.is_(None))):
        r.requester_name, r.requester_contact, r.details, r.redacted_at = None, None, None, utcnow()
        n += 1
    session.flush()
    return n


# ---- breach log ------------------------------------------------------------------------------------------------------

def breaches(session: Session, actor) -> list[dict]:
    """Every incident that involves (or may involve) personal data, with its assessment."""
    from keystone.incidents import service as inc
    from keystone.incidents.models import Incident

    authorize(session, actor, "read")
    assessed = {b.incident_id: b for b in session.scalars(select(BreachAssessment))}
    out = []
    for i in session.scalars(select(Incident).where(Incident.personal_data_involved.is_not(False)).order_by(Incident.detected_at.desc())):
        if i.personal_data_involved is None and i.id not in assessed:
            continue  # unknown and not assessed: shown on the incident, not yet in the log
        b = assessed.get(i.id)
        deadline = inc.notification_deadline(i)
        out.append({"incident": i, "assessment": b, "deadline": deadline,
                    "late": bool(i.notification_required and deadline and ((i.regulator_notified_at or utcnow()) > deadline))})
    return out


def assess_breach(session: Session, actor, incident_id: int, **fields) -> BreachAssessment:
    from keystone.incidents.models import Incident

    authorize(session, actor, "privacy.write")
    i = get_or_404(session, Incident, incident_id)
    if fields.get("risk_level") not in (None, *BREACH_RISK):
        raise ValueError("Choose no risk, risk or high risk.")
    for k in ("subjects_affected", "records_affected"):
        v = fields.get(k)
        if v is not None and (not isinstance(v, int) or v < 0):
            raise ValueError("Counts are whole numbers (approximate is fine).")
    b = session.scalar(select(BreachAssessment).where(BreachAssessment.incident_id == i.id)) or BreachAssessment(incident_id=i.id)
    apply_fields(b, fields, BREACH_FIELDS)
    if b.risk_level == "no_risk" and i.notification_required:
        raise ValueError("The incident says the authority must be notified; a breach with no risk to people normally isn't notifiable. Correct one of them.")
    if b.risk_level in ("risk", "high_risk") and not (b.rationale or "").strip() and not i.notification_required:
        raise ValueError("Explain why a breach that risks people's rights isn't being notified.")
    if i.personal_data_involved is None:
        i.personal_data_involved = True
    session.add(b)
    session.flush()
    return b


# ---- attention -------------------------------------------------------------------------------------------------------

def attention(session: Session, on: date | None = None) -> dict:
    from keystone.incidents.models import Incident

    on = on or today()
    open_reqs = [r for r in session.scalars(select(DataSubjectRequest).where(DataSubjectRequest.status.not_in(("completed", "refused"))))]
    assessed = set(session.scalars(select(BreachAssessment.incident_id)))
    return {
        "requests_overdue": [r for r in open_reqs if r.due_date < on],
        "requests_due_soon": [r for r in open_reqs if on <= r.due_date <= on + timedelta(days=7)],
        "dpias_awaiting_decision": list(session.scalars(select(Dpia).where(Dpia.status == "in_review"))),
        "activities_review_overdue": list(session.scalars(select(ProcessingActivity).where(ProcessingActivity.status == "active", ProcessingActivity.next_review_date < on))),
        "breaches_unassessed": [i for i in session.scalars(select(Incident).where(Incident.personal_data_involved.is_(True))) if i.id not in assessed],
    }

