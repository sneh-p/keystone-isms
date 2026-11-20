from __future__ import annotations

from datetime import datetime, timedelta
from functools import lru_cache

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.assets.models import Asset
from keystone.core.db import utcnow
from keystone.core.services import apply_fields, authorize, get_or_404, require_text, today
from keystone.core.settings import PROJECT_ROOT

from .models import CATEGORIES, RESOLUTIONS, SEVERITIES, STATUSES, Incident, IncidentAction, IncidentEvent, IncidentEvidence

# Allowed moves. Closing directly from triage is for false positives / duplicates.
TRANSITIONS = {
    "new": ("triage",),
    "triage": ("contained", "closed"),
    "contained": ("eradicated",),
    "eradicated": ("recovered",),
    "recovered": ("closed",),
    "closed": ("triage",),  # reopen
}


@lru_cache(maxsize=2)
def load_config(path: str = str(PROJECT_ROOT / "config" / "incidents.yaml")) -> dict:
    return yaml.safe_load(open(path, encoding="utf-8"))


def notification_deadline(inc: Incident) -> datetime | None:
    if inc.personal_data_involved and inc.notification_required is not False:
        return inc.detected_at + timedelta(hours=load_config()["personal_data_notification_hours"])
    return None


def containment_due(inc: Incident) -> datetime:
    return inc.detected_at + timedelta(hours=load_config()["containment_target_hours"][inc.severity])


def _event(session: Session, inc: Incident, actor, entry: str, kind: str = "note", when: datetime | None = None) -> IncidentEvent:
    # Setting the relationship (not the FK + append) avoids a duplicate in the loaded collection.
    ev = IncidentEvent(incident=inc, occurred_at=when or utcnow(), entry=entry, author=getattr(actor, "username", "system"), kind=kind)
    session.add(ev)
    return ev


FIELDS = {"title", "description", "category", "severity", "detected_at", "reported_by", "owner_id", "vendor_id", "risk_id", "personal_data_involved", "notification_required", "root_cause", "lessons_learned"}


def report_incident(session: Session, actor, *, asset_ids: list[int] | None = None, **fields) -> Incident:
    authorize(session, actor, "incident.write")
    inc = Incident(status="new", category="other", severity="medium", detected_at=fields.pop("detected_at", None) or utcnow())
    apply_fields(inc, fields, FIELDS)
    _validate(inc)
    if inc.detected_at > utcnow() + timedelta(minutes=5):
        raise ValueError("Detection time is in the future.")
    if asset_ids:
        inc.assets = list(session.scalars(select(Asset).where(Asset.id.in_(asset_ids))))
    session.add(inc)
    session.flush()
    _event(session, inc, actor, f"Incident reported ({inc.severity}, {inc.category}).", "system", inc.detected_at)
    _risk_realised(session, inc, actor)
    if inc.severity == "critical":
        from keystone.oncall.service import page_on_call

        page_on_call(session, f"Critical incident {inc.ref}: {inc.title}", f"/incidents?open={inc.id}", f"incident:{inc.id}")
    from keystone.outbound.service import emit

    # Reference and severity only: chat channels are a wider audience than the incident register.
    emit(session, "incident.created", title=f"Incident {inc.ref} reported", detail=f"Severity {inc.severity}", severity=inc.severity, ref=inc.ref, page=f"/incidents?open={inc.id}")
    session.flush()
    return inc


def _risk_realised(session: Session, inc: Incident, actor) -> None:
    """An incident that realises a risk is a reason to reassess it (ISO 27001 8.2, 6.1): its review becomes due now,
    which puts it in the risk owner's tasks. Recorded on the incident timeline; the risk change is audited."""
    from keystone.risk.models import Risk

    r = session.get(Risk, inc.risk_id) if inc.risk_id else None
    if r is None or r.status == "closed":
        return
    if r.review_date is None or r.review_date > today():
        r.review_date = today()
    _event(session, inc, actor, f"Linked to risk {r.ref} {r.title}; its review is now due so the owner can reassess it.", "system")


def _validate(inc: Incident) -> None:
    require_text(inc.title, "Title")
    if inc.category not in CATEGORIES:
        raise ValueError(f"category must be one of {CATEGORIES}")
    if inc.severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}")


def update_incident(session: Session, actor, incident_id: int, *, asset_ids: list[int] | None = None, **fields) -> Incident:
    authorize(session, actor, "incident.write")
    inc = get_or_404(session, Incident, incident_id)
    before, risk_before = inc.severity, inc.risk_id
    apply_fields(inc, fields, FIELDS)
    _validate(inc)
    if asset_ids is not None:
        inc.assets = list(session.scalars(select(Asset).where(Asset.id.in_(asset_ids))))
    if inc.severity != before:
        _event(session, inc, actor, f"Severity changed {before} → {inc.severity}.", "system")
    if inc.risk_id and inc.risk_id != risk_before:
        _risk_realised(session, inc, actor)
    session.flush()
    return inc


def add_note(session: Session, actor, incident_id: int, entry: str, when: datetime | None = None) -> IncidentEvent:
    authorize(session, actor, "incident.write")
    inc = get_or_404(session, Incident, incident_id)
    ev = _event(session, inc, actor, require_text(entry, "Timeline entry"), "note", when)
    session.flush()
    return ev


def move(session: Session, actor, incident_id: int, status: str, resolution: str | None = None) -> Incident:
    authorize(session, actor, "incident.write")
    inc = get_or_404(session, Incident, incident_id)
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    if status not in TRANSITIONS[inc.status]:
        raise ValueError(f"Cannot move from {inc.status} to {status}. Allowed: {', '.join(TRANSITIONS[inc.status])}.")
    if status == "closed":
        resolution = resolution or ("resolved" if inc.status == "recovered" else None)
        if resolution not in RESOLUTIONS:
            raise ValueError("Closing from triage needs a resolution: false_positive or duplicate.")
        if inc.status == "triage" and resolution == "resolved":
            raise ValueError("A real incident must be contained, eradicated and recovered before closing.")
        if resolution != "resolved" and (inc.status != "triage" or inc.contained_at is not None):
            # Only triage decides "not an incident". Once something was contained it was real, and closing it as a
            # false positive or duplicate would skip the root cause, lessons learned and notification checks below.
            raise ValueError("Only an incident still in triage, never contained, can be closed as a false positive or duplicate.")
        if resolution == "resolved":
            open_actions = session.scalar(select(IncidentAction.id).where(IncidentAction.incident_id == inc.id, IncidentAction.status == "open"))
            if open_actions:
                raise ValueError("Complete or remove the open response actions before closing.")
            if not (inc.root_cause or "").strip() or not (inc.lessons_learned or "").strip():
                raise ValueError("Record the root cause and lessons learned before closing (ISO 27001 A.5.27).")
            if notification_deadline(inc) and inc.regulator_notified_at is None and inc.notification_required:
                raise ValueError("A required regulator notification has not been recorded.")
        inc.resolution, inc.closed_at = resolution, utcnow()
    elif inc.status == "closed":
        inc.resolution, inc.closed_at = None, None
    if status == "contained" and inc.contained_at is None:
        inc.contained_at = utcnow()
    old = inc.status
    inc.status = status
    _event(session, inc, actor, f"Status {old} → {status}" + (f" ({resolution})" if status == "closed" else "") + ".", "status")
    session.flush()
    return inc


def record_notification(session: Session, actor, incident_id: int, when: datetime | None = None, note: str = "") -> Incident:
    authorize(session, actor, "incident.write")
    inc = get_or_404(session, Incident, incident_id)
    inc.regulator_notified_at = when or utcnow()
    inc.notification_required = True
    _event(session, inc, actor, "Regulator notified. " + note, "system", inc.regulator_notified_at)
    session.flush()
    return inc


def list_incidents(session: Session, include_closed: bool = True) -> list[Incident]:
    q = select(Incident).order_by(Incident.detected_at.desc())
    if not include_closed:
        q = q.where(Incident.status != "closed")
    return list(session.scalars(q))


def incident_attention(session: Session, now: datetime | None = None) -> dict[str, list[Incident]]:
    now = now or utcnow()
    open_ = [i for i in list_incidents(session) if i.status != "closed"]
    return {
        "open": open_,
        "notification_due": [i for i in open_ if (d := notification_deadline(i)) and i.regulator_notified_at is None and i.notification_required is not False],
        "notification_overdue": [i for i in open_ if (d := notification_deadline(i)) and i.regulator_notified_at is None and i.notification_required is not False and d < now],
        "containment_overdue": [i for i in open_ if i.status in ("new", "triage") and containment_due(i) < now],
    }


# ---- response actions, playbooks, evidence and follow-up (A.5.26-5.28, ISO/IEC 27035) ---------------------------

def add_action(session: Session, actor, incident_id: int, title: str, owner_id: int | None = None, due_date=None) -> IncidentAction:
    authorize(session, actor, "incident.write")
    inc = get_or_404(session, Incident, incident_id)
    if inc.status == "closed":
        raise ValueError("The incident is closed.")
    a = IncidentAction(incident_id=inc.id, title=require_text(title, "Action")[:300], owner_id=owner_id, due_date=due_date, status="open")
    session.add(a)
    session.flush()
    _event(session, inc, actor, f"Action added: {a.title}", "system")
    return a


def complete_action(session: Session, actor, action_id: int, done: bool = True) -> IncidentAction:
    authorize(session, actor, "incident.write")
    a = get_or_404(session, IncidentAction, action_id)
    a.status, a.done_at = ("done", utcnow()) if done else ("open", None)
    session.flush()
    inc = get_or_404(session, Incident, a.incident_id)
    _event(session, inc, actor, f"Action {'done' if done else 'reopened'}: {a.title}", "system")
    return a


def actions(session: Session, incident_id: int) -> list[IncidentAction]:
    return list(session.scalars(select(IncidentAction).where(IncidentAction.incident_id == incident_id).order_by(IncidentAction.status, IncidentAction.due_date, IncidentAction.id)))


def playbook(inc: Incident) -> list[dict]:
    steps = (load_config().get("playbooks") or {}).get(inc.category) or []
    done = inc.playbook_done or {}
    return [{"index": i, "step": str(step), "done": done.get(str(i))} for i, step in enumerate(steps)]


def tick_playbook(session: Session, actor, incident_id: int, index: int, done: bool) -> Incident:
    authorize(session, actor, "incident.write")
    inc = get_or_404(session, Incident, incident_id)
    steps = playbook(inc)
    if not 0 <= index < len(steps):
        raise ValueError("No such playbook step.")
    state = dict(inc.playbook_done or {})
    if done:
        state[str(index)] = {"by": getattr(actor, "display_name", None) or actor.username, "at": utcnow().isoformat(timespec="seconds")}
    else:
        state.pop(str(index), None)
    inc.playbook_done = state
    session.flush()
    _event(session, inc, actor, f"Playbook step {'done' if done else 'reopened'}: {steps[index]['step']}", "system")
    return inc


def add_evidence(session: Session, actor, incident_id: int, *, filename: str, data: bytes, description: str, source: str | None = None) -> IncidentEvidence:
    """Store a file as incident evidence with its SHA-256 and the first custody entry. The file is kept like any
    attachment (type and size checked, virus-scanned where set up); downloads go through `evidence_download`."""
    from keystone.core.attachments import save_attachment

    authorize(session, actor, "incident.write")
    inc = get_or_404(session, Incident, incident_id)
    att = save_attachment(session, actor, filename, data, "IncidentEvidence", inc.id)
    who = getattr(actor, "display_name", None) or actor.username
    now = utcnow()
    ev = IncidentEvidence(incident_id=inc.id, attachment_id=att.id, sha256=att.sha256, description=require_text(description, "Description")[:4000],
                          source=(source or "").strip()[:300] or None, collected_at=now, collected_by=who[:150],
                          custody=[{"at": now.isoformat(timespec="seconds"), "by": who, "action": f"collected ({att.filename}, SHA-256 {att.sha256[:16]}…)"}])
    session.add(ev)
    session.flush()
    _event(session, inc, actor, f"Evidence added: {att.filename} (SHA-256 {att.sha256})", "system")
    return ev


def evidence_items(session: Session, incident_id: int) -> list[IncidentEvidence]:
    return list(session.scalars(select(IncidentEvidence).where(IncidentEvidence.incident_id == incident_id).order_by(IncidentEvidence.id)))


def evidence_download(session: Session, actor, evidence_id: int):
    """The file, after checking it still matches the hash taken at collection and recording the download in its
    chain of custody (and the audit log)."""
    import hashlib

    from keystone.core.attachments import Attachment, read_attachment
    from keystone.core.audit import log_event

    authorize(session, actor, "incident.write")
    ev = get_or_404(session, IncidentEvidence, evidence_id)
    att = get_or_404(session, Attachment, ev.attachment_id)
    data = read_attachment(att)
    if hashlib.sha256(data).hexdigest() != ev.sha256:
        raise ValueError("The stored file no longer matches the hash taken when it was collected. Don't rely on it; report this.")
    who = getattr(actor, "display_name", None) or actor.username
    ev.custody = [*ev.custody, {"at": utcnow().isoformat(timespec="seconds"), "by": who, "action": "downloaded (hash verified)"}]
    session.flush()
    log_event(session, actor, "download", "IncidentEvidence", ev.id, f"Downloaded incident evidence {att.filename}")
    return att, data


def raise_nonconformity(session: Session, actor, incident_id: int):
    """Turn the incident's lessons into a nonconformity with corrective actions (ISO 27001 10.2)."""
    from keystone.improvement import service as improvement
    from keystone.improvement.models import Nonconformity

    authorize(session, actor, "nc.write")
    inc = get_or_404(session, Incident, incident_id)
    existing = session.scalar(select(Nonconformity).where(Nonconformity.incident_id == inc.id))
    if existing is not None:
        raise ValueError(f"Nonconformity {existing.ref} was already raised from this incident.")
    detail = "\n\n".join(x for x in (f"Root cause: {inc.root_cause}" if inc.root_cause else "", f"Lessons learned: {inc.lessons_learned}" if inc.lessons_learned else "") if x)
    nc = improvement.raise_nc(session, actor, title=f"Follow-up to incident {inc.ref}: {inc.title}"[:300], description=detail or inc.description or inc.title,
                              source="incident", incident_id=inc.id, severity="major" if inc.severity in ("high", "critical") else "minor", owner_id=inc.owner_id)
    _event(session, inc, actor, f"Nonconformity {nc.ref} raised", "system")
    return nc
