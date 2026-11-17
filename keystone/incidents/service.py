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

from .models import CATEGORIES, RESOLUTIONS, SEVERITIES, STATUSES, Incident, IncidentEvent

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
        if resolution == "resolved":
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
