"""Apply an HR system's people to the People register.

- Match by the HR system's id for the person, then by work email (case-insensitive). People without a work email are
  skipped and counted (Keystone needs one to invite them).
- New joiners are added as onboarding. Name, job title, department, employment type, start and end date and manager
  follow the HR system; status and checklists stay Keystone's.
- A leaver (end date reached, or marked inactive) who is onboarding or active moves to offboarding, which opens the
  offboarding checklist, and everyone who manages people is notified. Keystone never completes offboarding or
  deactivates accounts on its own: that stays a person's decision (or the identity provider's, via SCIM).
- People in Keystone that the HR system doesn't list are left alone (contractors are often kept only here).
"""

from __future__ import annotations

from datetime import date
from types import SimpleNamespace

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from keystone.core.db import utcnow
from keystone.core.services import today

from .models import Person


def sync(session: Session, integration, result, on: date | None = None) -> dict:
    from keystone.core.auth import User, expired
    from keystone.core.rbac import has_permission
    from keystone.notifications.models import Notification

    on = on or today()
    session.info["actor"] = SimpleNamespace(id=None, username=f"hr:{integration.name}"[:150], role=None, active=True)
    by_ext = {p.hr_external_id: p for p in session.scalars(select(Person).where(Person.hr_integration_id == integration.id, Person.hr_external_id.is_not(None)))}
    counts = {"read": len(result.people), "added": 0, "updated": 0, "leavers": 0, "skipped_no_email": 0}
    managers: list[tuple[Person, str]] = []
    leavers: list[Person] = []
    for hp in result.people:
        p = by_ext.get(hp.external_id)
        email = (hp.email or "").strip().lower() or None
        if p is None and email:
            p = session.scalar(select(Person).where(func.lower(Person.email) == email))
        if p is None:
            if not email or "@" not in email:
                counts["skipped_no_email"] += 1
                continue
            if hp.left or (hp.end_date and hp.end_date < on):
                continue  # someone who left before Keystone knew them: nothing to onboard or offboard
            p = Person(full_name=hp.full_name, email=email, status="onboarding", employment_type=hp.employment_type or "employee")
            session.add(p)
            counts["added"] += 1
        before = (p.full_name, p.job_title, p.department, p.employment_type, p.start_date, p.end_date)
        p.full_name = hp.full_name or p.full_name
        if email and email != (p.email or "").lower() and not session.scalar(select(Person.id).where(func.lower(Person.email) == email, Person.id != (p.id or 0))):
            p.email = email
        p.job_title = hp.job_title if hp.job_title is not None else p.job_title
        p.department = hp.department if hp.department is not None else p.department
        p.employment_type = hp.employment_type or p.employment_type
        p.start_date = hp.start_date or p.start_date
        p.end_date = hp.end_date or p.end_date
        p.hr_integration_id, p.hr_external_id = integration.id, hp.external_id[:100]
        if p.id and before != (p.full_name, p.job_title, p.department, p.employment_type, p.start_date, p.end_date):
            counts["updated"] += 1
        if hp.manager_email:
            managers.append((p, hp.manager_email.lower()))
        if (hp.left or (hp.end_date and hp.end_date <= on)) and p.status in ("onboarding", "active"):
            p.status, p.offboarding = "offboarding", p.offboarding or {}
            p.end_date = p.end_date or on
            leavers.append(p)
            counts["leavers"] += 1
    session.flush()
    for p, mgr_email in managers:
        m = session.scalar(select(Person).where(func.lower(Person.email) == mgr_email))
        if m is not None and m.id != p.id:
            p.manager_id = m.id
    if leavers:
        stamp = utcnow()
        holders = [u for u in session.scalars(select(User).where(User.active.is_(True))) if not expired(u) and has_permission(u, "people.write")]
        for u in holders:
            for p in leavers:
                key = f"hr-leaver:{p.id}:{p.end_date}"[:64]
                if session.scalar(select(Notification.id).where(Notification.user_id == u.id, Notification.key == key)) is None:
                    session.add(Notification(user_id=u.id, key=key, kind="system", title=f"{p.full_name} left on {p.end_date}: complete their offboarding (access, assets)",
                                             page=f"/people?open={p.id}", created_at=stamp))
    session.flush()
    return counts


def describe(counts: dict) -> str:
    s = f"Read {counts['read']} people: {counts['added']} added, {counts['updated']} updated, {counts['leavers']} moved to offboarding"
    if counts["skipped_no_email"]:
        s += f"; {counts['skipped_no_email']} skipped without a work email"
    return s
