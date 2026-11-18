"""Reports of suspicious activity from the employee portal (ISO 27001 A.6.8), and their triage.

Anyone with a portal (every role) can report and see their own reports and the reply. Incident handlers
(incident.write) see every report and decide: open an incident from it, or close it with a reply.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.auth import User
from keystone.core.db import utcnow
from keystone.core.rbac import has_permission
from keystone.core.services import authorize, get_or_404, require_text

from . import service as inc
from .models import REPORT_CATEGORY, REPORT_KINDS, SEVERITIES, SecurityReport

OUTCOMES = {"incident": "Handled as an incident", "phishing_blocked": "Phishing: blocked, thank you", "not_a_threat": "Checked: not a threat",
            "duplicate": "Already reported by someone else"}
CLOSE_OUTCOMES = ("phishing_blocked", "not_a_threat", "duplicate")


def _notify(session: Session, users, key: str, title: str, page: str) -> None:
    from keystone.notifications.models import Notification

    for u in users:
        session.add(Notification(user_id=u.id, key=key[:64], kind="report", title=title[:500], page=page, created_at=datetime.now()))


def submit(session: Session, user: User, *, kind: str, description: str, sender: str | None = None, subject: str | None = None,
           where: str | None = None, clicked: bool | None = None) -> SecurityReport:
    authorize(session, user, "portal")
    if kind not in REPORT_KINDS:
        raise ValueError("Choose what happened.")
    r = SecurityReport(reporter_id=user.id, kind=kind, description=require_text(description, "What happened")[:8000], status="new",
                       sender=(sender or "").strip()[:320] or None, subject=(subject or "").strip()[:300] or None,
                       where=(where or "").strip()[:300] or None, clicked=clicked)
    session.add(r)
    session.flush()
    handlers = [u for u in session.scalars(select(User).where(User.active.is_(True))) if u.id != user.id and has_permission(u, "incident.write")]
    urgent = " (they clicked or entered a password)" if clicked else ""
    _notify(session, handlers, f"report:{r.id}", f"New report {r.ref}: {REPORT_KINDS[kind]}{urgent}", f"/security-reports?open={r.id}")
    session.flush()
    return r


def mine(session: Session, user: User) -> list[SecurityReport]:
    authorize(session, user, "portal")
    return list(session.scalars(select(SecurityReport).where(SecurityReport.reporter_id == user.id).order_by(SecurityReport.id.desc()).limit(50)))


def reports(session: Session, actor, include_closed: bool = True) -> list[SecurityReport]:
    authorize(session, actor, "incident.write")
    q = select(SecurityReport).order_by(SecurityReport.id.desc())
    if not include_closed:
        q = q.where(SecurityReport.status == "new")
    return list(session.scalars(q))


def to_incident(session: Session, actor, report_id: int, *, severity: str, reply: str | None = None):
    """Open an incident from a report. The reporter is told it is being handled (the incident stays with the team)."""
    authorize(session, actor, "incident.write")
    r = get_or_404(session, SecurityReport, report_id)
    if r.status != "new":
        raise ValueError("This report was already triaged.")
    if severity not in SEVERITIES:
        raise ValueError("Choose a severity.")
    reporter = session.get(User, r.reporter_id)
    details = [f"Reported by {reporter.display_name if reporter else 'an employee'} ({r.ref}): {r.description}"]
    for label, v in (("Sender", r.sender), ("Subject", r.subject), ("Where", r.where)):
        if v:
            details.append(f"{label}: {v}")
    if r.clicked:
        details.append("The reporter clicked a link, opened an attachment or entered a password.")
    i = inc.report_incident(session, actor, title=f"{REPORT_KINDS[r.kind]} reported by {reporter.display_name if reporter else 'an employee'}"[:300],
                            category=REPORT_CATEGORY[r.kind], severity=severity, description="\n".join(details), reported_by=reporter.display_name if reporter else None,
                            detected_at=r.created_at)
    r.status, r.outcome, r.incident_id = "incident", "incident", i.id
    r.reply = (reply or "").strip()[:2000] or "Thank you. We're looking into it."
    r.triaged_by_id, r.triaged_at = actor.id, utcnow()
    if reporter is not None:
        _notify(session, [reporter], f"report-reply:{r.id}", f"Your report {r.ref}: {OUTCOMES['incident']}", "/portal")
    session.flush()
    return i


def close(session: Session, actor, report_id: int, *, outcome: str, reply: str) -> SecurityReport:
    authorize(session, actor, "incident.write")
    r = get_or_404(session, SecurityReport, report_id)
    if r.status != "new":
        raise ValueError("This report was already triaged.")
    if outcome not in CLOSE_OUTCOMES:
        raise ValueError("Choose how it was resolved.")
    r.status, r.outcome, r.reply = "closed", outcome, require_text(reply, "Reply to the reporter")[:2000]
    r.triaged_by_id, r.triaged_at = actor.id, utcnow()
    reporter = session.get(User, r.reporter_id)
    if reporter is not None:
        _notify(session, [reporter], f"report-reply:{r.id}", f"Your report {r.ref}: {OUTCOMES[outcome]}", "/portal")
    session.flush()
    return r
