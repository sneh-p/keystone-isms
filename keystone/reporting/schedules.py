"""Scheduled report emails.

- Reports: the board summary (PDF) or any register export (Excel), built as the person who last saved the schedule, so
  it contains only what they may see, and only while they're still active and allowed to read.
- Recipients are Keystone users, never typed-in addresses, and at send time only those still active, unexpired and
  allowed to read get it (with an email address on their account). A schedule can't be used to send ISMS data
  outside the organisation's Keystone accounts.
- Sent by the daily scheduled-reports job; attachments over 10 MB are replaced by a link.
"""

from __future__ import annotations

from datetime import date, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.auth import User, expired
from keystone.core.db import utcnow
from keystone.core.rbac import has_permission
from keystone.core.services import add_months, authorize, get_or_404, require_text, today

from .models import ReportSchedule

FREQUENCIES = ("weekly", "monthly", "quarterly")
MAX_ATTACHMENT = 10 * 1024 * 1024


def reports() -> dict[str, str]:
    from .registers import REGISTERS

    return {"board_pdf": "Board summary (PDF)", **{name: f"{name} (Excel)" for name in REGISTERS}}


def advance(d: date, frequency: str) -> date:
    return d + timedelta(days=7) if frequency == "weekly" else add_months(d, 1 if frequency == "monthly" else 3)


def schedules(session: Session, actor) -> list[ReportSchedule]:
    authorize(session, actor, "org.write")
    return list(session.scalars(select(ReportSchedule).order_by(ReportSchedule.name)))


def save(session: Session, actor, schedule_id: int | None = None, **fields) -> ReportSchedule:
    authorize(session, actor, "org.write")
    s = get_or_404(session, ReportSchedule, schedule_id) if schedule_id else ReportSchedule(enabled=True, frequency="monthly", recipient_ids=[])
    if "name" in fields:
        s.name = require_text(fields["name"], "Name")[:150]
    if "report" in fields:
        if fields["report"] not in reports():
            raise ValueError("Choose a report from the list.")
        s.report = fields["report"]
    if "frequency" in fields:
        if fields["frequency"] not in FREQUENCIES:
            raise ValueError("Weekly, monthly or quarterly.")
        s.frequency = fields["frequency"]
    if "recipient_ids" in fields:
        ids = sorted(set(fields["recipient_ids"] or []))
        if not ids or len(ids) > 25:
            raise ValueError("Choose between 1 and 25 recipients.")
        users = {u.id: u for u in session.scalars(select(User).where(User.id.in_(ids)))}
        bad = [i for i in ids if i not in users or not has_permission(users[i], "read")]
        if bad:
            raise ValueError("Recipients must be Keystone users who can read the ISMS (not employees-only accounts).")
        s.recipient_ids = ids
    if "next_run_on" in fields:
        if fields["next_run_on"] < today():
            raise ValueError("The first send date can't be in the past.")
        s.next_run_on = fields["next_run_on"]
    if "enabled" in fields:
        s.enabled = bool(fields["enabled"])
    if not s.name or not s.report or not s.recipient_ids or not s.next_run_on:
        raise ValueError("Name, report, recipients and first send date are required.")
    s.created_by_id = actor.id  # the report is built as whoever last saved the schedule
    session.add(s)
    session.flush()
    return s


def delete(session: Session, actor, schedule_id: int) -> None:
    authorize(session, actor, "org.write")
    session.delete(get_or_404(session, ReportSchedule, schedule_id))
    session.flush()


def _build(session: Session, owner: User, report: str) -> tuple[str, str, bytes]:
    from keystone.org.service import get_org

    if report == "board_pdf":
        from .board import report_pdf

        return f"Board_summary_{today().isoformat()}.pdf", "application/pdf", report_pdf(session, owner)
    from . import registers

    o = get_org(session)
    return f"{report.replace(' ', '_')}_{today().isoformat()}.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", registers.export(session, owner, report, o.name if o else "")


def send(session: Session, s: ReportSchedule) -> int:
    """Build and email one schedule now. Returns how many people it went to; errors are stored on the schedule."""
    from keystone.core.settings import get_settings
    from keystone.notifications import mailer
    from keystone.notifications import service as ntf

    owner = session.get(User, s.created_by_id) if s.created_by_id else None
    if owner is None or not owner.active or expired(owner) or not has_permission(owner, "read"):
        s.last_error = "The person who created this schedule can no longer read the ISMS; edit it to take it over."
        return 0
    smtp = ntf.smtp(session)
    if not smtp.enabled or not smtp.from_address:
        s.last_error = "Email isn't set up (Settings → Email)."
        return 0
    recipients = [u for u in session.scalars(select(User).where(User.id.in_(s.recipient_ids or [])))
                  if u.active and not expired(u) and has_permission(u, "read") and u.email]
    if not recipients:
        s.last_error = "None of the recipients can receive it (inactive, no email address, or no read access)."
        return 0
    filename, mime, data = _build(session, owner, s.report)
    base = get_settings().public_url
    link = f"{base}/reports" if base else "Keystone → Reports"
    attach = [(filename, mime, data)] if len(data) <= MAX_ATTACHMENT else []
    body = f"{s.name}: {reports().get(s.report, s.report)}, {today():%d %B %Y}.\n\n" + ("The report is attached." if attach else f"The report is too large to attach; download it from {link}.") + \
           "\n\nYou receive this because you're a recipient of this scheduled report in Keystone.\n"
    msgs = [mailer.build(smtp.from_address, smtp.from_name, u.email or "", f"Keystone: {s.name}"[:200], body, attach) for u in recipients]
    try:
        mailer.send(ntf._cfg(smtp), msgs)
    except (OSError, ValueError) as e:
        s.last_error = ntf._describe(e)[:300]
        return 0
    s.last_sent_at, s.last_error = utcnow(), None
    return len(msgs)


def run_due(session: Session, on: date | None = None) -> int:
    on = on or today()
    n = 0
    for s in list(session.scalars(select(ReportSchedule).where(ReportSchedule.enabled.is_(True), ReportSchedule.next_run_on <= on))):
        n += send(session, s)
        while s.next_run_on <= on:  # move on even after a failure, so a broken schedule doesn't send a backlog later
            s.next_run_on = advance(s.next_run_on, s.frequency)
    session.flush()
    return n


def send_now(session: Session, actor, schedule_id: int) -> ReportSchedule:
    authorize(session, actor, "org.write")
    s = get_or_404(session, ReportSchedule, schedule_id)
    send(session, s)
    session.flush()
    return s
