"""On-call alerting: a critical incident or alert pages whoever is on call (in-app and an immediate email, plus the
chat and webhook destinations that want the event). If nobody acknowledges within the rota's time, the next member
is paged, and after everyone, the ISMS managers. Phone and SMS would need an outside provider and aren't used."""

from __future__ import annotations

from datetime import date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.auth import User
from keystone.core.db import utcnow
from keystone.core.rbac import has_permission
from keystone.core.services import authorize, get_or_404, require_text, today

from .models import OnCallRota, Page

MAX_MEMBERS = 30


def on_call(r: OnCallRota, on: date | None = None, offset: int = 0) -> int | None:
    """The member on call on a day (offset 1: the next one in the rotation)."""
    if not r.member_ids:
        return None
    on = on or today()
    turns = max(0, (on - r.start_on).days) // max(1, r.rotation_days)
    return r.member_ids[(turns + offset) % len(r.member_ids)]


def rotas(session: Session, actor) -> list[OnCallRota]:
    authorize(session, actor, "read")
    return list(session.scalars(select(OnCallRota).order_by(OnCallRota.name)))


def save(session: Session, actor, rota_id: int | None = None, *, name: str, member_ids: list[int], start_on: date, rotation_days: int,
         escalate_after_minutes: int, active: bool = True) -> OnCallRota:
    authorize(session, actor, "org.write")
    if not member_ids or len(member_ids) > MAX_MEMBERS or len(set(member_ids)) != len(member_ids):
        raise ValueError(f"Choose 1 to {MAX_MEMBERS} different people, in rotation order.")
    for uid in member_ids:
        u = session.get(User, uid)
        if u is None or not u.active or not has_permission(u, "incident.write"):
            raise ValueError("Every member must be an active user who can handle incidents.")
    if not 1 <= rotation_days <= 31 or not 5 <= escalate_after_minutes <= 240:
        raise ValueError("Rotate every 1 to 31 days; escalate after 5 to 240 minutes.")
    r = get_or_404(session, OnCallRota, rota_id) if rota_id else OnCallRota()
    r.name, r.member_ids, r.start_on = require_text(name, "Name")[:100], list(member_ids), start_on
    r.rotation_days, r.escalate_after_minutes, r.active = rotation_days, escalate_after_minutes, bool(active)
    session.add(r)
    session.flush()
    return r


def _send(session: Session, p: Page) -> None:
    from keystone.core.settings import get_settings
    from keystone.notifications.models import Notification
    from keystone.notifications.service import send_now

    u = session.get(User, p.user_id)
    if u is None:
        return
    session.add(Notification(user_id=u.id, key=f"page:{p.id}", kind="system", title=f"On call: {p.title}"[:500], page=f"/on-call?page={p.id}", created_at=datetime.now()))
    if u.email:
        base = get_settings().public_url
        link = f"{base}/on-call?page={p.id}" if base else "Keystone → Operations → On-call"
        p.emailed = send_now(session, [(u.email, f"[Keystone on call] {p.title}"[:200], f"You are on call.\n\n{p.title}\n\nAcknowledge and open it: {link}\n")]) > 0


def page_on_call(session: Session, title: str, page: str, source: str) -> list[Page]:
    """Page whoever is on call on every active rota (called when a critical incident or alert arrives)."""
    out = []
    for r in session.scalars(select(OnCallRota).where(OnCallRota.active.is_(True))):
        uid = on_call(r)
        if uid is None or session.scalar(select(Page.id).where(Page.rota_id == r.id, Page.source == source)):
            continue
        p = Page(rota_id=r.id, user_id=uid, level=0, title=title[:300], page=page[:200], source=source[:60], created_at=utcnow())
        session.add(p)
        session.flush()
        _send(session, p)
        out.append(p)
    session.flush()
    return out


def acknowledge(session: Session, actor, page_id: int) -> Page:
    """Acknowledge a page: only the person paged (or an escalation of the same call) can."""
    authorize(session, actor, "incident.write")
    p = get_or_404(session, Page, page_id)
    if p.user_id != actor.id:
        raise LookupError("Not found")
    now = utcnow()
    for q in session.scalars(select(Page).where(Page.rota_id == p.rota_id, Page.source == p.source, Page.acked_at.is_(None))):
        q.acked_at = now  # one acknowledgement stops the whole call
    session.flush()
    return p


def escalate(session: Session, now: datetime | None = None) -> int:
    """Page the next person for calls nobody acknowledged in time (called every few minutes)."""
    now = now or utcnow()
    n = 0
    for p in list(session.scalars(select(Page).where(Page.acked_at.is_(None), Page.escalated_at.is_(None)))):
        r = session.get(OnCallRota, p.rota_id)
        if r is None or p.created_at > now - timedelta(minutes=r.escalate_after_minutes):
            continue
        p.escalated_at = now
        nxt = on_call(r, offset=p.level + 1) if p.level + 1 < len(r.member_ids) else None
        targets = [nxt] if nxt is not None else [u.id for u in session.scalars(select(User).where(User.active.is_(True)))
                                                 if has_permission(u, "org.write") and has_permission(u, "incident.write")]
        for uid in targets:
            q = Page(rota_id=r.id, user_id=uid, level=p.level + 1, title=f"Escalated: {p.title}"[:300], page=p.page, source=p.source, created_at=now)
            session.add(q)
            session.flush()
            _send(session, q)
            n += 1
    session.flush()
    return n


def pages(session: Session, actor, limit: int = 100) -> list[Page]:
    authorize(session, actor, "incident.write")
    return list(session.scalars(select(Page).order_by(Page.id.desc()).limit(limit)))
