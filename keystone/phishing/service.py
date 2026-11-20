"""Phishing simulations (ISO 27001 A.6.3): practice emails written by Keystone, sent through the organisation's own
email relay to a chosen audience, measuring who clicks and who reports.

Safeguards: the landing page explains the warning signs and never asks for a password or anything else; link tokens
are random, single-purpose and stored as hashes; individual results are visible only to people who manage people;
someone other than the person who prepared a campaign launches it; emails go only to the organisation's own users.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from functools import lru_cache

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.auth import User
from keystone.core.db import utcnow
from keystone.core.rbac import has_permission
from keystone.core.services import authorize, get_or_404, require_text
from keystone.core.settings import PROJECT_ROOT, get_settings

from .models import PhishingCampaign, PhishingTarget

BATCH = 25  # emails per run of the sending job
CAMPAIGN_DAYS = 14  # a campaign completes by itself after this many days


@lru_cache(maxsize=1)
def templates() -> dict[str, dict]:
    out = {}
    for p in sorted((PROJECT_ROOT / "content" / "phishing").glob("*.yaml")):
        t = yaml.safe_load(p.read_text(encoding="utf-8"))
        if "{link}" not in t["body"]:
            raise ValueError(f"{p.name}: the body needs a {{link}}")
        out[t["key"]] = t
    return out


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _pct(part: int, whole: int) -> float:
    return round(100 * part / whole, 1) if whole else 0.0


def campaigns(session: Session, actor) -> list[PhishingCampaign]:
    authorize(session, actor, "people.write")
    return list(session.scalars(select(PhishingCampaign).order_by(PhishingCampaign.id.desc())))


def create(session: Session, actor, *, name: str, template: str, audience: dict | None) -> PhishingCampaign:
    from keystone.core import audience as aud

    authorize(session, actor, "people.write")
    if template not in templates():
        raise ValueError("Choose a template.")
    c = PhishingCampaign(name=require_text(name, "Name")[:200], template=template, audience=aud.clean(audience), status="draft")
    session.add(c)
    session.flush()
    return c


def recipients(session: Session, c: PhishingCampaign) -> list[tuple[User, object]]:
    """Active users with a portal and an email address, in the campaign's audience (with their People record)."""
    from keystone.core import audience as aud

    out = []
    for u in session.scalars(select(User).where(User.active.is_(True))):
        if not u.email or not has_permission(u, "portal"):
            continue
        person = aud.person_of(session, u.id)
        if aud.matches(c.audience, person):
            out.append((u, person))
    return out


def launch(session: Session, actor, campaign_id: int) -> PhishingCampaign:
    """Start sending. Someone other than whoever prepared the campaign launches it, email must be set up, and
    KEYSTONE_PUBLIC_URL must be set (the links point to it)."""
    from keystone.notifications.service import smtp

    authorize(session, actor, "people.write")
    c = get_or_404(session, PhishingCampaign, campaign_id)
    if c.status != "draft":
        raise ValueError("Only a draft campaign can be launched.")
    if c.created_by_id is not None and c.created_by_id == actor.id:
        raise ValueError("Segregation of duties: someone other than whoever prepared the campaign launches it.")
    s = smtp(session)
    if not s.enabled or not s.from_address:
        raise ValueError("Set up email first (Settings → Email): the practice emails go through your relay.")
    if not get_settings().public_url:
        raise ValueError("Set KEYSTONE_PUBLIC_URL first: the links in the emails point to it.")
    people = recipients(session, c)
    if not people:
        raise ValueError("Nobody in this audience has a portal account with an email address.")
    for u, p in people:
        session.add(PhishingTarget(campaign_id=c.id, user_id=u.id, department=getattr(p, "department", None)))
    c.status, c.launched_by_id, c.launched_at = "running", actor.id, utcnow()
    session.flush()
    return c


def send_batch(session: Session) -> int:
    """Send the next emails of running campaigns (called by the scheduler). Tokens are made here and only their hash
    is kept, so a link can't be rebuilt from the database."""
    from keystone.notifications import mailer
    from keystone.notifications.service import _cfg, smtp

    s = smtp(session)
    base = get_settings().public_url
    if not s.enabled or not s.from_address or not base:
        return 0
    pending = list(session.scalars(select(PhishingTarget).join(PhishingCampaign, PhishingCampaign.id == PhishingTarget.campaign_id)
                                   .where(PhishingCampaign.status == "running", PhishingTarget.sent_at.is_(None), PhishingTarget.send_error.is_(None)).limit(BATCH)))
    msgs, sent = [], []
    for t in pending:
        u = session.get(User, t.user_id)
        c = session.get(PhishingCampaign, t.campaign_id)
        if u is None or c is None or not u.email:
            t.send_error = "No email address"
            continue
        tpl = templates()[c.template]
        raw = secrets.token_urlsafe(24)
        t.token_hash = _hash(raw)
        body = tpl["body"].replace("{link}", f"{base}/phish#t={raw}")
        msgs.append(mailer.build(s.from_address, tpl["from_name"], u.email, tpl["subject"], body))
        sent.append(t)
    if msgs:
        try:
            mailer.send(_cfg(s), msgs)
        except (OSError, ValueError) as e:
            for t in sent:
                t.token_hash = None
            s.last_error = type(e).__name__
            session.flush()
            return 0
        for t in sent:
            t.sent_at = utcnow()
    session.flush()
    return len(sent)


def click(session: Session, token: str) -> dict:
    """Someone opened a practice link. Records the first click and returns what the landing page explains."""
    if not token or len(token) > 100:
        raise LookupError("Not found")
    t = session.scalar(select(PhishingTarget).where(PhishingTarget.token_hash == _hash(token)))
    if t is None:
        raise LookupError("Not found")
    c = session.get(PhishingCampaign, t.campaign_id)
    if c is None or c.status not in ("running", "completed"):
        raise LookupError("Not found")
    if c.status == "running":
        t.clicks += 1
        t.clicked_at = t.clicked_at or utcnow()
        session.flush()
    tpl = templates()[c.template]
    return {"title": tpl["title"], "subject": tpl["subject"], "red_flags": tpl["red_flags"]}


def mark_reported(session: Session, user_id: int) -> None:
    """A portal report of a suspicious email during a running campaign counts as reporting it."""
    t = session.scalar(select(PhishingTarget).join(PhishingCampaign, PhishingCampaign.id == PhishingTarget.campaign_id)
                       .where(PhishingTarget.user_id == user_id, PhishingCampaign.status == "running", PhishingTarget.sent_at.is_not(None),
                              PhishingTarget.reported_at.is_(None)).order_by(PhishingTarget.sent_at.desc()))
    if t is not None:
        t.reported_at = utcnow()
        session.flush()


def complete(session: Session, actor, campaign_id: int) -> PhishingCampaign:
    authorize(session, actor, "people.write")
    c = get_or_404(session, PhishingCampaign, campaign_id)
    if c.status not in ("draft", "running"):
        raise ValueError("This campaign has already ended.")
    c.status, c.completed_at = ("completed" if c.status == "running" else "cancelled"), utcnow()
    session.flush()
    return c


def complete_due(session: Session) -> int:
    """Complete running campaigns older than CAMPAIGN_DAYS (called by the scheduler)."""
    n = 0
    for c in session.scalars(select(PhishingCampaign).where(PhishingCampaign.status == "running", PhishingCampaign.launched_at < utcnow() - timedelta(days=CAMPAIGN_DAYS))):
        c.status, c.completed_at = "completed", utcnow()
        n += 1
    session.flush()
    return n


def results(session: Session, actor, campaign_id: int) -> dict:
    """Totals and results by department, and (for people who manage people) each person's result."""
    authorize(session, actor, "people.write")
    c = get_or_404(session, PhishingCampaign, campaign_id)
    ts = list(session.scalars(select(PhishingTarget).where(PhishingTarget.campaign_id == c.id)))
    sent = [t for t in ts if t.sent_at]
    clicked = sum(1 for t in sent if t.clicked_at)
    reported = sum(1 for t in sent if t.reported_at)
    by_dep: dict[str, dict] = {}
    for t in sent:
        d = by_dep.setdefault(t.department or "No department", {"sent": 0, "clicked": 0, "reported": 0})
        d["sent"] += 1
        d["clicked"] += 1 if t.clicked_at else 0
        d["reported"] += 1 if t.reported_at else 0
    names = {u.id: u.display_name for u in session.scalars(select(User))}
    return {"targets": len(ts), "sent": len(sent), "clicked": clicked, "reported": reported,
            "click_rate": _pct(clicked, len(sent)), "report_rate": _pct(reported, len(sent)),
            "by_department": [{"department": k, **v} for k, v in sorted(by_dep.items())],
            "people": [{"name": names.get(t.user_id), "department": t.department, "sent_at": t.sent_at, "clicked_at": t.clicked_at, "reported_at": t.reported_at,
                        "error": t.send_error} for t in ts]}


def latest_click_rate(session: Session) -> float | None:
    c = session.scalar(select(PhishingCampaign).where(PhishingCampaign.status == "completed").order_by(PhishingCampaign.completed_at.desc()))
    if c is None:
        return None
    ts = [t for t in session.scalars(select(PhishingTarget).where(PhishingTarget.campaign_id == c.id)) if t.sent_at]
    return _pct(sum(1 for t in ts if t.clicked_at), len(ts)) if ts else None
