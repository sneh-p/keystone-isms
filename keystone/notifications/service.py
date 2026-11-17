"""Inbox and daily email digest.

Items come from the same rules as the dashboard's "My tasks" (keystone/reporting/dashboard.my_tasks), limited to what
needs action within NOTIFY_WITHIN_DAYS, plus integration failures for people who manage integrations. A scheduled job
refreshes every user's inbox; items that no longer need action are marked resolved.
"""

from __future__ import annotations

from email.message import EmailMessage

import hashlib
import logging
import re
import smtplib
import ssl
from datetime import date, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from keystone.core import secrets
from keystone.core.auth import User
from keystone.core.rbac import has_permission
from keystone.core.services import authorize, today

from . import mailer
from .models import Notification, NotificationPrefs, SmtpSettings

_LOG = logging.getLogger(__name__)
NOTIFY_WITHIN_DAYS = 14
EVENT_KINDS = ("mention", "asm", "system", "ticket")  # one-off notifications; the hourly refresh never resolves these
EMAIL = r"^[^@\s]{1,64}@[^@\s]{1,255}$"


def _key(*parts) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:64]


def _kind(page: str) -> str:
    return page.strip("/").split("/")[0].split("?")[0] or "general"


def items_for(session: Session, user: User, on: date | None = None, routed: dict | None = None) -> list[dict]:
    """What this user should be told about today."""
    from keystone.reporting.dashboard import my_tasks

    on = on or today()
    out = []
    for t in my_tasks(session, user, on, routed):
        if t["due"] is None or t["due"] <= on + timedelta(days=NOTIFY_WITHIN_DAYS):
            out.append({"key": _key("task", t["what"], t["page"], t["due"]), "kind": _kind(t["page"]), "title": t["what"], "page": t["page"], "due": t["due"]})
    if has_permission(user, "integration.manage"):
        from keystone.integrations.models import Integration

        for i in session.scalars(select(Integration).where(Integration.enabled.is_(True), Integration.last_status == "error")):
            out.append({"key": _key("integration", i.id, i.last_run_at), "kind": "integrations", "title": f"Integration {i.name} failed on its last run", "page": "/integrations", "due": None})
    # Questionnaires returned through the vendor portal: the vendor's owner, or vendor managers if it has none.
    from keystone.tprm.models import Vendor, VendorQuestionnaire

    q = select(VendorQuestionnaire, Vendor).join(Vendor, Vendor.id == VendorQuestionnaire.vendor_id).where(VendorQuestionnaire.status == "received")
    for vq, v in session.execute(q):
        if v.owner_id == user.id or (v.owner_id is None and has_permission(user, "vendor.write")):
            out.append({"key": _key("vq", vq.id, vq.received_at), "kind": "questionnaires", "title": f"Review the questionnaire returned by {v.name}", "page": f"/questionnaires?open={vq.id}", "due": None})
    return out


def refresh(session: Session, user: User, on: date | None = None, routed: dict | None = None) -> int:
    """Add new items to the user's inbox and resolve ones that no longer apply. Returns the number added."""
    now = datetime.now()
    items = {i["key"]: i for i in items_for(session, user, on, routed)}
    # Only derived items resolve themselves; event notifications (mentions) stay until read.
    existing = {n.key: n for n in session.scalars(select(Notification).where(Notification.user_id == user.id, Notification.resolved_at.is_(None), Notification.kind.not_in(EVENT_KINDS)))}
    for k, n in existing.items():
        if k not in items:
            n.resolved_at = now
    known = set(session.scalars(select(Notification.key).where(Notification.user_id == user.id)))
    added = 0
    for k, i in items.items():
        if k not in known:
            session.add(Notification(user_id=user.id, key=k, kind=i["kind"], title=i["title"][:500], page=i["page"][:200], due=i["due"], created_at=now))
            added += 1
    session.flush()
    return added


def refresh_all(session: Session, on: date | None = None) -> int:
    from keystone.reporting.routing import routed_items

    routed = routed_items(session, on)  # once for everyone
    return sum(refresh(session, u, on, routed) for u in list(session.scalars(select(User).where(User.active.is_(True)))))


# ---- the signed-in user's own inbox (every role: permission "portal", plus a user-id filter) ----------------

def inbox(session: Session, actor, include_resolved: bool = False, limit: int = 100) -> list[Notification]:
    authorize(session, actor, "portal")
    return _items(session, actor.id, include_resolved, limit)


def _items(session: Session, user_id: int, include_resolved: bool = False, limit: int = 100) -> list[Notification]:
    q = select(Notification).where(Notification.user_id == user_id)
    if not include_resolved:
        q = q.where(Notification.resolved_at.is_(None))
    return list(session.scalars(q.order_by(Notification.read_at.is_not(None), Notification.due.is_(None), Notification.due, Notification.id.desc()).limit(limit)))


def unread_count(session: Session, actor) -> int:
    authorize(session, actor, "portal")
    return session.scalar(select(func.count(Notification.id)).where(Notification.user_id == actor.id, Notification.read_at.is_(None), Notification.resolved_at.is_(None))) or 0


def mark_read(session: Session, actor, ids: list[int] | None = None) -> int:
    """Mark the given items (or all) as read. Items of other users are refused as not found."""
    authorize(session, actor, "portal")
    q = select(Notification).where(Notification.user_id == actor.id, Notification.read_at.is_(None))
    if ids is not None:
        rows = list(session.scalars(select(Notification).where(Notification.id.in_(ids))))
        if len(rows) != len(set(ids)) or any(n.user_id != actor.id for n in rows):
            raise LookupError("Notification not found")
        q = q.where(Notification.id.in_(ids))
    rows = list(session.scalars(q))
    now = datetime.now()
    for n in rows:
        n.read_at = now
    session.flush()
    return len(rows)


def prefs(session: Session, user: User) -> NotificationPrefs:
    p = session.get(NotificationPrefs, user.id)
    if p is None:
        p = NotificationPrefs(user_id=user.id, email_digest=True)
        session.add(p)
        session.flush()
    return p


# Digest categories, from the page a notification links to. In-app notifications are never muted; only the email.
CATEGORIES = {
    "work": ("Tasks and mentions", ("tasks", "calendar", "workload", "mention", "general")),
    "compliance": ("Controls, evidence and policies", ("controls", "evidence", "policies", "soa", "frameworks")),
    "risk": ("Risks and assets", ("risks", "assets")),
    "findings": ("Attack surface and configuration", ("attack-surface", "asm", "configuration", "config")),
    "operations": ("Incidents, nonconformities and audits", ("incidents", "nonconformities", "audits", "reviews")),
    "vendors": ("Vendors and questionnaires", ("vendors", "questionnaires", "assessments", "security-questionnaires")),
    "privacy": ("Privacy, continuity and access reviews", ("privacy", "continuity", "access-reviews")),
    "system": ("Integrations and system", ("integrations", "settings", "system", "ticket")),
}
_CATEGORY_OF = {kind: cat for cat, (_, kinds) in CATEGORIES.items() for kind in kinds}


def category(kind: str) -> str:
    return _CATEGORY_OF.get(kind, "work")


def set_prefs(session: Session, actor, email_digest: bool | None = None, digest_muted: list[str] | None = None) -> NotificationPrefs:
    authorize(session, actor, "portal")
    p = prefs(session, actor)
    if email_digest is not None:
        p.email_digest = bool(email_digest)
    if digest_muted is not None:
        unknown = set(digest_muted) - set(CATEGORIES)
        if unknown:
            raise ValueError(f"Unknown categories: {', '.join(sorted(unknown))}.")
        p.digest_muted = sorted(set(digest_muted)) or None
    session.flush()
    return p


# ---- SMTP settings (administrators) -------------------------------------------------------------------

def smtp(session: Session) -> SmtpSettings:
    s = session.scalar(select(SmtpSettings))
    if s is None:
        s = SmtpSettings()
        session.add(s)
        session.flush()
    return s


def smtp_view(s: SmtpSettings) -> dict:
    """Never returns the password, only whether one is stored."""
    return {"enabled": s.enabled, "host": s.host, "port": s.port, "security": s.security, "username": s.username, "password_set": bool(s.password_enc),
            "from_address": s.from_address, "from_name": s.from_name, "digest_hour_utc": s.digest_hour_utc, "last_error": s.last_error,
            "private_hosts_allowed": sorted(mailer.private_allowlist())}


def update_smtp(session: Session, actor, **fields) -> SmtpSettings:
    authorize(session, actor, "users.manage")
    s = smtp(session)
    allowed = {"enabled", "host", "port", "security", "username", "password", "clear_password", "from_address", "from_name", "digest_hour_utc"}
    if set(fields) - allowed:
        raise ValueError(f"fields not editable here: {', '.join(sorted(set(fields) - allowed))}")
    host = mailer.validate_host(fields["host"]) if fields.get("host") else (None if "host" in fields else s.host)
    port = int(fields.get("port", s.port))
    security = fields.get("security", s.security)
    if port not in mailer.ALLOWED_PORTS:
        raise ValueError(f"Port must be one of {', '.join(map(str, mailer.ALLOWED_PORTS))}.")
    if security not in ("starttls", "tls"):
        raise ValueError("Security must be starttls or tls.")
    sender = (fields.get("from_address", s.from_address) or "").strip() or None
    if sender and not re.match(EMAIL, sender):
        raise ValueError("Enter a valid sender address.")
    name = (fields.get("from_name", s.from_name) or "").strip() or "Keystone ISMS"
    if any(c in name for c in "\r\n<>\""):
        raise ValueError("The sender name can't contain line breaks, quotes or angle brackets.")
    hour = int(fields.get("digest_hour_utc", s.digest_hour_utc))
    if not 0 <= hour <= 23:
        raise ValueError("Digest hour must be 0-23 (UTC).")
    enabled = bool(fields.get("enabled", s.enabled))
    if enabled and not (host and sender):
        raise ValueError("Set the relay host and the sender address before turning email on.")
    # SC-SSRF-003: a stored password is only ever sent to the host it was entered for.
    host_changed = host != s.host
    s.host, s.port, s.security, s.from_address, s.from_name, s.digest_hour_utc, s.enabled = host, port, security, sender, name, hour, enabled
    if "username" in fields:
        s.username = (fields["username"] or "").strip() or None
    if fields.get("clear_password") or (host_changed and not fields.get("password")):
        s.password_enc, s.password_host = None, None
    if fields.get("password"):
        s.password_enc, s.password_host = secrets.encrypt(fields["password"]), host
    session.flush()
    return s


def _cfg(s: SmtpSettings) -> dict:
    if not s.host or not s.from_address:
        raise ValueError("Email is not set up.")
    password = None
    if s.password_enc:
        if s.password_host != s.host:  # defence in depth for SC-SSRF-003
            raise ValueError("The stored password belongs to a different host; enter it again.")
        password = secrets.decrypt(s.password_enc)
    return {"host": s.host, "port": s.port, "security": s.security, "username": s.username, "password": password}


def send_test(session: Session, actor, to: str | None = None) -> str:
    """Send a test message to the administrator (or the given address)."""
    authorize(session, actor, "users.manage")
    s = smtp(session)
    to = (to or actor.email or "").strip()
    if not re.match(EMAIL, to):
        raise ValueError("Add an email address to your account, or enter one to send the test to.")
    msg = mailer.build(s.from_address or "", s.from_name, to, "Keystone ISMS test message", "This is a test message from Keystone ISMS. Email digests are working.\n")
    try:
        mailer.send(_cfg(s), [msg])
    except (smtplib.SMTPException, OSError, ValueError) as e:
        s.last_error = _describe(e)
        session.flush()
        raise ValueError(f"Sending failed: {s.last_error}") from None
    s.last_error = None
    session.flush()
    return to


def send_now(session: Session, messages: list[tuple[str, str, str]]) -> int:
    """Best-effort immediate emails (to, subject, body) for system alerts. Does nothing when email isn't set up; a
    failure is recorded in smtp_settings.last_error, never raised, because the inbox notification already exists."""
    s = smtp(session)
    if not messages or not s.enabled or not s.from_address:
        return 0
    msgs = [mailer.build(s.from_address, s.from_name, to, subject, body) for to, subject, body in messages if re.match(EMAIL, to or "")]
    try:
        mailer.send(_cfg(s), msgs)
    except (smtplib.SMTPException, OSError, ValueError) as e:
        s.last_error = _describe(e)
        session.flush()
        return 0
    return len(msgs)


def _describe(e: Exception) -> str:
    """A short reason without echoing server responses that might contain credentials or addresses."""
    if isinstance(e, smtplib.SMTPAuthenticationError):
        return "the relay rejected the user name or password"
    if isinstance(e, (ssl.SSLError, ssl.CertificateError)):
        return "TLS failed (certificate not valid for the host, or TLS not supported)"
    if isinstance(e, smtplib.SMTPRecipientsRefused):
        return "the relay refused the recipient"
    if isinstance(e, (TimeoutError, ConnectionError, OSError)) and not isinstance(e, smtplib.SMTPException):
        return f"could not connect ({type(e).__name__})"
    if isinstance(e, ValueError):
        return str(e)
    return type(e).__name__


# ---- daily digest --------------------------------------------------------------------------------------

def digest_body(user: User, items: list[Notification]) -> str:
    from keystone.core.settings import get_settings

    base = get_settings().public_url
    lines = [f"Hello {user.display_name},", "", f"{len(items)} item{'s' if len(items) != 1 else ''} in Keystone need{'' if len(items) != 1 else 's'} your attention:", ""]
    for n in items[:50]:
        due = f" (due {n.due:%d %b %Y})" if n.due else ""
        lines.append(f"- {n.title}{due}")
    if len(items) > 50:
        lines.append(f"- and {len(items) - 50} more")
    lines += ["", f"Open Keystone: {base}/" if base else "Open Keystone to see them.", "",
              "You receive this daily digest because email digests are on in your Keystone account. Turn them off under My account."]
    return "\n".join(lines)


def send_digests(session: Session, now: datetime | None = None) -> int:
    """Send each opted-in user one digest per day, at or after the configured hour. Returns messages sent."""
    now = now or datetime.now()
    s = smtp(session)
    if not s.enabled or now.hour < s.digest_hour_utc:
        return 0
    batch: list[tuple[NotificationPrefs, list[Notification], EmailMessage]] = []
    for u in session.scalars(select(User).where(User.active.is_(True))):
        p = prefs(session, u)
        if not p.email_digest or p.last_digest_on == now.date() or not u.email or not re.match(EMAIL, u.email):
            continue
        muted = set(p.digest_muted or [])
        items = [n for n in _items(session, u.id) if n.read_at is None and category(n.kind) not in muted]
        if not items:
            continue
        batch.append((p, items, mailer.build(s.from_address or "", s.from_name, u.email, f"Keystone: {len(items)} item{'s' if len(items) != 1 else ''} need your attention", digest_body(u, items))))
    if not batch:
        return 0
    try:
        mailer.send(_cfg(s), [m for _, _, m in batch])
    except (smtplib.SMTPException, OSError, ValueError) as e:
        s.last_error = _describe(e)
        _LOG.warning("email digest failed: %s", s.last_error)
        session.flush()
        return 0
    for p, items, _ in batch:
        p.last_digest_on = now.date()
        for n in items:
            n.emailed_at = now
    s.last_error = None
    session.flush()
    return len(batch)


# ---- emailing a link (invitations, vendor portal links, Trust Center access) ------------------------------

def email_link(session: Session, actor, *, to: str | None, subject: str, intro: str, path: str, closing: str, entity: tuple[str, int | None]) -> str:
    """Send one plain-text email containing a Keystone link. The link is built from KEYSTONE_PUBLIC_URL (never from the
    request), and the audit entry names the recipient but never the link, which may carry an access token. Raises
    ValueError (and so rolls back the caller's change, e.g. a new token) if the email can't be sent."""
    from keystone.core.audit import log_event
    from keystone.core.settings import get_settings

    to = (to or "").strip()
    if not re.match(EMAIL, to):
        raise ValueError("There's no valid email address to send this to.")
    base = get_settings().public_url
    if not base:
        raise ValueError("Set KEYSTONE_PUBLIC_URL on the server so emailed links point to the right address; copy the link instead for now.")
    s = smtp(session)
    if not s.enabled:
        raise ValueError("Email isn't set up (Settings > Email); copy the link instead.")
    from keystone.org.service import get_org

    org = get_org(session)
    body = f"{intro}\n\n{base}{path}\n\n{closing}\n\n-- \nSent by {org.name if org else 'Keystone'} with Keystone ISMS.\n"
    msg = mailer.build(s.from_address or "", s.from_name, to, subject, body)
    try:
        mailer.send(_cfg(s), [msg])
    except (smtplib.SMTPException, OSError, ValueError) as e:
        s.last_error = _describe(e)
        raise ValueError(f"The email couldn't be sent ({s.last_error}). Nothing was changed; try again or copy the link instead.") from None
    log_event(session, actor, "email", entity[0], entity[1], f"Link emailed to {to}: {subject}")
    session.flush()
    return to
