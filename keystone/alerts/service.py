"""The security alert inbox.

Tools (EDR, SIEM, email security, cloud, backup) send alerts to POST /api/inbound/alerts with their own source
token. Keystone stores what it needs, folds repeats into one alert with a count, links the alert to an asset and its
owner by host name, and notifies the owner (or the incident handlers) about high and critical ones. Handlers
acknowledge, open an incident from an alert, or close it with a reason. Nothing is ever sent back to the tools.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from keystone.core.auth import User
from keystone.core.db import utcnow
from keystone.core.rbac import has_permission
from keystone.core.services import authorize, get_or_404, require_text

from .models import CATEGORIES, CLOSE_REASONS, SEVERITIES, Alert, AlertSource

SOURCE_PREFIX = "kalt_"  # marks Keystone alert-source tokens (public), e.g. for secret scanners
SOURCE_KINDS = {"edr": "EDR / antivirus", "siem": "SIEM or log platform", "email": "Email security", "cloud": "Cloud security", "identity": "Identity provider",
                "backup": "Backup", "ci": "CI / build pipeline", "other": "Other"}
REPEAT_WINDOW = timedelta(hours=24)
MAX_PULLED = 2000  # alerts taken from one integration run
MAX_SOURCES = 50
INCIDENT_CATEGORY = {c: c for c in CATEGORIES} | {"vulnerability": "misconfiguration", "backup": "other"}


class SourceRejected(Exception):
    pass


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


# ---- sources (integration.manage) ----------------------------------------------------------------------------------

def sources(session: Session, actor) -> list[AlertSource]:
    authorize(session, actor, "integration.manage")
    return list(session.scalars(select(AlertSource).order_by(AlertSource.name)))


def create_source(session: Session, actor, name: str, kind: str) -> tuple[AlertSource, str]:
    """A new source and its token, returned once (only its hash is stored)."""
    authorize(session, actor, "integration.manage")
    if kind not in SOURCE_KINDS:
        raise ValueError("Choose the kind of tool.")
    if (session.scalar(select(func.count(AlertSource.id))) or 0) >= MAX_SOURCES:
        raise ValueError(f"At most {MAX_SOURCES} sources.")
    raw = SOURCE_PREFIX + secrets.token_urlsafe(32)
    s = AlertSource(name=require_text(name, "Name")[:100], kind=kind, token_hash=_hash(raw), enabled=True, received=0)
    session.add(s)
    session.flush()
    return s, raw


def rotate_token(session: Session, actor, source_id: int) -> tuple[AlertSource, str]:
    authorize(session, actor, "integration.manage")
    s = get_or_404(session, AlertSource, source_id)
    if s.integration_id is not None:
        raise ValueError("Alerts from this source are pulled by an integration: it has no token.")
    raw = SOURCE_PREFIX + secrets.token_urlsafe(32)
    s.token_hash = _hash(raw)
    session.flush()
    return s, raw


def set_enabled(session: Session, actor, source_id: int, enabled: bool) -> AlertSource:
    authorize(session, actor, "integration.manage")
    s = get_or_404(session, AlertSource, source_id)
    s.enabled = bool(enabled)
    session.flush()
    return s


def pulled_source(session: Session, integration) -> AlertSource:
    """The inbox source for alerts an integration pulls from its tool. It has no usable token: its stored hash belongs to
    a random value nobody is given, so nothing can post to it."""
    s = session.scalar(select(AlertSource).where(AlertSource.integration_id == integration.id))
    if s is None:
        s = AlertSource(name=f"{integration.name} (pulled)"[:100], kind="edr", token_hash=_hash(secrets.token_urlsafe(32)), enabled=True, integration_id=integration.id)
        session.add(s)
        session.flush()
    return s


def receive_pulled(session: Session, integration, items: list[dict]) -> int:
    """Store alerts an integration fetched; ones already in the inbox (same id) aren't counted again. Returns how many are new."""
    source = pulled_source(session, integration)
    if not source.enabled:
        return 0
    new = 0
    for it in items[:MAX_PULLED]:
        ext = str(it.get("external_id") or "")[:200] or None
        if ext is None or session.scalar(select(Alert.id).where(Alert.source_id == source.id, Alert.external_id == ext)) is not None:
            continue
        severity = str(it.get("severity")) if it.get("severity") in SEVERITIES else "medium"
        category = str(it.get("category")) if it.get("category") in CATEGORIES else "other"
        link = it.get("link") if isinstance(it.get("link"), str) and it["link"].startswith("https://") else None
        _, created = receive(session, source, title=str(it.get("title") or "Alert")[:300], severity=severity, category=category, external_id=ext,
                             host=(str(it["host"])[:253] if it.get("host") else None), account=(str(it["account"])[:320] if it.get("account") else None),
                             description=(str(it["description"])[:8000] if it.get("description") else None), link=link, occurred_at=it.get("occurred_at"))
        new += created
    return new


def resolve_source(session: Session, header: str | None) -> AlertSource:
    if not header or not header.startswith("Bearer ") or len(header) > 300:
        raise SourceRejected("Source token required.")
    raw = header[7:].strip()
    if not raw.startswith(SOURCE_PREFIX):
        raise SourceRejected("Invalid source token.")
    digest = _hash(raw)
    s = session.scalar(select(AlertSource).where(AlertSource.token_hash == digest))
    if s is None or not hmac.compare_digest(s.token_hash, digest) or not s.enabled or s.integration_id is not None:
        raise SourceRejected("Invalid or disabled source token.")
    return s


# ---- receiving ---------------------------------------------------------------------------------------------------------

def _match_asset(session: Session, host: str | None):
    """The asset an alert is about, by host name: an asset with that name, or a device the attack surface tools report
    (linked to an asset)."""
    if not host:
        return None
    from keystone.asm.models import AsmDevice
    from keystone.assets.models import Asset

    h = host.strip().lower()
    a = session.scalar(select(Asset).where(func.lower(Asset.name) == h))
    if a is not None:
        return a
    d = session.scalar(select(AsmDevice).where((func.lower(AsmDevice.name) == h) | (func.lower(AsmDevice.hostname) == h), AsmDevice.asset_id.is_not(None)))
    return session.get(Asset, d.asset_id) if d is not None and d.asset_id else None


def receive(session: Session, source: AlertSource, *, title: str, severity: str, category: str, external_id: str | None = None, host: str | None = None,
            account: str | None = None, description: str | None = None, link: str | None = None, occurred_at: datetime | None = None) -> tuple[Alert, bool]:
    """Store an alert, or count a repeat of an open one. Returns (alert, is_new)."""
    if severity not in SEVERITIES or category not in CATEGORIES:
        raise ValueError("Unknown severity or category.")
    if link and not link.startswith("https://"):
        raise ValueError("The link must be an https address.")
    now = utcnow()
    seen = min(occurred_at.replace(tzinfo=None) if occurred_at else now, now)
    fp = hashlib.sha256("|".join([title.strip().lower(), (host or "").strip().lower(), (account or "").strip().lower()]).encode()).hexdigest()
    existing = None
    if external_id:
        existing = session.scalar(select(Alert).where(Alert.source_id == source.id, Alert.external_id == external_id))
    else:
        existing = session.scalar(select(Alert).where(Alert.source_id == source.id, Alert.fingerprint == fp, Alert.external_id.is_(None),
                                                      Alert.status.in_(("new", "acknowledged")), Alert.last_seen >= now - REPEAT_WINDOW).order_by(Alert.id.desc()))
    source.last_received_at, source.received = now, source.received + 1
    if existing is not None:
        existing.count += 1
        existing.last_seen = max(existing.last_seen, seen)
        if SEVERITIES.index(severity) > SEVERITIES.index(existing.severity):
            existing.severity = severity  # an escalation
        session.flush()
        return existing, False
    asset = _match_asset(session, host)
    a = Alert(source_id=source.id, external_id=external_id or None, fingerprint=fp, title=title.strip()[:300], severity=severity, category=category,
              host=(host or "").strip()[:253] or None, account=(account or "").strip()[:320] or None, description=(description or "").strip()[:8000] or None,
              link=link or None, first_seen=seen, last_seen=seen, count=1, status="new", asset_id=asset.id if asset else None,
              owner_id=asset.owner_id if asset else None)
    session.add(a)
    session.flush()
    if severity in ("high", "critical"):
        _notify_new(session, a, source)
    if severity == "critical":
        from keystone.oncall.service import page_on_call

        page_on_call(session, f"Critical alert from {source.name}: {a.title}", f"/alerts?open={a.id}", f"alert:{a.id}")
    return a, True


def _notify_new(session: Session, a: Alert, source: AlertSource) -> None:
    from keystone.notifications.models import Notification

    owner = session.get(User, a.owner_id) if a.owner_id else None
    users = [owner] if owner is not None and owner.active and has_permission(owner, "read") else []
    users += [u for u in session.scalars(select(User).where(User.active.is_(True))) if has_permission(u, "incident.write") and u not in users]
    for u in users:
        session.add(Notification(user_id=u.id, key=f"alert:{a.id}", kind="asm", title=f"{a.severity.title()} alert from {source.name}: {a.title}"[:500],
                                 page=f"/alerts?open={a.id}", created_at=datetime.now()))
    from keystone.outbound.service import emit

    emit(session, "alert.received", title=f"{a.severity.title()} alert from {source.name}: {a.title}"[:300], severity=a.severity, ref=a.ref, page=f"/alerts?open={a.id}")


# ---- handling (incident.write) ---------------------------------------------------------------------------------------

def alerts(session: Session, actor, open_only: bool = False) -> list[Alert]:
    authorize(session, actor, "incident.write")
    q = select(Alert).order_by(Alert.last_seen.desc()).limit(1000)
    if open_only:
        q = q.where(Alert.status.in_(("new", "acknowledged")))
    return list(session.scalars(q))


def _open(session: Session, alert_id: int) -> Alert:
    a = get_or_404(session, Alert, alert_id)
    if a.status not in ("new", "acknowledged"):
        raise ValueError("This alert was already handled.")
    return a


def acknowledge(session: Session, actor, alert_id: int) -> Alert:
    authorize(session, actor, "incident.write")
    a = _open(session, alert_id)
    a.status, a.handled_by_id, a.handled_at = "acknowledged", actor.id, utcnow()
    session.flush()
    return a


def to_incident(session: Session, actor, alert_id: int, severity: str | None = None):
    from keystone.incidents import service as inc

    authorize(session, actor, "incident.write")
    a = _open(session, alert_id)
    source = session.get(AlertSource, a.source_id)
    sev = severity or ("critical" if a.severity == "critical" else "high" if a.severity == "high" else "medium" if a.severity == "medium" else "low")
    lines = [f"From {source.name if source else 'a security tool'} ({a.ref}, seen {a.count} time(s), first {a.first_seen:%Y-%m-%d %H:%M} UTC)."]
    for label, v in (("Host", a.host), ("Account", a.account), ("Details", a.description), ("In the tool", a.link)):
        if v:
            lines.append(f"{label}: {v}")
    i = inc.report_incident(session, actor, title=a.title[:300], category=INCIDENT_CATEGORY.get(a.category, "other"), severity=sev, description="\n".join(lines),
                            detected_at=a.first_seen, reported_by=source.name if source else None, asset_ids=[a.asset_id] if a.asset_id else None)
    a.status, a.incident_id, a.handled_by_id, a.handled_at = "incident", i.id, actor.id, utcnow()
    session.flush()
    return i


def close(session: Session, actor, alert_id: int, reason: str, note: str) -> Alert:
    authorize(session, actor, "incident.write")
    a = _open(session, alert_id)
    if reason not in CLOSE_REASONS:
        raise ValueError("Choose why it is closed.")
    a.status, a.close_reason, a.note = "closed", reason, require_text(note, "Note")[:4000]
    a.handled_by_id, a.handled_at = actor.id, utcnow()
    session.flush()
    return a
