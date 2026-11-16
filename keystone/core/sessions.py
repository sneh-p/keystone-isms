"""Server-side web sessions. The cookie holds a random token; only its SHA-256 is stored."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta

from sqlalchemy import DateTime, ForeignKey, Integer, String, delete, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from .db import Base, utcnow
from .settings import get_settings

ABSOLUTE_HOURS = 12


class WebSession(Base):
    __tablename__ = "web_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(300))


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create(session: Session, user_id: int, ip: str | None = None, user_agent: str | None = None) -> tuple[str, WebSession]:
    token = secrets.token_urlsafe(32)
    ws = WebSession(token_hash=_hash(token), csrf_token=secrets.token_urlsafe(32), user_id=user_id, expires_at=utcnow() + timedelta(hours=ABSOLUTE_HOURS), ip=ip, user_agent=(user_agent or "")[:300])
    session.add(ws)
    session.flush()
    return token, ws


def resolve(session: Session, token: str | None) -> WebSession | None:
    """Return the live session for a cookie token, extending its idle window; None if invalid/expired."""
    if not token or len(token) > 200:
        return None
    ws = session.scalar(select(WebSession).where(WebSession.token_hash == _hash(token)))
    if ws is None:
        return None
    now = utcnow()
    idle = timedelta(minutes=get_settings().session_timeout_minutes)
    if ws.expires_at < now or ws.last_seen_at + idle < now:
        session.delete(ws)
        session.flush()
        return None
    ws.last_seen_at = now
    return ws


def csrf_ok(ws: WebSession, supplied: str | None) -> bool:
    return bool(supplied) and hmac.compare_digest(ws.csrf_token, supplied)


def destroy(session: Session, token: str | None) -> None:
    if token:
        session.execute(delete(WebSession).where(WebSession.token_hash == _hash(token)))


def destroy_all_for(session: Session, user_id: int) -> None:
    session.execute(delete(WebSession).where(WebSession.user_id == user_id))
