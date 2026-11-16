"""Local user accounts: argon2id password hashes, lockout, password policy."""

from __future__ import annotations

from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import Boolean, DateTime, Integer, String, func, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from .audit import log_event
from .db import Audited, Base, TimestampMixin, utcnow
from .rbac import Role, require
from .settings import get_settings

_hasher = PasswordHasher()
# Used to equalise timing when the username does not exist.
_DUMMY_HASH = _hasher.hash("keystone-dummy-password")


class User(Audited, TimestampMixin, Base):
    __tablename__ = "users"
    __audit_redact__ = ("password_hash",)
    REF_PREFIX = "USR"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(150), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    role: Mapped[str] = mapped_column(String(30), nullable=False, default=Role.VIEWER.value)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # Time-limited accounts (required for auditors): sign-in and every request are refused after this moment.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def __repr__(self) -> str:
        return f"<User {self.username} ({self.role})>"


class AuthError(Exception):
    """Login failed. The message is safe to show to the user."""


class PasswordPolicyError(ValueError):
    pass


def check_password_policy(password: str, username: str = "") -> None:
    s = get_settings()
    problems = []
    if len(password) < s.min_password_length:
        problems.append(f"at least {s.min_password_length} characters")
    classes = sum(
        [
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        ]
    )
    if classes < 3:
        problems.append("at least three of: lowercase, uppercase, digit, symbol")
    if username and username.lower() in password.lower():
        problems.append("must not contain the username")
    if problems:
        raise PasswordPolicyError("Password needs " + "; ".join(problems) + ".")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def _normalise(username: str) -> str:
    return username.strip().lower()


def expired(user: User, now: datetime | None = None) -> bool:
    return user.expires_at is not None and user.expires_at <= (now or utcnow())


def _check_expiry(role: str, expires_at: datetime | None, changing: bool) -> None:
    if role == Role.AUDITOR.value and expires_at is None:
        raise ValueError("Auditor accounts need an expiry date.")
    if changing and expires_at is not None and expires_at <= utcnow():
        raise ValueError("The expiry must be in the future.")


def create_user(session: Session, actor, *, username: str, display_name: str, password: str, role: Role | str = Role.VIEWER, email: str | None = None, must_change_password: bool = True, expires_at: datetime | None = None) -> User:
    """Create an account. The very first account may be created without an actor (bootstrap) and is always admin."""
    bootstrap = session.scalar(select(func.count(User.id))) == 0
    if not bootstrap:
        require(actor, "users.manage")
        session.info["actor"] = actor
    username = _normalise(username)
    if not username:
        raise ValueError("username is required")
    if session.scalar(select(User).where(User.username == username)):
        raise ValueError(f"user {username!r} already exists")
    check_password_policy(password, username)
    final_role = (Role.ADMIN if bootstrap else Role(role)).value
    _check_expiry(final_role, expires_at, changing=True)
    user = User(
        expires_at=expires_at,
        username=username,
        display_name=display_name.strip() or username,
        email=email,
        role=final_role,
        password_hash=hash_password(password),
        must_change_password=must_change_password and not bootstrap,
    )
    session.add(user)
    session.flush()
    return user


def needs_bootstrap(session: Session) -> bool:
    return session.scalar(select(func.count(User.id))) == 0


def authenticate(session: Session, username: str, password: str) -> User:
    s = get_settings()
    user = session.scalar(select(User).where(User.username == _normalise(username)))
    if user is None:
        try:
            _hasher.verify(_DUMMY_HASH, password)
        except VerificationError:
            pass
        log_event(session, None, "login_failed", "User", None, "Unknown username")
        raise AuthError("Invalid username or password.")
    now = utcnow()
    if not user.active or expired(user, now):
        log_event(session, user, "login_failed", "User", user.id, "Account disabled" if not user.active else "Account expired")
        raise AuthError("Invalid username or password.")
    if user.locked_until and user.locked_until > now:
        log_event(session, user, "login_failed", "User", user.id, "Account locked")
        raise AuthError("Account temporarily locked after repeated failures. Try again later.")
    try:
        _hasher.verify(user.password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        user.failed_logins += 1
        if user.failed_logins >= s.max_failed_logins:
            user.locked_until = now + timedelta(minutes=s.lockout_minutes)
            user.failed_logins = 0
        session.flush()
        log_event(session, user, "login_failed", "User", user.id, "Wrong password")
        raise AuthError("Invalid username or password.")
    if _hasher.check_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = now
    session.flush()
    log_event(session, user, "login", "User", user.id, "Signed in")
    return user


def change_password(session: Session, user: User, current: str, new: str) -> None:
    try:
        _hasher.verify(user.password_hash, current)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        raise AuthError("Current password is incorrect.") from None
    session.info["actor"] = user
    check_password_policy(new, user.username)
    if current == new:
        raise PasswordPolicyError("New password must differ from the current one.")
    user.password_hash = hash_password(new)
    user.must_change_password = False
    session.flush()


def admin_reset_password(session: Session, actor, user: User, new: str) -> None:
    require(actor, "users.manage")
    session.info["actor"] = actor
    check_password_policy(new, user.username)
    user.password_hash = hash_password(new)
    user.must_change_password = True
    user.failed_logins = 0
    user.locked_until = None
    session.flush()


_UNSET = object()


def update_user(session: Session, actor, user: User, *, role: str | None = None, active: bool | None = None, display_name: str | None = None, email: str | None = None, expires_at=_UNSET) -> User:
    require(actor, "users.manage")
    session.info["actor"] = actor
    if user.id == actor.id and (active is False or (role and role != Role.ADMIN.value) or (expires_at is not _UNSET and expires_at is not None)):
        raise ValueError("You cannot disable, demote or set an expiry on your own account.")
    new_role = Role(role).value if role is not None else user.role
    new_expiry = user.expires_at if expires_at is _UNSET else expires_at
    _check_expiry(new_role, new_expiry, changing=expires_at is not _UNSET)
    if expires_at is not _UNSET:
        user.expires_at = expires_at
    if role is not None:
        user.role = Role(role).value
    if active is not None:
        user.active = active
    if display_name is not None:
        user.display_name = display_name
    if email is not None:
        user.email = email
    session.flush()
    return user


def list_users(session: Session, active_only: bool = False) -> list[User]:
    q = select(User).order_by(User.display_name)
    if active_only:
        q = q.where(User.active.is_(True))
    return list(session.scalars(q))
