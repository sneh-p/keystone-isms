"""Workforce: people, invitations, onboarding/offboarding, training, device attestation."""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from functools import lru_cache

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core import auth, sessions
from keystone.core.attachments import save_attachment
from keystone.core.db import utcnow
from keystone.core.rbac import Role
from keystone.core.services import apply_fields, authorize, get_or_404, require_text, today
from keystone.core.settings import PROJECT_ROOT
from keystone.policies import service as pol

from .models import DEVICE_CHECKS, OFFBOARDING_ITEMS, PERSON_STATUSES, DeviceAttestation, Invitation, Person, TrainingCompletion

INVITE_DAYS = 7
TRAINING_VALID_DAYS = 365
DEVICE_VALID_DAYS = 180
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---- training content -----------------------------------------------------------------------

@lru_cache(maxsize=1)
def modules() -> list[dict]:
    out = []
    for p in sorted((PROJECT_ROOT / "content" / "training").glob("*.yaml")):
        m = yaml.safe_load(p.read_text(encoding="utf-8"))
        for q in m["quiz"]:
            if not 0 <= q["answer"] < len(q["options"]):
                raise ValueError(f"{p.name}: bad answer index")
        out.append(m)
    return out


def module(key: str) -> dict:
    for m in modules():
        if m["key"] == key:
            return m
    raise LookupError(f"Training module {key} not found")


def public_module(m: dict) -> dict:
    """Module for display: quiz answers are never sent to the browser."""
    return {k: v for k, v in m.items() if k != "quiz"} | {"quiz": [{"q": q["q"], "options": q["options"]} for q in m["quiz"]]}


# ---- people ------------------------------------------------------------------------------------

FIELDS = {"full_name", "email", "job_title", "department", "employment_type", "manager_id", "start_date", "end_date"}


def save_person(session: Session, actor, person_id: int | None = None, **fields) -> Person:
    authorize(session, actor, "people.write")
    p = get_or_404(session, Person, person_id) if person_id else Person(status="onboarding", employment_type="employee")
    if "email" in fields and fields["email"]:
        fields["email"] = fields["email"].strip().lower()
    apply_fields(p, fields, FIELDS)
    require_text(p.full_name, "Full name")
    if not EMAIL.match(p.email or ""):
        raise ValueError("Enter a valid email address.")
    if p.employment_type not in ("employee", "contractor"):
        raise ValueError("employment_type must be employee or contractor")
    if session.scalar(select(Person).where(Person.email == p.email, Person.id != (p.id or 0))):
        raise ValueError(f"{p.email} is already in the people directory.")
    session.add(p)
    session.flush()
    return p


def list_people(session: Session, include_offboarded: bool = False) -> list[Person]:
    q = select(Person).order_by(Person.full_name)
    if not include_offboarded:
        q = q.where(Person.status != "offboarded")
    return list(session.scalars(q))


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def invite(session: Session, actor, person_id: int) -> str:
    """Create a one-time sign-up token (returned once, stored hashed). Older open invites are revoked."""
    authorize(session, actor, "people.write")
    p = get_or_404(session, Person, person_id)
    if p.user_id:
        raise ValueError("This person already has a sign-in.")
    if p.status == "offboarded":
        raise ValueError("This person has been offboarded.")
    for old in session.scalars(select(Invitation).where(Invitation.person_id == p.id, Invitation.used_at.is_(None))):
        old.used_at = utcnow()  # revoke
    token = secrets.token_urlsafe(32)
    session.add(Invitation(person_id=p.id, token_hash=_hash(token), created_by_id=actor.id, created_at=utcnow(), expires_at=utcnow() + timedelta(days=INVITE_DAYS)))
    from keystone.core.audit import log_event

    log_event(session, actor, "invite", "Person", p.id, f"Invitation created for {p.email}")
    session.flush()
    return token


def _open_invite(session: Session, token: str) -> Invitation:
    if not token or len(token) > 200:
        raise LookupError("Invitation not found.")
    inv = session.scalar(select(Invitation).where(Invitation.token_hash == _hash(token)))
    if inv is None or inv.used_at is not None or inv.expires_at < utcnow():
        raise LookupError("This invitation link is invalid, used or expired. Ask for a new one.")
    return inv


def describe_invite(session: Session, token: str) -> dict:
    inv = _open_invite(session, token)
    p = session.get(Person, inv.person_id)
    return {"full_name": p.full_name, "email": p.email, "expires_at": inv.expires_at}


def accept_invite(session: Session, token: str, password: str) -> auth.User:
    inv = _open_invite(session, token)
    p = session.get(Person, inv.person_id)
    if session.scalar(select(auth.User).where(auth.User.username == p.email)):
        raise ValueError("An account with this email already exists; ask an administrator to link it.")
    auth.check_password_policy(password, p.email)
    user = auth.User(username=p.email, display_name=p.full_name, email=p.email, role=Role.EMPLOYEE.value, password_hash=auth.hash_password(password), must_change_password=False)
    session.info["actor"] = user
    session.add(user)
    session.flush()
    p.user_id = user.id
    if p.status == "onboarding" and p.start_date and p.start_date <= today():
        p.status = "active"
    inv.used_at = utcnow()
    session.flush()
    return user


def link_user(session: Session, actor, person_id: int, user_id: int | None) -> Person:
    """Link an existing staff account to a person record (so their portal tasks count)."""
    authorize(session, actor, "people.write")
    p = get_or_404(session, Person, person_id)
    if user_id and session.scalar(select(Person).where(Person.user_id == user_id, Person.id != p.id)):
        raise ValueError("That account is already linked to another person.")
    p.user_id = user_id
    session.flush()
    return p


def set_status(session: Session, actor, person_id: int, status: str) -> Person:
    authorize(session, actor, "people.write")
    p = get_or_404(session, Person, person_id)
    if status not in ("onboarding", "active", "offboarding"):
        raise ValueError("Use complete_offboarding to offboard someone.")
    if status == "offboarding":
        p.offboarding = p.offboarding or {}
        p.end_date = p.end_date or today()
    p.status = status
    session.flush()
    return p


def tick_offboarding(session: Session, actor, person_id: int, item: str, done: bool = True) -> Person:
    authorize(session, actor, "people.write")
    p = get_or_404(session, Person, person_id)
    if p.status != "offboarding":
        raise ValueError("Start offboarding first.")
    if item not in OFFBOARDING_ITEMS:
        raise ValueError(f"Unknown checklist item {item}")
    state = dict(p.offboarding or {})
    if done:
        state[item] = {"by": actor.username, "at": utcnow().isoformat(timespec="seconds")}
    else:
        state.pop(item, None)
    p.offboarding = state
    session.flush()
    return p


def complete_offboarding(session: Session, actor, person_id: int) -> Person:
    authorize(session, actor, "people.write")
    p = get_or_404(session, Person, person_id)
    missing = [OFFBOARDING_ITEMS[k] for k in OFFBOARDING_ITEMS if k not in (p.offboarding or {})]
    if missing:
        raise ValueError("Checklist incomplete: " + "; ".join(missing))
    if p.user_id:
        u = session.get(auth.User, p.user_id)
        if u.id == actor.id:
            raise ValueError("You cannot offboard yourself.")
        u.active = False
        sessions.destroy_all_for(session, u.id)
    p.status = "offboarded"
    session.flush()
    return p


# ---- compliance status ----------------------------------------------------------------------------

@dataclass
class PersonStatus:
    policies_total: int
    policies_done: int
    training_total: int
    training_done: int
    device_ok: bool | None  # None = no attestation yet
    devices: int

    @property
    def complete(self) -> bool:
        return self.policies_done == self.policies_total and self.training_done == self.training_total and self.device_ok is True

    def as_dict(self) -> dict:
        return self.__dict__ | {"complete": self.complete}


def _current_completions(session: Session, user_id: int, on: date) -> dict[str, TrainingCompletion]:
    out = {}
    for c in session.scalars(select(TrainingCompletion).where(TrainingCompletion.user_id == user_id, TrainingCompletion.passed.is_(True)).order_by(TrainingCompletion.completed_at)):
        if c.completed_at.date() >= on - timedelta(days=TRAINING_VALID_DAYS):
            m = next((m for m in modules() if m["key"] == c.module_key), None)
            if m and c.module_version >= m["version"]:
                out[c.module_key] = c
    return out


def device_issues(d: DeviceAttestation, on: date | None = None) -> list[str]:
    """What stops a device counting as secure, in words the employee can act on."""
    on = on or today()
    out = [f"Not confirmed: {label.rstrip('.')}" for k, label in DEVICE_CHECKS.items() if d.checks.get(k) is not True]
    if d.attested_at.date() < on - timedelta(days=DEVICE_VALID_DAYS):
        out.append(f"Last confirmed more than {DEVICE_VALID_DAYS} days ago; confirm the checks again")
    return out


def device_compliant(d: DeviceAttestation, on: date | None = None) -> bool:
    return not device_issues(d, on)


def status_for_user(session: Session, user: auth.User, on: date | None = None) -> PersonStatus:
    on = on or today()
    docs = [d for d in pol.documents(session) if d.requires_acknowledgement and d.status == "approved"]
    pending = pol.pending_for(session, user)
    devices = list(session.scalars(select(DeviceAttestation).where(DeviceAttestation.user_id == user.id)))
    return PersonStatus(
        policies_total=len(docs), policies_done=len(docs) - len(pending),
        training_total=len(modules()), training_done=len(_current_completions(session, user.id, on)),
        device_ok=None if not devices else all(device_compliant(d, on) for d in devices), devices=len(devices),
    )


def people_overview(session: Session) -> list[tuple[Person, PersonStatus | None]]:
    out = []
    for p in list_people(session):
        u = session.get(auth.User, p.user_id) if p.user_id else None
        out.append((p, status_for_user(session, u) if u else None))
    return out


# ---- portal actions (the signed-in user acting for themselves) ----------------------------------------

def submit_quiz(session: Session, user: auth.User, key: str, answers: list[int]) -> TrainingCompletion:
    authorize(session, user, "portal")
    m = module(key)
    if len(answers) != len(m["quiz"]):
        raise ValueError("Answer every question.")
    score = sum(1 for a, q in zip(answers, m["quiz"]) if a == q["answer"])
    c = TrainingCompletion(user_id=user.id, module_key=key, module_version=m["version"], score=score, out_of=len(m["quiz"]), passed=score >= m["pass_mark"], completed_at=utcnow())
    session.add(c)
    session.flush()
    return c


def my_training(session: Session, user: auth.User) -> list[dict]:
    done = _current_completions(session, user.id, today())
    return [{"key": m["key"], "title": m["title"], "minutes": m["minutes"], "summary": m["summary"], "version": m["version"], "completed_at": done[m["key"]].completed_at if m["key"] in done else None} for m in modules()]


def attest_device(session: Session, user: auth.User, *, device_name: str, os: str, checks: dict, filename: str | None = None, data: bytes | None = None) -> DeviceAttestation:
    authorize(session, user, "portal")
    require_text(device_name, "Device name")
    if os not in ("windows", "macos", "linux", "ios", "android", "other"):
        raise ValueError("Choose an operating system.")
    unknown = set(checks) - set(DEVICE_CHECKS)
    if unknown:
        raise ValueError(f"Unknown checks: {sorted(unknown)}")
    d = session.scalar(select(DeviceAttestation).where(DeviceAttestation.user_id == user.id, DeviceAttestation.device_name == device_name.strip())) or DeviceAttestation(user_id=user.id, device_name=device_name.strip())
    d.os, d.checks, d.attested_at = os, {k: bool(checks.get(k)) for k in DEVICE_CHECKS}, utcnow()
    session.add(d)
    session.flush()
    if data and filename:
        d.attachment_id = save_attachment(session, user, filename, data, "DeviceAttestation", d.id).id
        session.flush()
    return d


def my_devices(session: Session, user: auth.User) -> list[DeviceAttestation]:
    return list(session.scalars(select(DeviceAttestation).where(DeviceAttestation.user_id == user.id).order_by(DeviceAttestation.device_name)))
