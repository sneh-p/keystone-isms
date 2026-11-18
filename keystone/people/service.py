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

from .models import DEVICE_CHECKS, OFFBOARDING_ITEMS, PERSON_STATUSES, DeviceAttestation, ExternalTraining, Invitation, Person, TrainingCompletion, TrainingModule

INVITE_DAYS = 7
TRAINING_VALID_DAYS = 365
DEFAULT_DUE_DAYS = 30
DEVICE_VALID_DAYS = 180
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---- training content -----------------------------------------------------------------------
# Built-in modules are Keystone's own (content/training/*.yaml). Organisations add their own (TrainingModule), and can
# switch any module off (TrainingAssignment.active). Quiz answers never leave the server (public_module).

@lru_cache(maxsize=1)
def builtin_modules() -> tuple[dict, ...]:
    out = []
    for p in sorted((PROJECT_ROOT / "content" / "training").glob("*.yaml")):
        m = yaml.safe_load(p.read_text(encoding="utf-8"))
        for q in m["quiz"]:
            if not 0 <= q["answer"] < len(q["options"]):
                raise ValueError(f"{p.name}: bad answer index")
        out.append(m | {"source": "builtin"})
    return tuple(out)


def _custom(m: TrainingModule) -> dict:
    return {"key": m.key, "title": m.title, "summary": m.summary, "minutes": m.minutes, "version": m.version, "body": m.body,
            "quiz": m.quiz, "pass_mark": m.pass_mark, "source": "custom", "id": m.id, "copied_from": m.copied_from}


def modules(session: Session, include_off: bool = False) -> list[dict]:
    """Every training module: built-in ones first, then the organisation's own. Switched-off ones only on request."""
    from .models import TrainingAssignment

    off = set(session.scalars(select(TrainingAssignment.module_key).where(TrainingAssignment.active.is_(False))))
    out = [dict(m) for m in builtin_modules()] + [_custom(c) for c in session.scalars(select(TrainingModule).order_by(TrainingModule.title))]
    for m in out:
        m["active"] = m["key"] not in off
    return out if include_off else [m for m in out if m["active"]]


def module(session: Session, key: str, include_off: bool = False) -> dict:
    for m in modules(session, include_off):
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
    p = get_or_404(session, Person, inv.person_id)
    return {"full_name": p.full_name, "email": p.email, "expires_at": inv.expires_at}


def accept_invite(session: Session, token: str, password: str) -> auth.User:
    inv = _open_invite(session, token)
    p = get_or_404(session, Person, inv.person_id)
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
        u = get_or_404(session, auth.User, p.user_id)
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


def _current_completions(session: Session, user_id: int | None, on: date, person: Person | None = None, catalogue: list[dict] | None = None) -> dict:
    """The passes that still count, per module key: quizzes passed in the portal within a year, and training recorded
    as done elsewhere that is still valid. Both must be of the module's current version. A copy of a built-in module
    keeps the built-in module's passes until it gets a new version."""
    catalogue = catalogue if catalogue is not None else modules(session, include_off=True)
    versions = {m["key"]: m["version"] for m in catalogue}
    out: dict = {}
    if user_id is not None:
        for c in session.scalars(select(TrainingCompletion).where(TrainingCompletion.user_id == user_id, TrainingCompletion.passed.is_(True)).order_by(TrainingCompletion.completed_at)):
            if c.completed_at.date() >= on - timedelta(days=TRAINING_VALID_DAYS) and c.module_key in versions and c.module_version >= versions[c.module_key]:
                out[c.module_key] = c
        if person is None:
            person = session.scalar(select(Person).where(Person.user_id == user_id))
    if person is not None:
        for e in session.scalars(select(ExternalTraining).where(ExternalTraining.person_id == person.id, ExternalTraining.module_key.is_not(None)).order_by(ExternalTraining.completed_on)):
            key = e.module_key or ""
            if e.completed_on <= on <= e.valid_until and key in versions and (e.module_version or 0) >= versions[key]:
                if key not in out or out[key].completed_at <= e.completed_at:
                    out[key] = e
    for m in catalogue:
        if m.get("copied_from") and m["version"] == 1 and m["key"] not in out and m["copied_from"] in out:
            out[m["key"]] = out[m["copied_from"]]
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
        training_total=len(mine := modules_for(session, user)), training_done=len([k for k in _current_completions(session, user.id, on) if k in {m["key"] for m in mine}]),
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
    m = module(session, key)
    if len(answers) != len(m["quiz"]):
        raise ValueError("Answer every question.")
    score = sum(1 for a, q in zip(answers, m["quiz"]) if a == q["answer"])
    c = TrainingCompletion(user_id=user.id, module_key=key, module_version=m["version"], score=score, out_of=len(m["quiz"]), passed=score >= m["pass_mark"], completed_at=utcnow())
    session.add(c)
    session.flush()
    return c


def my_training(session: Session, user: auth.User) -> list[dict]:
    on = today()
    done = _current_completions(session, user.id, on)
    person = session.scalar(select(Person).where(Person.user_id == user.id))
    return [{"key": m["key"], "title": m["title"], "minutes": m["minutes"], "summary": m["summary"], "version": m["version"],
             "completed_at": done[m["key"]].completed_at if m["key"] in done else None, "due": training_due(session, m["key"], person, user, done.get(m["key"]))}
            for m in modules_for(session, user)]


# ---- training assignment (A.6.3): who takes which module, by when -------------------------------------

def assignments(session: Session) -> dict:
    from .models import TrainingAssignment

    return {a.module_key: a for a in session.scalars(select(TrainingAssignment))}


def modules_for(session: Session, user: auth.User | None, assigned: dict | None = None, person: Person | None = None, mods: list[dict] | None = None) -> list[dict]:
    """The switched-on modules that apply to a user (or, for someone without an account, to their People record)."""
    from keystone.core import audience

    assigned = assigned if assigned is not None else assignments(session)
    out = []
    for m in (mods if mods is not None else modules(session)):
        a = assigned.get(m["key"])
        if a is not None and a.audience:
            if person is None and user is not None:
                person = audience.person_of(session, user.id)
            if not audience.matches(a.audience, person):
                continue
        out.append(m)
    return out


def training_due(session: Session, key: str, person, user: auth.User | None, completion: TrainingCompletion | ExternalTraining | None, assigned: dict | None = None) -> date:
    """When the module is due: a year after the last pass, or `due_days` after the person started (or after the
    module was assigned, or the account created, whichever is later)."""
    if completion is not None:
        if isinstance(completion, ExternalTraining):
            return completion.valid_until
        return completion.completed_at.date() + timedelta(days=TRAINING_VALID_DAYS)
    a = (assigned if assigned is not None else assignments(session)).get(key)
    starts = [d for d in ((person.start_date if person else None), (a.created_at.date() if a else None), user.created_at.date() if user is not None and getattr(user, "created_at", None) else None) if d]
    return max(starts or [today()]) + timedelta(days=a.due_days if a else DEFAULT_DUE_DAYS)


def set_assignment(session: Session, actor, module_key: str, *, audience: dict | None, due_days: int):
    from keystone.core import audience as aud

    from .models import TrainingAssignment

    authorize(session, actor, "people.write")
    module(session, module_key, include_off=True)
    if not 1 <= due_days <= 365:
        raise ValueError("Give between 1 and 365 days.")
    a = session.scalar(select(TrainingAssignment).where(TrainingAssignment.module_key == module_key)) or TrainingAssignment(module_key=module_key)
    a.audience, a.due_days = aud.clean(audience), due_days
    session.add(a)
    session.flush()
    return a


# ---- managing modules (people.write) ------------------------------------------------------------------------------

MAX_QUESTIONS, MAX_OPTIONS = 20, 6
CERTIFICATE_TYPES = (".pdf", ".png", ".jpg", ".jpeg")
_KEY_CHARS = re.compile(r"[^a-z0-9]+")


def clean_quiz(quiz) -> list[dict]:
    """Questions with 2 to 6 answers and exactly one right answer, given by its position."""
    if not isinstance(quiz, list) or not 1 <= len(quiz) <= MAX_QUESTIONS:
        raise ValueError(f"Write between 1 and {MAX_QUESTIONS} quiz questions.")
    out = []
    for n, q in enumerate(quiz, 1):
        if not isinstance(q, dict) or set(q) - {"q", "options", "answer"}:
            raise ValueError(f"Question {n}: give the question, its answers and which one is right.")
        text = str(q.get("q") or "").strip()
        options = [str(o).strip() for o in (q.get("options") or [])] if isinstance(q.get("options"), list) else []
        answer = q.get("answer")
        if not text or len(text) > 500:
            raise ValueError(f"Question {n}: write the question (up to 500 characters).")
        if not 2 <= len(options) <= MAX_OPTIONS or any(not o or len(o) > 300 for o in options):
            raise ValueError(f"Question {n}: give 2 to {MAX_OPTIONS} answers of up to 300 characters.")
        if len(set(o.lower() for o in options)) != len(options):
            raise ValueError(f"Question {n}: two answers are the same.")
        if not isinstance(answer, int) or isinstance(answer, bool) or not 0 <= answer < len(options):
            raise ValueError(f"Question {n}: choose the right answer.")
        out.append({"q": text, "options": options, "answer": answer})
    return out


def _new_key(session: Session, title: str) -> str:
    base = "own-" + (_KEY_CHARS.sub("-", title.lower()).strip("-")[:40] or "module")
    taken = {m["key"] for m in builtin_modules()} | set(session.scalars(select(TrainingModule.key)))
    key, n = base, 2
    while key in taken:
        key, n = f"{base}-{n}", n + 1
    return key


def save_module(session: Session, actor, key: str | None = None, *, title: str, summary: str, minutes: int, body: str, quiz, pass_mark: int,
                retake: bool = False, copied_from: str | None = None) -> TrainingModule:
    """Create or change one of the organisation's own modules. `retake` makes it a new version: earlier passes stop
    counting and everyone it applies to takes it again. Built-in modules can't be changed; copy one instead."""
    authorize(session, actor, "people.write")
    if key is not None:
        m = session.scalar(select(TrainingModule).where(TrainingModule.key == key))
        if m is None:
            if any(b["key"] == key for b in builtin_modules()):
                raise ValueError("Built-in modules can't be changed. Make your own copy instead.")
            raise LookupError(f"Training module {key} not found")
    else:
        m = TrainingModule(key=_new_key(session, require_text(title, "Title")), version=1, copied_from=copied_from)
    m.title = require_text(title, "Title")[:200]
    m.summary = require_text(summary, "Summary")[:300]
    if not isinstance(minutes, int) or not 1 <= minutes <= 240:
        raise ValueError("Give how long it takes: 1 to 240 minutes.")
    m.minutes = minutes
    body = require_text(body, "Content")
    if len(body) > 50_000:
        raise ValueError("The content can be up to 50,000 characters.")
    m.body = body
    m.quiz = clean_quiz(quiz)
    if not isinstance(pass_mark, int) or not 1 <= pass_mark <= len(m.quiz):
        raise ValueError(f"The pass mark must be between 1 and {len(m.quiz)} (the number of questions).")
    m.pass_mark = pass_mark
    if key is not None and retake:
        m.version += 1
    session.add(m)
    session.flush()
    return m


def set_module_active(session: Session, actor, key: str, active: bool):
    """Switch a module on or off. Off: no longer offered in the portal, due or counted; earlier passes are kept."""
    from .models import TrainingAssignment

    authorize(session, actor, "people.write")
    module(session, key, include_off=True)
    a = session.scalar(select(TrainingAssignment).where(TrainingAssignment.module_key == key)) or TrainingAssignment(module_key=key, due_days=DEFAULT_DUE_DAYS)
    a.active = bool(active)
    session.add(a)
    session.flush()
    return a


def copy_builtin(session: Session, actor, key: str) -> TrainingModule:
    """Start an editable module from a built-in one: same content and quiz, same audience and due days. The built-in
    module is switched off, so people aren't asked to take both."""
    from .models import TrainingAssignment

    authorize(session, actor, "people.write")
    b = next((m for m in builtin_modules() if m["key"] == key), None)
    if b is None:
        raise LookupError(f"Built-in training module {key} not found")
    m = save_module(session, actor, title=b["title"], summary=b["summary"], minutes=b["minutes"], body=b["body"], quiz=b["quiz"], pass_mark=b["pass_mark"], copied_from=key)
    old = session.scalar(select(TrainingAssignment).where(TrainingAssignment.module_key == key))
    if old is not None:
        session.add(TrainingAssignment(module_key=m.key, audience=old.audience, due_days=old.due_days))
    set_module_active(session, actor, key, False)
    return m


def delete_module(session: Session, actor, key: str) -> None:
    """Delete one of the organisation's own modules created by mistake. Once anyone took it, switch it off instead:
    passes are training records."""
    from .models import TrainingAssignment

    authorize(session, actor, "people.write")
    m = session.scalar(select(TrainingModule).where(TrainingModule.key == key))
    if m is None:
        raise LookupError(f"Training module {key} not found")
    used = session.scalar(select(TrainingCompletion.id).where(TrainingCompletion.module_key == key).limit(1)) or session.scalar(select(ExternalTraining.id).where(ExternalTraining.module_key == key).limit(1))
    if used:
        raise ValueError("People have taken this module, so it is part of their training records. Switch it off instead.")
    for a in session.scalars(select(TrainingAssignment).where(TrainingAssignment.module_key == key)):
        session.delete(a)
    session.delete(m)
    session.flush()


# ---- training done elsewhere (people.write; holds personal data) ---------------------------------------------------

def record_external(session: Session, actor, *, person_id: int, completed_on: date, module_key: str | None = None, title: str | None = None,
                    provider: str | None = None, valid_until: date | None = None, note: str | None = None,
                    filename: str | None = None, data: bytes | None = None) -> ExternalTraining:
    """Record training someone did outside Keystone. Naming a module makes it count as passing that module (its
    current version) until `valid_until` (a year by default)."""
    authorize(session, actor, "people.write")
    p = get_or_404(session, Person, person_id)
    on = today()
    if completed_on > on:
        raise ValueError("The training can't have been completed in the future.")
    if completed_on < on - timedelta(days=3 * 365):
        raise ValueError("Record training from the last three years.")
    valid_until = valid_until or completed_on + timedelta(days=TRAINING_VALID_DAYS)
    if not completed_on < valid_until <= completed_on + timedelta(days=3 * 365):
        raise ValueError("Valid until must be after the completion date, and within three years of it.")
    m = module(session, module_key, include_off=True) if module_key else None
    title = (title or "").strip() or (m["title"] if m else "")
    if not title:
        raise ValueError("Choose the module this training covers, or name the training.")
    if data is not None and filename and not filename.lower().endswith(CERTIFICATE_TYPES):
        raise ValueError("Attach the certificate as a PDF, PNG or JPG.")
    e = ExternalTraining(person_id=p.id, module_key=m["key"] if m else None, module_version=m["version"] if m else None, title=title[:200],
                         provider=(provider or "").strip()[:200] or None, completed_on=completed_on, valid_until=valid_until,
                         note=(note or "").strip()[:2000] or None)
    session.add(e)
    session.flush()
    if data is not None and filename:
        e.attachment_id = save_attachment(session, actor, filename, data, "ExternalTraining", e.id).id
        session.flush()
    return e


def external_records(session: Session, actor, person_id: int | None = None) -> list[ExternalTraining]:
    authorize(session, actor, "people.write")
    q = select(ExternalTraining).order_by(ExternalTraining.completed_on.desc(), ExternalTraining.id.desc())
    if person_id is not None:
        q = q.where(ExternalTraining.person_id == person_id)
    return list(session.scalars(q))


def delete_external(session: Session, actor, record_id: int) -> None:
    """Remove a record entered by mistake (the audit log keeps what it said)."""
    authorize(session, actor, "people.write")
    session.delete(get_or_404(session, ExternalTraining, record_id))
    session.flush()


def training_matrix(session: Session, actor) -> tuple[list[str], list[list]]:
    """Everyone in scope (with or without a portal account) against every switched-on module that applies to them:
    passed (until when, and where it was done elsewhere), due or overdue."""
    authorize(session, actor, "read")
    on = today()
    assigned = assignments(session)
    mods = modules(session)
    catalogue = modules(session, include_off=True)
    headers = ["Person", "Department", "Type", "Status"] + [m["title"] for m in mods]
    rows = []
    for p in list_people(session):
        if p.status == "offboarded":
            continue
        u = session.get(auth.User, p.user_id) if p.user_id else None
        mine = {m["key"] for m in modules_for(session, u, assigned, person=p, mods=mods)}
        done = _current_completions(session, u.id if u else None, on, person=p, catalogue=catalogue)
        cells = []
        for m in mods:
            if m["key"] not in mine:
                cells.append("not assigned")
            elif m["key"] in done:
                where = " (recorded: done elsewhere)" if isinstance(done[m["key"]], ExternalTraining) else ""
                cells.append(f"passed until {training_due(session, m['key'], p, u, done[m['key']], assigned).isoformat()}{where}")
            elif u is None:
                cells.append("no portal account")
            else:
                due = training_due(session, m["key"], p, u, None, assigned)
                cells.append(f"{'overdue since' if due < on else 'due'} {due.isoformat()}")
        rows.append([p.full_name, p.department or "", p.employment_type, p.status] + cells)
    return headers, rows


def training_overdue(session: Session, on: date | None = None) -> dict[str, int]:
    """How many people are overdue on each module (for reminders to people managers)."""
    on = on or today()
    assigned = assignments(session)
    mods = modules(session)
    catalogue = modules(session, include_off=True)
    out: dict[str, int] = {}
    for p in list_people(session):
        if p.status not in ("active", "onboarding") or not p.user_id:
            continue
        u = session.get(auth.User, p.user_id)
        if u is None or not u.active:
            continue
        done = _current_completions(session, u.id, on, person=p, catalogue=catalogue)
        for m in modules_for(session, u, assigned, person=p, mods=mods):
            if m["key"] not in done and training_due(session, m["key"], p, u, None, assigned) < on:
                out[m["title"]] = out.get(m["title"], 0) + 1
    return out


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
