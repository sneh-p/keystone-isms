"""Registers: list, add, change, move through their workflow, delete while new. Every value is checked against the
register's declaration; reads of need-to-know registers (background checks, visitors) need their own permission."""

from __future__ import annotations

from datetime import date, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.auth import User
from keystone.core.db import utcnow
from keystone.core.rbac import has_permission
from keystone.core.services import authorize, get_or_404, require_text, today

from .models import RegisterEntry
from .spec import REGISTERS, F, Register

MAX_LIST = 100


def spec(key: str) -> Register:
    r = REGISTERS.get(key)
    if r is None:
        raise LookupError("Unknown register")
    return r


def readable(actor) -> list[Register]:
    return [r for r in REGISTERS.values() if has_permission(actor, r.read)]


def spec_out(r: Register, actor) -> dict:
    return {"key": r.key, "title": r.title, "singular": r.singular, "prefix": r.prefix, "description": r.description, "iso": r.iso, "help": r.help,
            "title_label": r.title_label, "owner": r.owner, "due": r.due, "due_label": r.due_label, "comments": r.comments, "max_due_days": r.max_due_days,
            "statuses": [{"key": k, "label": label, "tone": tone} for k, label, tone in r.statuses], "closed": list(r.closed), "initial": r.initial,
            "can_write": has_permission(actor, r.write),
            "fields": [{"key": f.key, "label": f.label, "type": f.type, "required": f.required, "listed": f.listed, "hint": f.hint, "min": f.min, "max": f.max,
                        "ref": f.ref, "choices": [{"value": v, "label": label} for v, label in f.choices]} for f in r.fields],
            "moves": [{"key": m.id, "to": m.to, "label": m.label, "from": list(m.frm), "sod": m.sod, "needs": list(m.needs), "note": m.note,
                       "allowed": has_permission(actor, m.perm)} for m in r.moves]}


def _months_after(d: date, months: int) -> date:
    y, m = divmod(d.month - 1 + months, 12)
    day = min(d.day, [31, 29 if (d.year + y) % 4 == 0 and ((d.year + y) % 100 or (d.year + y) % 400 == 0) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m])
    return date(d.year + y, m + 1, day)


def _value(session: Session, r: Register, f: F, v):
    """One field's value, checked and normalised for storage (dates as ISO text, links as ids that exist)."""
    if v is None or v == "" or v == []:
        return None
    t = f.type
    if t in ("text", "long"):
        if not isinstance(v, str):
            raise ValueError(f"{f.label}: text expected.")
        limit = f.max or (300 if t == "text" else 8000)
        v = v.strip()
        if len(v) > limit:
            raise ValueError(f"{f.label}: at most {limit} characters.")
        return v or None
    if t == "date":
        try:
            d = v if isinstance(v, date) else date.fromisoformat(str(v))
        except ValueError:
            raise ValueError(f"{f.label}: a date (YYYY-MM-DD) expected.") from None
        if not date(2000, 1, 1) <= d <= date(2100, 1, 1):
            raise ValueError(f"{f.label}: that date is out of range.")
        return d.isoformat()
    if t == "choice":
        if v not in {c for c, _ in f.choices}:
            raise ValueError(f"{f.label}: choose one of the options.")
        return v
    if t == "bool":
        if not isinstance(v, bool):
            raise ValueError(f"{f.label}: yes or no expected.")
        return v
    if t == "int":
        if not isinstance(v, int) or isinstance(v, bool) or (f.min is not None and v < f.min) or (f.max is not None and v > f.max):
            raise ValueError(f"{f.label}: a whole number from {f.min} to {f.max} expected.")
        return v
    if t == "user":
        u = session.get(User, v) if isinstance(v, int) else None
        if u is None or not u.active:
            raise ValueError(f"{f.label}: choose an active user.")
        return v
    if t == "person":
        from keystone.people.models import Person

        if not isinstance(v, int) or session.get(Person, v) is None:
            raise ValueError(f"{f.label}: choose a person from People.")
        return v
    if t == "entry":
        e = session.get(RegisterEntry, v) if isinstance(v, int) else None
        if e is None or e.register != f.ref:
            raise ValueError(f"{f.label}: choose an entry from {REGISTERS[f.ref or ''].title}.")
        return v
    if t in ("assets", "controls", "vendors"):
        from keystone.assets.models import Asset
        from keystone.frameworks.models import CommonControl
        from keystone.tprm.models import Vendor

        if not isinstance(v, list) or len(v) > MAX_LIST or not all(isinstance(i, int) and not isinstance(i, bool) for i in v):
            raise ValueError(f"{f.label}: a list of up to {MAX_LIST} records expected.")
        ids = sorted(set(v))
        if t == "assets":
            found = set(session.scalars(select(Asset.id).where(Asset.id.in_(ids))))
        elif t == "controls":
            found = set(session.scalars(select(CommonControl.id).where(CommonControl.id.in_(ids))))
        else:
            found = set(session.scalars(select(Vendor.id).where(Vendor.id.in_(ids))))
        if found != set(ids):
            raise ValueError(f"{f.label}: unknown records.")
        return ids
    raise ValueError(f"{f.label}: unsupported field.")


def _apply(session: Session, r: Register, e: RegisterEntry, values: dict) -> None:
    unknown = set(values) - {f.key for f in r.fields} - {"title", "owner_id"}
    if unknown:
        raise ValueError(f"Unknown fields: {', '.join(sorted(unknown))}.")
    if "title" in values:
        e.title = require_text(values["title"], r.title_label)[:300]
    if "owner_id" in values:
        if not r.owner:
            raise ValueError("This register has no owner.")
        e.owner_id = _value(session, r, F("owner_id", "Owner", "user"), values["owner_id"])
    data = dict(e.data or {})
    for f in r.fields:
        if f.key in values:
            data[f.key] = _value(session, r, f, values[f.key])
    e.data = data
    _derive(r, e)


def _derive(r: Register, e: RegisterEntry) -> None:
    """Person link and due date, from the fields."""
    data = e.data or {}
    person = next((f for f in r.fields if f.type == "person"), None)
    e.person_id = data.get(person.key) if person else None
    if r.due_every and data.get(r.due_every[0]) and data.get(r.due_every[1]) and not data.get(r.due or ""):
        # next due worked out from the last check unless set by hand; kept in the record so it shows
        e.due_on = _months_after(date.fromisoformat(data[r.due_every[0]]), int(data[r.due_every[1]]))
    elif r.due_by and not data.get(r.due or "") and data.get(r.due_by[0]) in dict(r.due_by[1]):
        # e.g. a finding's fix-by date from its severity, counted from when it was raised
        raised = e.created_at.date() if e.created_at else today()
        e.due_on = raised + timedelta(days=dict(r.due_by[1])[data[r.due_by[0]]])
    else:
        e.due_on = date.fromisoformat(data[r.due]) if r.due and data.get(r.due) else None


def _check_required(r: Register, e: RegisterEntry) -> None:
    missing = [f.label for f in r.fields if f.required and (e.data or {}).get(f.key) in (None, "", [])]
    if missing:
        raise ValueError("Fill in: " + ", ".join(missing) + ".")
    if r.max_due_days and e.due_on and e.due_on > today() + timedelta(days=r.max_due_days):
        raise ValueError(f"{r.due_label} can be at most {r.max_due_days} days ahead.")


def entries(session: Session, actor, key: str) -> list[RegisterEntry]:
    r = spec(key)
    authorize(session, actor, r.read)
    return list(session.scalars(select(RegisterEntry).where(RegisterEntry.register == key).order_by(RegisterEntry.id.desc())))


def entry(session: Session, actor, entry_id: int) -> tuple[Register, RegisterEntry]:
    e = get_or_404(session, RegisterEntry, entry_id)
    r = spec(e.register)
    authorize(session, actor, r.read)
    return r, e


def save(session: Session, actor, key: str, entry_id: int | None = None, **values) -> RegisterEntry:
    r = spec(key)
    authorize(session, actor, r.write)
    if entry_id is None:
        from sqlalchemy import func

        last = session.scalar(select(func.max(RegisterEntry.seq)).where(RegisterEntry.register == key)) or 0
        e = RegisterEntry(register=key, status=r.initial, data={}, seq=last + 1)
    else:
        e = get_or_404(session, RegisterEntry, entry_id)
        if e.register != key:
            raise LookupError("Not found")
        if e.status in r.closed:
            raise ValueError("This record is closed and can't be changed.")
    _apply(session, r, e, values)
    if not (e.title or "").strip():
        raise ValueError(f"Give the {r.title_label.lower()}.")
    _check_required(r, e)
    session.add(e)
    session.flush()
    return e


def move(session: Session, actor, entry_id: int, to: str, note: str | None = None) -> RegisterEntry:
    """Move a record through its workflow. Approvals by whoever raised the record are refused."""
    e = get_or_404(session, RegisterEntry, entry_id)
    r = spec(e.register)
    authorize(session, actor, r.read)
    m = next((m for m in r.moves if m.id == to and e.status in m.frm), None) or next((m for m in r.moves if m.to == to and e.status in m.frm), None)
    if m is None:
        raise ValueError(f"Can't go from {dict((k, label) for k, label, _ in r.statuses).get(e.status, e.status)} to that.")
    authorize(session, actor, m.perm)
    if m.sod and e.created_by_id is not None and e.created_by_id == actor.id:
        raise ValueError(f"Segregation of duties: someone other than whoever raised this {r.singular} decides it.")
    if m.sod_last and e.decisions and e.decisions[-1].get("by") == actor.username:
        raise ValueError(f"Segregation of duties: someone other than whoever made the last step does this ({m.label.lower()}).")
    data = e.data or {}
    missing = [f.label for f in r.fields if f.key in m.needs and data.get(f.key) in (None, "", [])]
    if missing:
        raise ValueError("First fill in: " + ", ".join(missing) + ".")
    note = (note or "").strip()[:2000] or None
    if m.note and not note:
        raise ValueError("Add a note saying why.")
    if m.sets:
        e.data = {**data, m.sets: today().isoformat()}
        if r.due and r.due_every and r.due_resets and m.sets == r.due_every[0]:
            e.data = {**e.data, r.due: None}  # a new check: the next due date is worked out again
        _derive(r, e)
    e.decisions = [*(e.decisions or []), {"at": utcnow().isoformat(timespec="seconds"), "by": actor.username, "from": e.status, "to": m.to, "step": m.label, "note": note}]
    e.status = m.to
    _check_required(r, e)
    session.flush()
    return e


# Steps a machine may record without a person (POST /api/inbound/checkin with a backup tool's token). Only steps with no
# segregation-of-duties rule and nothing to fill in; everything else needs a signed-in user.
SYSTEM_MOVES = {("backups", "success"), ("backups", "failure")}


def system_move(session: Session, e: RegisterEntry, key: str, by: str, note: str | None = None) -> RegisterEntry:
    """Record an allowed step reported by a tool (see SYSTEM_MOVES). The decision names the tool, not a person."""
    r = spec(e.register)
    m = next((m for m in r.moves if m.id == key and e.status in m.frm), None)
    if (e.register, key) not in SYSTEM_MOVES or m is None or m.sod or m.sod_last or m.needs:
        raise ValueError("That step can't be recorded by a tool.")
    data = e.data or {}
    if m.sets:
        e.data = {**data, m.sets: today().isoformat()}
        _derive(r, e)
    e.decisions = [*(e.decisions or []), {"at": utcnow().isoformat(timespec="seconds"), "by": by[:120], "from": e.status, "to": m.to, "step": m.label,
                                          "note": (note or "").strip()[:2000] or None}]
    e.status = m.to
    session.flush()
    return e


def delete(session: Session, actor, entry_id: int) -> None:
    """Delete a record created by mistake: only while it is still in its first status and no decision was recorded."""
    e = get_or_404(session, RegisterEntry, entry_id)
    r = spec(e.register)
    authorize(session, actor, r.write)
    if e.status != r.initial or e.decisions:
        raise ValueError(f"Decisions were recorded on this {r.singular}, so it stays on record. Close or end it instead.")
    session.delete(e)
    session.flush()


def due_soon(session: Session, on: date | None = None, days: int = 14) -> list[tuple[Register, RegisterEntry]]:
    """Open records whose due date has passed or is near (for the dashboard, calendar and notifications)."""
    on = on or today()
    out = []
    for e in session.scalars(select(RegisterEntry).where(RegisterEntry.due_on.is_not(None), RegisterEntry.due_on <= on + timedelta(days=days))):
        r = REGISTERS.get(e.register)
        if r and e.status not in r.closed:
            out.append((r, e))
    return out


def sync_public_certificates(session: Session) -> int:
    """Keep the certificates register up to date with the TLS certificates the internet-facing checks see: one entry
    per host, its expiry refreshed on each scan. Entries people added or edited by hand are left alone."""
    from keystone.asm.models import ExternalHost

    source = "Internet-facing check"
    existing = {(e.data or {}).get("location"): e for e in session.scalars(select(RegisterEntry).where(RegisterEntry.register == "crypto"))
                if (e.data or {}).get("source") == source}
    r = spec("crypto")
    changed = 0
    for h in session.scalars(select(ExternalHost).where(ExternalHost.current.is_(True))):
        expires = (h.facts or {}).get("cert_expires")
        if not expires:
            continue
        try:
            exp = date.fromisoformat(str(expires)[:10]).isoformat()
        except ValueError:
            continue
        e = existing.get(h.host)
        if e is None:
            from sqlalchemy import func

            last = session.scalar(select(func.max(RegisterEntry.seq)).where(RegisterEntry.register == "crypto")) or 0
            e = RegisterEntry(register="crypto", seq=last + 1, status=r.initial, title=f"TLS certificate for {h.host}"[:300],
                              data={"kind": "tls_certificate", "location": h.host, "expires_on": exp, "source": source})
            session.add(e)
            changed += 1
        elif (e.data or {}).get("expires_on") != exp:
            e.data = {**(e.data or {}), "expires_on": exp}
            changed += 1
        _derive(r, e)
    session.flush()
    return changed
