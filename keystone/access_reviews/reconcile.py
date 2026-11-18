"""Leaver access check: People (the HR view of who works here) against the accounts Keystone can see, so leavers
who keep access and accounts nobody owns are found without waiting for the next access review (ISO 27001 A.5.18,
A.6.5). Read-only: it never changes an account; deactivating stays a deliberate step in Users or the source system."""

from __future__ import annotations

from datetime import date

from sqlalchemy import Integer, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from keystone.core.auth import User
from keystone.core.db import Audited, Base, OwnedMixin, TimestampMixin
from keystone.core.services import authorize, get_or_404, require_text, today


class AccessCheckExemption(Audited, OwnedMixin, TimestampMixin, Base):
    """An account that is expected to have no person behind it (a service or shared account), with the reason."""

    __tablename__ = "access_check_exemptions"
    REF_PREFIX = "ACE"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account: Mapped[str] = mapped_column(String(400), unique=True, nullable=False)  # "<source>:<login>"
    note: Mapped[str] = mapped_column(Text, nullable=False)


def _enabled(props: dict) -> bool:
    return props.get("account_enabled") is not False


def findings(session: Session, actor, on: date | None = None) -> dict:
    """Leavers who still have access, and accounts with no person in People."""
    from keystone.asm.models import AsmIdentity
    from keystone.people.models import Person

    authorize(session, actor, "access_review.manage")
    on = on or today()
    people = list(session.scalars(select(Person)))
    by_email = {p.email.lower(): p for p in people if p.email}
    exempt = {x.account: x for x in session.scalars(select(AccessCheckExemption))}
    out: list[dict] = []

    def leaving(p) -> str | None:
        if p.status in ("offboarding", "offboarded"):
            return f"is {p.status}"
        if p.end_date and p.end_date < on:
            return f"left on {p.end_date.isoformat()}"
        return None

    for p in people:
        why = leaving(p)
        if not why:
            continue
        u = session.get(User, p.user_id) if p.user_id else None
        if u is not None and u.active:
            out.append({"kind": "leaver", "severity": "high", "person": p.full_name, "person_id": p.id, "source": "Keystone", "account": u.username,
                        "detail": f"{p.full_name} {why} but their Keystone account is active.", "page": "/settings/users"})
    identities = list(session.scalars(select(AsmIdentity)))
    for i in identities:
        if not _enabled(i.properties or {}):
            continue
        key = f"{i.source}:{i.upn.lower()}"
        holder = by_email.get(i.upn.lower())
        if holder is not None:
            why = leaving(holder)
            if why:
                out.append({"kind": "leaver", "severity": "high", "person": holder.full_name, "person_id": holder.id, "source": i.source, "account": i.upn,
                            "detail": f"{holder.full_name} {why} but their {i.source} account is enabled.", "page": "/attack-surface?tab=identities"})
            continue
        if key in exempt:
            continue
        guest = (i.properties or {}).get("is_guest") is True
        out.append({"kind": "guest" if guest else "orphan", "severity": "medium" if guest else "low", "person": None, "person_id": None, "source": i.source,
                    "account": i.upn, "key": key,
                    "detail": ("A guest account with no person or vendor contact behind it." if guest else "An enabled account with no person in People: a service account, or someone missing from People."),
                    "page": "/attack-surface?tab=identities"})
    linked = {p.user_id for p in people if p.user_id}
    for u in session.scalars(select(User).where(User.active.is_(True))):
        key = f"keystone:{u.username.lower()}"
        if u.id in linked or key in exempt or (u.email or "").lower() in by_email:
            continue
        out.append({"kind": "orphan", "severity": "low", "person": None, "person_id": None, "source": "Keystone", "account": u.username, "key": key,
                    "detail": "A Keystone account with no person in People.", "page": "/settings/users"})
    order = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda f: (order[f["severity"]], f["kind"], f["account"]))
    return {"findings": out, "exemptions": [{"id": x.id, "account": x.account, "note": x.note, "created_at": x.created_at} for x in exempt.values()],
            "sources": sorted({i.source for i in identities} | {"Keystone"})}


def exempt(session: Session, actor, account: str, note: str) -> AccessCheckExemption:
    """Mark an account as expected to have no person (a service or shared account), with the reason."""
    authorize(session, actor, "access_review.manage")
    account = account.strip().lower()
    if ":" not in account or len(account) > 400:
        raise ValueError("Unknown account.")
    if session.scalar(select(AccessCheckExemption).where(AccessCheckExemption.account == account)):
        raise ValueError("This account is already marked as expected.")
    x = AccessCheckExemption(account=account, note=require_text(note, "Reason")[:2000])
    session.add(x)
    session.flush()
    return x


def remove_exemption(session: Session, actor, exemption_id: int) -> None:
    authorize(session, actor, "access_review.manage")
    session.delete(get_or_404(session, AccessCheckExemption, exemption_id))
    session.flush()
