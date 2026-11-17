"""Who a policy acknowledgement or a training module applies to: everyone, or people in some departments or of some
employment types (from the People register). An audience of {"departments": [], "employment_types": []} (or none)
means everyone; otherwise a person in any listed department, or of any listed employment type, is included. Accounts
without a People record can't be matched, so they are only included when the audience is everyone."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

MAX_ITEMS = 50
EMPLOYMENT_TYPES = ("employee", "contractor")


def clean(audience: dict | None) -> dict | None:
    if not audience:
        return None
    if not isinstance(audience, dict) or set(audience) - {"departments", "employment_types"}:
        raise ValueError("An audience has departments and employment types.")
    deps = [str(d).strip()[:200] for d in (audience.get("departments") or []) if str(d).strip()][:MAX_ITEMS]
    types = [str(t).strip() for t in (audience.get("employment_types") or []) if str(t).strip()]
    if set(types) - set(EMPLOYMENT_TYPES):
        raise ValueError("Employment types are employee or contractor.")
    return {"departments": sorted(set(deps)), "employment_types": sorted(set(types))} if (deps or types) else None


def person_of(session: Session, user_id: int):
    from keystone.people.models import Person

    return session.scalar(select(Person).where(Person.user_id == user_id))


def matches(audience: dict | None, person) -> bool:
    if not audience or not (audience.get("departments") or audience.get("employment_types")):
        return True
    if person is None:
        return False
    deps = {d.lower() for d in audience.get("departments") or []}
    return (bool(person.department) and person.department.lower() in deps) or person.employment_type in (audience.get("employment_types") or [])


def departments(session: Session) -> list[str]:
    from keystone.people.models import Person

    return sorted({d for d in session.scalars(select(Person.department).where(Person.department.is_not(None))) if d})
