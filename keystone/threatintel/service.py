"""Look-alike domains and supplier breach news. Both download public data and match it here, so they reveal at most
your own verified domain names (to certificate transparency, which already sees them) and nothing about your vendors.

- Look-alikes: certificates issued for names that contain your brand, or are one or two typing mistakes away from it
  (with common character swaps such as 0 for o and rn for m), found in certificate transparency logs (crt.sh).
- Breach news: the public Have I Been Pwned breach list, matched against your vendors' web addresses.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from urllib.parse import quote, urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.auth import User
from keystone.core.db import utcnow
from keystone.core.rbac import has_permission
from keystone.core.services import authorize, get_or_404, require_text
from keystone.integrations.http import Api, ConnectorError, HostPolicy

from .models import LookalikeDomain, VendorBreach

CT_URL = "https://crt.sh/?q={q}&output=json"
CT_POLICY = HostPolicy(hosts=frozenset({"crt.sh"}))
HIBP_URL = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_POLICY = HostPolicy(hosts=frozenset({"haveibeenpwned.com"}))
MAX_ROWS = 5000
SECOND_LEVEL = {"co", "com", "org", "net", "ac", "gov", "edu", "ltd", "plc"}
HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("i", "l"))
LOOKALIKE_STATUSES = {"ours": "Ours", "benign": "Not a threat", "threat": "Threat"}
BREACH_STATUSES = {"not_affected": "Not affected", "assessing": "Assessing", "affected": "Affected"}


def registrable(host: str) -> str:
    """The registrable domain of a host name, approximately: the last two labels, or three under a short country code
    with a common second level (example.co.uk)."""
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _label(domain: str) -> str:
    return registrable(domain).split(".")[0]


def _norm(s: str) -> str:
    s = s.lower().replace("-", "")
    for a, b in HOMOGLYPHS:
        s = s.replace(a, b)
    return s


def distance(a: str, b: str) -> int:
    """Optimal string alignment distance (insertions, deletions, substitutions, swaps of neighbours)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def why_lookalike(candidate: str, brand: str) -> str | None:
    """Why a registrable domain looks like the brand, or None."""
    label = candidate.split(".")[0]
    if len(brand) < 4:
        return None
    if brand in label and label != brand:
        return f"Contains '{brand}'"
    if label == brand:
        return "Same name, different ending"
    n, nb = _norm(label), _norm(brand)
    if n == nb:
        return "Same name with swapped look-alike characters"
    if len(brand) >= 6 and distance(n, nb) <= 2:
        return "One or two typing mistakes away"
    return None


def ct_names(pattern: str) -> set[str]:
    rows = Api(CT_POLICY).json("GET", CT_URL.format(q=quote(pattern, safe="")), headers={"Accept": "application/json"}, retries=2)
    if not isinstance(rows, list):
        raise ConnectorError("crt.sh didn't return a list.")
    out: set[str] = set()
    for r in rows[:MAX_ROWS]:
        if isinstance(r, dict):
            for n in str(r.get("name_value") or "").lower().split("\n"):
                n = n.strip().removeprefix("*.").rstrip(".")
                if n and len(n) <= 253 and all(c.isalnum() or c in "-." for c in n):
                    out.add(registrable(n))
    return out


def scan_lookalikes(session: Session, fetch=ct_names) -> int:
    """Look for new look-alikes of every verified domain (called by the daily scan). Returns how many are new."""
    from keystone.asm.models import ExternalDomain

    domains = list(session.scalars(select(ExternalDomain).where(ExternalDomain.verified_at.is_not(None))))
    own = {registrable(d.name) for d in session.scalars(select(ExternalDomain))}
    now, new = utcnow(), []
    for d in domains:
        brand = _label(d.name)
        if len(brand) < 4:
            continue
        found = fetch(f"%{brand}%") | (fetch(f"%{brand[: len(brand) // 2 + 1]}%") if len(brand) >= 8 else set())
        for cand in sorted(found):
            if cand in own:
                continue
            reason = why_lookalike(cand, brand)
            if reason is None:
                continue
            row = session.scalar(select(LookalikeDomain).where(LookalikeDomain.name == cand))
            if row is None:
                row = LookalikeDomain(domain_id=d.id, name=cand, reason=reason, first_seen=now, last_seen=now, status="new")
                session.add(row)
                new.append(row)
            else:
                row.last_seen = now
    session.flush()
    if new:
        _notify(session, "integration.manage", f"lookalike:{now:%Y%m%d%H%M%S}", f"{len(new)} new look-alike domain(s), e.g. {new[0].name}", "/domain-protection")
    return len(new)


def lookalikes(session: Session, actor) -> list[LookalikeDomain]:
    authorize(session, actor, "read")
    return list(session.scalars(select(LookalikeDomain).order_by(LookalikeDomain.status != "new", LookalikeDomain.first_seen.desc())))


def decide_lookalike(session: Session, actor, lookalike_id: int, status: str, note: str | None) -> LookalikeDomain:
    authorize(session, actor, "integration.manage")
    x = get_or_404(session, LookalikeDomain, lookalike_id)
    if status not in LOOKALIKE_STATUSES:
        raise ValueError("Choose ours, not a threat, or threat.")
    if status == "threat" and not (note or "").strip():
        raise ValueError("Say what is being done (blocked, takedown requested, ...).")
    x.status, x.note, x.decided_by_id = status, (note or "").strip()[:2000] or None, actor.id
    session.flush()
    return x


# ---- supplier breach news -----------------------------------------------------------------------------------------

def fetch_breaches() -> list[dict]:
    rows = Api(HIBP_POLICY).json("GET", HIBP_URL, headers={"Accept": "application/json", "User-Agent": "Keystone-ISMS"}, retries=2)
    if not isinstance(rows, list):
        raise ConnectorError("The breach list didn't return a list.")
    return [r for r in rows if isinstance(r, dict)]


def _date(v) -> date | None:
    try:
        return date.fromisoformat(str(v)[:10]) if v else None
    except ValueError:
        return None


def scan_breaches(session: Session, fetch=fetch_breaches, recent_days: int = 30) -> int:
    """Match the public breach list against vendors' web addresses (called daily). New matches added to the list in
    the last `recent_days` notify the vendor's owner. Returns how many matches are new."""
    from keystone.tprm.models import Vendor

    vendors: dict[str, list] = {}
    for v in session.scalars(select(Vendor).where(Vendor.status != "terminated")):
        host = urlparse(v.website if "://" in (v.website or "") else f"https://{v.website or ''}").hostname if v.website else None
        if host:
            vendors.setdefault(registrable(host), []).append(v)
    if not vendors:
        return 0
    new = 0
    for b in fetch():
        dom = str(b.get("Domain") or "").lower().strip()
        if not dom or registrable(dom) not in vendors:
            continue
        for v in vendors[registrable(dom)]:
            name = str(b.get("Name") or "")[:200]
            if not name or session.scalar(select(VendorBreach).where(VendorBreach.vendor_id == v.id, VendorBreach.breach == name)):
                continue
            classes = b.get("DataClasses") if isinstance(b.get("DataClasses"), list) else []
            vb = VendorBreach(vendor_id=v.id, breach=name, title=str(b.get("Title") or name)[:300], domain=dom[:253], breach_date=_date(b.get("BreachDate")),
                              added_on=_date(b.get("AddedDate")), accounts=b.get("PwnCount") if isinstance(b.get("PwnCount"), int) else None,
                              data_classes=[str(c)[:80] for c in classes][:30], status="new")
            session.add(vb)
            session.flush()
            new += 1
            if vb.added_on and vb.added_on >= date.today() - timedelta(days=recent_days):
                owner = session.get(User, v.owner_id) if v.owner_id else None
                users = [owner] if owner is not None and owner.active else None
                _notify(session, "vendor.write", f"vendor-breach:{vb.id}", f"Breach reported at {v.name}: {vb.title}", f"/vendor-breaches?open={vb.id}", users)
    session.flush()
    return new


def breaches(session: Session, actor) -> list[VendorBreach]:
    authorize(session, actor, "read")
    return list(session.scalars(select(VendorBreach).order_by(VendorBreach.status != "new", VendorBreach.added_on.desc())))


def decide_breach(session: Session, actor, breach_id: int, status: str, note: str) -> VendorBreach:
    authorize(session, actor, "vendor.write")
    b = get_or_404(session, VendorBreach, breach_id)
    if status not in BREACH_STATUSES:
        raise ValueError("Choose not affected, assessing or affected.")
    b.status, b.note, b.decided_by_id = status, require_text(note, "Note")[:2000], actor.id
    session.flush()
    return b


def _notify(session: Session, permission: str, key: str, title: str, page: str, users: list | None = None) -> None:
    from keystone.notifications.models import Notification

    targets = users if users else [u for u in session.scalars(select(User).where(User.active.is_(True))) if has_permission(u, permission)]
    for u in targets:
        session.add(Notification(user_id=u.id, key=key[:64], kind="asm", title=title[:500], page=page, created_at=datetime.now()))
