"""Match app owner organisations to Keystone vendors. Nothing is applied until a user confirms."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from rapidfuzz import fuzz
from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.db import utcnow
from keystone.core.services import authorize, get_or_404
from keystone.tprm.models import Vendor

from .inventory import OwnerOrg, mappings, owner_orgs
from .models import VendorAppMapping

STRONG_SCORE = 90
MIN_CANDIDATE_SCORE = 60
MULTI_PART_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "com.br", "co.za", "com.mx", "co.in"}
NOISE_WORDS = {"inc", "inc.", "ltd", "ltd.", "llc", "limited", "corp", "corporation", "gmbh", "ag", "sa", "bv", "plc", "co", "company", "the"}


def host_of(url: str | None) -> str | None:
    if not url:
        return None
    try:
        h = urlparse(url if "://" in url else f"https://{url}").hostname
    except ValueError:
        return None
    return h.lower() if h else None


def registrable_domain(host: str | None) -> str | None:
    """Best-effort eTLD+1 (no public suffix list dependency; covers common multi-part suffixes)."""
    if not host:
        return None
    parts = host.lower().strip(".").split(".")
    if len(parts) < 2:
        return None
    take = 3 if ".".join(parts[-2:]) in MULTI_PART_SUFFIXES and len(parts) >= 3 else 2
    return ".".join(parts[-take:])


def _clean(name: str) -> str:
    return " ".join(w for w in name.lower().replace(",", " ").split() if w not in NOISE_WORDS)


@dataclass
class Candidate:
    vendor_id: int
    vendor_name: str
    score: float
    domain_match: bool
    best_name: str | None
    matched_domain: str | None

    @property
    def strength(self) -> str:
        return "strong" if self.score >= STRONG_SCORE and self.domain_match else "weak"

    def signals(self) -> dict:
        return {"name_score": self.score, "matched_name": self.best_name, "domain_match": self.domain_match, "matched_domain": self.matched_domain, "strength": self.strength}


def candidates(org: OwnerOrg, vendors: list[Vendor], limit: int = 5) -> list[Candidate]:
    org_domains = {registrable_domain(d) for d in org.domains} - {None}
    out = []
    for v in vendors:
        best, best_name = 0.0, None
        for n in org.names:
            s = fuzz.token_set_ratio(_clean(v.name), _clean(n))
            if s > best:
                best, best_name = float(s), n
        vdom = registrable_domain(host_of(v.website))
        dmatch = bool(vdom and vdom in org_domains)
        if best >= MIN_CANDIDATE_SCORE or dmatch:
            out.append(Candidate(v.id, v.name, round(best, 1), dmatch, best_name, vdom if dmatch else None))
    out.sort(key=lambda c: (c.domain_match and c.score >= STRONG_SCORE, c.domain_match, c.score), reverse=True)
    return out[:limit]


def refresh_suggestions(session: Session, actor) -> int:
    """(Re)compute the best candidate for every owner org that is not confirmed or ignored."""
    authorize(session, actor, "exposure.import")
    vendors = list(session.scalars(select(Vendor).where(Vendor.status != "terminated")))
    existing = mappings(session)
    n = 0
    for oid, org in owner_orgs(session).items():
        m = existing.get(oid)
        if m and m.status in ("confirmed", "ignored"):
            continue
        cands = candidates(org, vendors)
        if not cands:
            if m:
                m.vendor_id, m.match_score, m.match_signals = None, None, {"candidates": []}
            continue
        top = cands[0]
        if m is None:
            m = VendorAppMapping(owner_org_id=oid, status="suggested")
            session.add(m)
        m.vendor_id, m.match_score = top.vendor_id, top.score
        m.match_signals = {**top.signals(), "candidates": [{"vendor_id": c.vendor_id, "vendor": c.vendor_name, **c.signals()} for c in cands]}
        n += 1
    session.flush()
    return n


def confirm(session: Session, actor, owner_org_id: str, vendor_id: int) -> VendorAppMapping:
    authorize(session, actor, "exposure.confirm")
    get_or_404(session, Vendor, vendor_id)
    owner_org_id = owner_org_id.lower()
    m = session.scalar(select(VendorAppMapping).where(VendorAppMapping.owner_org_id == owner_org_id)) or VendorAppMapping(owner_org_id=owner_org_id)
    m.vendor_id, m.status, m.confirmed_by, m.confirmed_at = vendor_id, "confirmed", actor.username, utcnow()
    session.add(m)
    session.flush()
    return m


def ignore(session: Session, actor, owner_org_id: str) -> VendorAppMapping:
    authorize(session, actor, "exposure.confirm")
    owner_org_id = owner_org_id.lower()
    m = session.scalar(select(VendorAppMapping).where(VendorAppMapping.owner_org_id == owner_org_id)) or VendorAppMapping(owner_org_id=owner_org_id)
    m.vendor_id, m.status, m.confirmed_by, m.confirmed_at = None, "ignored", actor.username, utcnow()
    session.add(m)
    session.flush()
    return m


def reset(session: Session, actor, owner_org_id: str) -> None:
    authorize(session, actor, "exposure.confirm")
    m = session.scalar(select(VendorAppMapping).where(VendorAppMapping.owner_org_id == owner_org_id.lower()))
    if m:
        session.delete(m)
        session.flush()


def queue(session: Session) -> list[tuple[OwnerOrg, VendorAppMapping | None]]:
    """Third-party owner orgs still needing a decision, worst exposure first."""
    from .inventory import worst
    from .scoring import LEVEL_ORDER

    maps = mappings(session)
    items = [(o, maps.get(oid)) for oid, o in owner_orgs(session).items() if not maps.get(oid) or maps[oid].status == "suggested"]
    items.sort(key=lambda x: -LEVEL_ORDER.index(worst(x[0].level_by_tenant.values()) or "Low"))
    return items
