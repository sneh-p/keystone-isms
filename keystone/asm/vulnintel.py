"""Vulnerability prioritisation: CISA KEV, FIRST EPSS and fix-by deadlines.

Two public feeds, no credentials, fetched through the shared connector client (exact hosts, HTTPS, pinned addresses,
size caps; SC-SSRF-001):

- CISA Known Exploited Vulnerabilities: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- FIRST EPSS, the full daily file from https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz. Downloading
  every score (instead of asking the EPSS API about specific CVEs) means no outside party learns which
  vulnerabilities this organisation has. Only scores for CVEs Keystone has seen are kept.

Priority (documented in the admin guide, shown in the app):
  P1  a CVE is on the KEV catalogue (exploited in the wild)
  P2  EPSS at or above the threshold (default 10 %), or the scanner reports a public exploit for a critical/high one
  P3  critical or high
  P4  medium or low
Fix-by: first seen + the deadline for its severity; known-exploited ones get the (shorter) KEV deadline, counted from
when they were first seen or added to the catalogue, whichever is later.
"""

from __future__ import annotations

import csv
import gzip
import io
import re
from collections.abc import Iterable
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from keystone.core.db import utcnow
from keystone.core.services import authorize
from keystone.integrations.http import Api, ConnectorError, HostPolicy

from .models import AsmDevice, AsmVulnerability, EpssScore, KevEntry, VulnPolicy

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-{day}.csv.gz"
KEV_POLICY = HostPolicy(hosts=frozenset({"www.cisa.gov"}))
EPSS_POLICY = HostPolicy(hosts=frozenset({"epss.empiricalsecurity.com"}))
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
MAX_EPSS_UNCOMPRESSED = 200 * 1024 * 1024  # the real file is about 20 MB; refuse anything that inflates further
MAX_KEV_ENTRIES = 50_000
PRIORITIES = ("P1", "P2", "P3", "P4")
PRIORITY_LABELS = {"P1": "Known exploited", "P2": "Likely to be exploited", "P3": "Critical or high", "P4": "Medium or low"}


def policy(session: Session) -> VulnPolicy:
    p = session.scalars(select(VulnPolicy).limit(1)).first()
    if p is None:
        p = VulnPolicy()
        session.add(p)
        session.flush()
    return p


def policy_view(p: VulnPolicy) -> dict:
    return {k: getattr(p, k) for k in ("kev_enabled", "epss_enabled", "epss_threshold", "sla_critical", "sla_high", "sla_medium", "sla_low", "sla_kev",
                                       "kev_refreshed_at", "epss_refreshed_at", "epss_score_date", "last_error")} | {"priority_labels": PRIORITY_LABELS}


def update_policy(session: Session, actor, **fields) -> VulnPolicy:
    authorize(session, actor, "integration.manage")
    p = policy(session)
    for k, v in fields.items():
        if v is None:
            continue
        if k.startswith("sla_") and not 1 <= int(v) <= 730:
            raise ValueError("Deadlines must be between 1 and 730 days.")
        if k == "epss_threshold" and not 0.0 < float(v) <= 1.0:
            raise ValueError("The EPSS threshold is a probability between 0 and 1.")
        setattr(p, k, v)
    session.flush()
    prioritise(session)
    return p


# ---- feeds ------------------------------------------------------------------------------------------------------

def _parse_date(v) -> date | None:
    try:
        return date.fromisoformat(str(v)[:10]) if v else None
    except ValueError:
        return None


def parse_kev(doc) -> list[KevEntry]:
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise ConnectorError("The KEV catalogue wasn't in the expected format.")
    rows = doc["vulnerabilities"]
    if len(rows) > MAX_KEV_ENTRIES:
        raise ConnectorError("The KEV catalogue is larger than expected.")
    out: dict[str, KevEntry] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        cve = str(r.get("cveID") or "").upper()
        if not CVE_RE.fullmatch(cve):
            continue
        ransom = str(r.get("knownRansomwareCampaignUse") or "").lower()
        out[cve] = KevEntry(cve=cve, vendor=str(r.get("vendorProject") or "")[:200] or None, product=str(r.get("product") or "")[:200] or None,
                            name=str(r.get("vulnerabilityName") or "")[:500] or None, date_added=_parse_date(r.get("dateAdded")),
                            due_date=_parse_date(r.get("dueDate")), ransomware=True if ransom == "known" else False if ransom == "unknown" else None)
    if not out:
        raise ConnectorError("The KEV catalogue was empty.")
    return list(out.values())


def parse_epss(gz: bytes, wanted: set[str]) -> tuple[dict[str, tuple[float, float | None]], date | None]:
    """Read the gzip'd EPSS CSV with a cap on its inflated size; keep only the wanted CVEs."""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(gz)) as f:
            raw = f.read(MAX_EPSS_UNCOMPRESSED + 1)
    except (OSError, EOFError) as e:
        raise ConnectorError("The EPSS file couldn't be decompressed.") from e
    if len(raw) > MAX_EPSS_UNCOMPRESSED:
        raise ConnectorError("The EPSS file is larger than expected.")
    text = raw.decode("utf-8", "replace")
    score_date = None
    lines = text.splitlines()
    if lines and lines[0].startswith("#"):
        m = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", lines[0])
        score_date = _parse_date(m.group(1)) if m else None
        lines = lines[1:]
    out: dict[str, tuple[float, float | None]] = {}
    reader = csv.DictReader(lines)
    if not reader.fieldnames or "cve" not in reader.fieldnames or "epss" not in reader.fieldnames:
        raise ConnectorError("The EPSS file wasn't in the expected format.")
    for row in reader:
        cve = (row.get("cve") or "").upper()
        if cve in wanted:
            try:
                score = float(row.get("epss") or "")
                pct = float(row["percentile"]) if row.get("percentile") else None
            except ValueError:
                continue
            if 0.0 <= score <= 1.0:
                out[cve] = (score, pct)
    return out, score_date


def cves_of(text: str | None) -> list[str]:
    return sorted({c.upper() for c in CVE_RE.findall(text or "")})


def _wanted(session: Session) -> set[str]:
    out: set[str] = set()
    for cve in session.scalars(select(AsmVulnerability.cve).where(AsmVulnerability.cve.is_not(None))):
        out.update(cves_of(cve))
    return out


def refresh(session: Session, actor=None, today: date | None = None) -> dict:
    """Download the enabled feeds and re-prioritise. A feed that fails keeps its previous data; the error is stored
    on the policy and raised as ConnectorError after the other feed has been tried."""
    if actor is not None:
        authorize(session, actor, "integration.manage")
    p = policy(session)
    today = today or datetime.now(timezone.utc).date()
    errors: list[str] = []
    out: dict[str, int | None] = {"kev": None, "epss": None}
    if p.kev_enabled:
        try:
            entries = parse_kev(Api(KEV_POLICY).json("GET", KEV_URL))
            session.execute(delete(KevEntry))
            session.add_all(entries)
            p.kev_refreshed_at = utcnow()
            out["kev"] = len(entries)
        except ConnectorError as e:
            errors.append(f"KEV: {e}")
    if p.epss_enabled:
        wanted = _wanted(session)
        try:
            body, last = None, None
            for day in (today, today - timedelta(days=1)):  # today's file appears during the day (UTC)
                try:
                    body = Api(EPSS_POLICY).request("GET", EPSS_URL.format(day=day.isoformat()), headers={"Accept": "application/gzip"}).content
                    break
                except ConnectorError as e:
                    last = e
            if body is None:
                raise last or ConnectorError("EPSS file not available")
            scores, score_date = parse_epss(body, wanted)
            session.execute(delete(EpssScore))
            session.add_all([EpssScore(cve=c, score=s, percentile=pct, score_date=score_date) for c, (s, pct) in scores.items()])
            p.epss_refreshed_at, p.epss_score_date = utcnow(), score_date
            out["epss"] = len(scores)
        except ConnectorError as e:
            errors.append(f"EPSS: {e}")
    p.last_error = "; ".join(errors)[:500] or None
    session.flush()
    out["prioritised"] = prioritise(session)
    if errors:
        raise ConnectorError(p.last_error or "feed refresh failed")
    return out


# ---- prioritisation ---------------------------------------------------------------------------------------------

def _priority(severity: str, kev: bool, epss: float | None, exploitable: bool, threshold: float) -> str:
    if kev:
        return "P1"
    if (epss is not None and epss >= threshold) or (exploitable and severity in ("critical", "high")):
        return "P2"
    return "P3" if severity in ("critical", "high") else "P4"


def prioritise(session: Session, vulns: Iterable[AsmVulnerability] | None = None) -> int:
    """Set kev, epss, priority and fix_by on open vulnerabilities. Returns how many were updated."""
    p = policy(session)
    kev = {k.cve: k for k in session.scalars(select(KevEntry))} if p.kev_enabled else {}
    epss = {e.cve: e.score for e in session.scalars(select(EpssScore))} if p.epss_enabled else {}
    sla = {"critical": p.sla_critical, "high": p.sla_high, "medium": p.sla_medium, "low": p.sla_low}
    rows = vulns if vulns is not None else session.scalars(select(AsmVulnerability).where(AsmVulnerability.state == "open"))
    n = 0
    for v in rows:
        cves = cves_of(v.cve)
        hits = [kev[c] for c in cves if c in kev]
        scores = [epss[c] for c in cves if c in epss]
        v.kev = bool(hits)
        v.epss = max(scores) if scores else None
        v.priority = _priority(v.severity, v.kev, v.epss, v.exploitable, p.epss_threshold)
        seen = v.first_seen or utcnow().date()
        due = seen + timedelta(days=sla.get(v.severity, p.sla_low))
        if hits:
            added = max((h.date_added for h in hits if h.date_added), default=seen)
            due = min(due, max(seen, added) + timedelta(days=p.sla_kev))
        v.fix_by = due
        n += 1
    session.flush()
    return n


# ---- views ------------------------------------------------------------------------------------------------------

def summary(session: Session, on: date | None = None) -> dict:
    on = on or utcnow().date()
    base = select(func.count(AsmVulnerability.id)).where(AsmVulnerability.state == "open")
    by_priority = dict(session.execute(select(AsmVulnerability.priority, func.count()).where(AsmVulnerability.state == "open").group_by(AsmVulnerability.priority)).all())
    return {
        "known_exploited": session.scalar(base.where(AsmVulnerability.kev.is_(True))) or 0,
        "overdue": session.scalar(base.where(AsmVulnerability.fix_by < on)) or 0,
        "by_priority": {k: by_priority.get(k, 0) for k in PRIORITIES},
    }


def vulnerabilities(session: Session, actor, *, priority: str | None = None, overdue: bool = False, kev_only: bool = False,
                    device_id: int | None = None, limit: int = 1000, on: date | None = None) -> list[dict]:
    authorize(session, actor, "read")
    on = on or utcnow().date()
    q = select(AsmVulnerability, AsmDevice).join(AsmDevice, AsmDevice.id == AsmVulnerability.device_id).where(AsmVulnerability.state == "open")
    if priority:
        q = q.where(AsmVulnerability.priority == priority)
    if overdue:
        q = q.where(AsmVulnerability.fix_by < on)
    if kev_only:
        q = q.where(AsmVulnerability.kev.is_(True))
    if device_id:
        q = q.where(AsmVulnerability.device_id == device_id)
    q = q.order_by(AsmVulnerability.priority, AsmVulnerability.fix_by, AsmVulnerability.id).limit(limit)
    kev = {k.cve: k for k in session.scalars(select(KevEntry))}
    out = []
    for v, d in session.execute(q).all():
        hits = [kev[c] for c in cves_of(v.cve) if c in kev]
        out.append({"id": v.id, "device_id": d.id, "device": d.name, "owner_user_id": d.owner_user_id, "cve": v.cve, "title": v.title,
                    "severity": v.severity, "cvss": v.cvss, "exploitable": v.exploitable, "kev": v.kev, "ransomware": any(h.ransomware for h in hits),
                    "epss": v.epss, "priority": v.priority, "first_seen": v.first_seen, "fix_by": v.fix_by,
                    "overdue": bool(v.fix_by and v.fix_by < on), "days_left": (v.fix_by - on).days if v.fix_by else None})
    return out
