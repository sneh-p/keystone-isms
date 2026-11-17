"""External attack surface: passive discovery and hygiene checks for domains the organisation has proved it owns.

Scope and limits (decided with the round 3 approval; see docs/feature-security-designs.md):
- A domain is only enumerated or checked after its owner publishes a TXT record Keystone generated, and the record is
  re-checked before every scan: Keystone can't be used to map someone else's estate.
- Discovery is passive: certificate transparency (crt.sh, exact host) and DNS lookups through the server's resolver.
- Probing is limited to what a browser does: HTTPS on 443 and one plain HTTP request on 80 to see whether it
  redirects, through the website check (public addresses only, pinned connections, no redirects to private hosts).
  No port scanning, no vulnerability probes, no login attempts.
- Every host probed must be the verified domain or a sub-domain of it.
"""

from __future__ import annotations

import re
import secrets as pysecrets
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.db import utcnow
from keystone.core.services import authorize, get_or_404
from keystone.integrations.http import Api, ConnectorError, HostPolicy

from .models import ExternalDomain, ExternalHost

DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
RECORD_PREFIX = "keystone-site-verification="
VERIFY_LABEL = "_keystone-verification"
CT_URL = "https://crt.sh/?q={q}&output=json"
CT_POLICY = HostPolicy(hosts=frozenset({"crt.sh"}))
MAX_HOSTS = 300
MAX_DOMAINS = 50
PROBE_WORKERS = 6
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class NotVerified(ValueError):
    pass


# ---- DNS (one place, so tests can replace it) --------------------------------------------------------------------

def _resolver():
    import dns.resolver

    r = dns.resolver.Resolver()
    r.lifetime = 5.0
    return r


def dns_txt(name: str) -> list[str]:
    import dns.exception
    import dns.resolver

    try:
        ans = _resolver().resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    return [b"".join(r.strings).decode("utf-8", "replace") for r in ans]


def dns_records(name: str, rtype: str) -> list[str]:
    import dns.exception
    import dns.resolver

    try:
        return [r.to_text().rstrip(".").lower() for r in _resolver().resolve(name, rtype)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def dns_nxdomain(name: str) -> bool:
    """True only when the name definitely doesn't exist (NXDOMAIN), not on timeouts."""
    import dns.exception
    import dns.resolver

    try:
        _resolver().resolve(name, "A")
    except dns.resolver.NXDOMAIN:
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return False
    return False


# ---- domains -------------------------------------------------------------------------------------------------------

def normalise_domain(name: str) -> str:
    d = (name or "").strip().lower().rstrip(".")
    d = d.removeprefix("https://").removeprefix("http://").split("/")[0]
    if not DOMAIN_RE.match(d):
        raise ValueError("Enter a domain name such as example.com.")
    return d


def add_domain(session: Session, actor, name: str) -> ExternalDomain:
    authorize(session, actor, "integration.manage")
    d = normalise_domain(name)
    if session.scalar(select(ExternalDomain).where(ExternalDomain.name == d)):
        raise ValueError(f"{d} is already listed.")
    if len(list(session.scalars(select(ExternalDomain.id)))) >= MAX_DOMAINS:
        raise ValueError(f"Keystone checks up to {MAX_DOMAINS} domains.")
    dom = ExternalDomain(name=d, verification_token=RECORD_PREFIX + pysecrets.token_hex(16))
    session.add(dom)
    session.flush()
    return dom


def remove_domain(session: Session, actor, domain_id: int) -> None:
    authorize(session, actor, "integration.manage")
    session.delete(get_or_404(session, ExternalDomain, domain_id))
    session.flush()


def _has_token(d: ExternalDomain) -> bool:
    return any(t.strip() == d.verification_token for t in dns_txt(f"{VERIFY_LABEL}.{d.name}") + dns_txt(d.name))


def verify(session: Session, actor, domain_id: int) -> ExternalDomain:
    authorize(session, actor, "integration.manage")
    d = get_or_404(session, ExternalDomain, domain_id)
    if not _has_token(d):
        raise NotVerified(f"The TXT record wasn't found yet. Add it at {VERIFY_LABEL}.{d.name} (or at {d.name}) and try again; DNS changes can take a while to appear.")
    d.verified_at = utcnow()
    session.flush()
    return d


# ---- checks ----------------------------------------------------------------------------------------------------------

def _issue(code: str, severity: str, title: str) -> dict:
    return {"code": code, "severity": severity, "title": title}


def email_checks(domain: str) -> tuple[dict, list[dict]]:
    """SPF, DMARC and CAA for the domain itself."""
    issues: list[dict] = []
    txt = dns_txt(domain)
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    if not spf:
        issues.append(_issue("spf_missing", "high", "No SPF record: anyone can send email that claims to be from this domain"))
    elif len(spf) > 1:
        issues.append(_issue("spf_multiple", "medium", "More than one SPF record (receivers treat this as an error)"))
    elif re.search(r"(^|\s)\+all\b", spf[0].lower()):
        issues.append(_issue("spf_pass_all", "critical", "SPF ends in +all, which authorises every server on the internet"))
    elif not re.search(r"(^|\s)[-~]all\b|redirect=", spf[0].lower()):
        issues.append(_issue("spf_weak", "medium", "SPF doesn't end in -all or ~all"))
    dmarc = [t for t in dns_txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    policy = None
    if not dmarc:
        issues.append(_issue("dmarc_missing", "high", "No DMARC record: spoofed email from this domain isn't rejected"))
    else:
        m = re.search(r"\bp\s*=\s*(none|quarantine|reject)", dmarc[0].lower())
        policy = m.group(1) if m else None
        if policy in (None, "none"):
            issues.append(_issue("dmarc_monitor_only", "medium", "DMARC policy is p=none (monitoring only)"))
    caa = dns_records(domain, "CAA")
    if not caa:
        issues.append(_issue("caa_missing", "low", "No CAA record limiting which certificate authorities may issue for this domain"))
    return {"spf": spf[0] if spf else None, "dmarc": dmarc[0] if dmarc else None, "dmarc_policy": policy, "caa": caa[:10]}, issues


def ct_hosts(domain: str) -> set[str]:
    """Host names under the domain seen in certificate transparency logs (crt.sh)."""
    rows = Api(CT_POLICY).json("GET", CT_URL.format(q=quote(f"%.{domain}", safe="")), headers={"Accept": "application/json"}, retries=2)
    if not isinstance(rows, list):
        raise ConnectorError("crt.sh didn't return a list.")
    out: set[str] = set()
    for r in rows:
        if not isinstance(r, dict):
            continue
        for n in str(r.get("name_value") or "").lower().split("\n"):
            n = n.strip().removeprefix("*.").rstrip(".")
            if (n == domain or n.endswith("." + domain)) and DOMAIN_RE.match(n):
                out.add(n)
    return out


def _probe_web(host: str) -> tuple[dict, list[dict]]:
    """HTTPS on 443 and the HTTP to HTTPS redirect, via the website check (public addresses only, pinned)."""
    from keystone.integrations.providers.website import WebsiteProvider

    facts: dict = {}
    issues: list[dict] = []
    try:
        outcomes = {o.key: o for o in WebsiteProvider().run({"url": f"https://{host}/"}, {})}
    except ValueError as e:  # resolves to a non-public address, or not at all
        return {"web": "not checked", "reason": str(e)[:200]}, issues
    tls, cert, redirect, headers = (outcomes.get(k) for k in ("tls_version", "certificate", "https_redirect", "security_headers"))
    if tls and tls.result == "error":
        if "CertVerification" in tls.summary or "CertificateError" in tls.summary:
            facts["web"] = "https"
            issues.append(_issue("cert_invalid", "high", "HTTPS certificate isn't valid for this name (expired, self-signed or wrong host)"))
        else:
            facts["web"] = "no https"
        return facts, issues
    facts["web"] = "https"
    if tls:
        facts["tls_version"] = (tls.details or {}).get("version")
        if tls.result == "fail":
            issues.append(_issue("tls_old", "high", f"Old TLS version ({facts['tls_version']})"))
    if cert and cert.result in ("pass", "fail"):
        facts["cert_expires"] = (cert.details or {}).get("expires")
        if cert.result == "fail":
            issues.append(_issue("cert_expiring", "high", f"Certificate expires soon ({facts['cert_expires']})"))
    if redirect and redirect.result == "fail":
        issues.append(_issue("no_https_redirect", "medium", "Plain HTTP doesn't redirect to HTTPS"))
    if headers and headers.result == "fail" and "strict-transport-security" in ((headers.details or {}).get("missing") or []):
        issues.append(_issue("hsts_missing", "low", "No Strict-Transport-Security header"))
    facts["https_redirect"] = None if not redirect or redirect.result == "error" else redirect.result == "pass"
    return facts, issues


def check_host(host: str) -> tuple[dict, list[dict]]:
    """DNS facts, takeover risk and web hygiene for one host."""
    from ipaddress import ip_address

    from keystone.integrations.providers.website import _is_public

    facts: dict = {}
    issues: list[dict] = []
    cname = dns_records(host, "CNAME")
    facts["cname"] = cname[0] if cname else None
    addrs = dns_records(host, "A") + dns_records(host, "AAAA")
    facts["addresses"] = addrs[:20]
    if facts["cname"] and not addrs and dns_nxdomain(facts["cname"]):
        issues.append(_issue("dangling_cname", "high", f"Points (CNAME) to {facts['cname']}, which doesn't exist: someone could claim it and serve content on this name"))
        return facts, issues
    if not addrs:
        facts["web"] = "no address"
        return facts, issues
    parsed = []
    for a in addrs:
        try:
            parsed.append(ip_address(a))
        except ValueError:
            continue
    if any(not _is_public(a) for a in parsed):
        issues.append(_issue("internal_address", "low", "Public DNS gives an internal address for this name (reveals internal naming)"))
        facts["web"] = "not checked"
        return facts, issues
    web, web_issues = _probe_web(host)
    facts.update(web)
    return facts, issues + web_issues


def _worst(issues: list[dict]) -> str | None:
    return min((i["severity"] for i in issues), key=lambda s: SEVERITY_ORDER.get(s, 9), default=None)


def scan(session: Session, actor, domain_id: int, *, probe=None) -> dict:
    """Re-check ownership, then discover and check hosts. Returns counts."""
    if actor is not None:
        authorize(session, actor, "integration.manage")
    d = get_or_404(session, ExternalDomain, domain_id)
    if not _has_token(d):
        d.verified_at = None
        d.scan_error = "The verification TXT record is gone, so the domain is no longer checked. Add it back and verify again."
        session.flush()
        raise NotVerified(d.scan_error)
    probe = probe or check_host
    now = utcnow()
    d.email, domain_issues = email_checks(d.name)
    errors = []
    names = {d.name, f"www.{d.name}"}
    try:
        names |= ct_hosts(d.name)
    except ConnectorError as e:
        errors.append(f"Certificate transparency: {e}")
    known = {h.host: h for h in session.scalars(select(ExternalHost).where(ExternalHost.domain_id == d.id))}
    names |= {h for h, row in known.items() if row.source == "manual"}
    ordered = sorted(names, key=lambda n: (n != d.name, n.count("."), n))[:MAX_HOSTS]
    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
        results = dict(zip(ordered, pool.map(probe, ordered), strict=True))
    new_issues = 0
    for name, (facts, issues) in results.items():
        h = known.get(name)
        if h is None:
            h = ExternalHost(domain_id=d.id, host=name, source="ct" if name not in (d.name, f"www.{d.name}") else "dns", first_seen=now)
            session.add(h)
            known[name] = h
        before = {i["code"] for i in (h.issues or [])}
        new_issues += sum(1 for i in issues if i["code"] not in before and i["severity"] in ("critical", "high"))
        h.facts, h.issues, h.worst, h.last_seen, h.checked_at = facts, issues, _worst(issues), now, now
    for name, h in known.items():
        h.current = name in results
    before = {i["code"] for i in (d.issues or [])}
    new_issues += sum(1 for i in domain_issues if i["code"] not in before and i["severity"] in ("critical", "high"))
    d.issues, d.last_scan_at, d.scan_error = domain_issues, now, "; ".join(errors)[:500] or None
    session.flush()
    if new_issues:
        _notify(session, d, new_issues)
        from keystone.outbound.service import emit

        emit(session, "external.issue", title=f"{new_issues} new critical or high issue(s) on {d.name}", severity="high", page="/attack-surface?tab=external")
    return {"hosts": len(results), "issues": sum(len(r[1]) for r in results.values()) + len(domain_issues), "new_high": new_issues}


def _notify(session: Session, d: ExternalDomain, n: int) -> None:
    from keystone.core.auth import User, expired
    from keystone.core.rbac import Role
    from keystone.notifications.models import Notification

    users = [u for u in session.scalars(select(User).where(User.active.is_(True))) if not expired(u)]
    managers = [u.id for u in users if u.role == Role.ISMS_MANAGER.value] or [u.id for u in users if u.role == Role.ADMIN.value]
    stamp = utcnow()
    for uid in managers:
        session.add(Notification(user_id=uid, key=f"ext:{d.id}:{stamp:%Y%m%d%H%M%S%f}"[:64], kind="asm",
                                 title=f"{n} new critical or high issue(s) on {d.name}", page="/attack-surface?tab=external", created_at=stamp))
    session.flush()


def add_host(session: Session, actor, domain_id: int, host: str) -> ExternalHost:
    """A host certificate logs don't show (for example one with a wildcard certificate). Must be under the domain."""
    authorize(session, actor, "integration.manage")
    d = get_or_404(session, ExternalDomain, domain_id)
    h = normalise_domain(host)
    if h != d.name and not h.endswith("." + d.name):
        raise ValueError(f"{h} isn't part of {d.name}.")
    row = session.scalar(select(ExternalHost).where(ExternalHost.host == h))
    if row is None:
        row = ExternalHost(domain_id=d.id, host=h, source="manual", first_seen=utcnow())
        session.add(row)
    else:
        row.source = "manual"
    session.flush()
    return row


def scan_all(session: Session) -> dict:
    out = {"scanned": 0, "failed": 0}
    for d in list(session.scalars(select(ExternalDomain).where(ExternalDomain.verified_at.is_not(None)))):
        try:
            scan(session, None, d.id)
            out["scanned"] += 1
        except NotVerified:
            out["failed"] += 1
    return out


# ---- views ---------------------------------------------------------------------------------------------------------

def view(session: Session, actor) -> dict:
    authorize(session, actor, "read")
    domains = list(session.scalars(select(ExternalDomain).order_by(ExternalDomain.name)))
    hosts = sorted(session.scalars(select(ExternalHost).where(ExternalHost.current.is_(True))), key=lambda h: (SEVERITY_ORDER.get(h.worst or "", 9), h.host))
    by_domain: dict[int, list[ExternalHost]] = {}
    for h in hosts:
        by_domain.setdefault(h.domain_id, []).append(h)
    from keystone.core.rbac import has_permission

    can_manage = has_permission(actor, "integration.manage")
    return {
        "domains": [{"id": d.id, "name": d.name, "verified": d.verified_at is not None, "verified_at": d.verified_at,
                     # The token is only useful to whoever adds the DNS record; viewers don't need it.
                     "verification": {"name": f"{VERIFY_LABEL}.{d.name}", "type": "TXT", "value": d.verification_token} if can_manage else None,
                     "last_scan_at": d.last_scan_at, "scan_error": d.scan_error, "email": d.email or {}, "issues": d.issues or [],
                     "hosts": len(by_domain.get(d.id, []))} for d in domains],
        "hosts": [{"id": h.id, "domain_id": h.domain_id, "host": h.host, "source": h.source, "first_seen": h.first_seen, "checked_at": h.checked_at,
                   "facts": h.facts or {}, "issues": h.issues or [], "worst": h.worst} for h in hosts],
        "summary": summary(session),
    }


def summary(session: Session) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for issues in [h.issues for h in session.scalars(select(ExternalHost).where(ExternalHost.current.is_(True)))] + [d.issues for d in session.scalars(select(ExternalDomain))]:
        for i in issues or []:
            counts[i.get("severity", "low")] = counts.get(i.get("severity", "low"), 0) + 1
    return counts

