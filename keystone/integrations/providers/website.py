"""Public website / TLS hygiene. No credentials. Private and internal addresses are refused (SSRF guard)."""

from __future__ import annotations

import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx

from .base import CheckDef, ConfigField, Outcome, Provider, SetupStep

SECURITY_HEADERS = ("strict-transport-security", "x-content-type-options", "content-security-policy")
USER_AGENT = "KeystoneISMS/2.0 (read-only website security check)"
REDIRECTS = (301, 302, 303, 307, 308)
MAX_HOPS = 5


def assert_public_host(host: str) -> None:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve {host}.") from None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise ValueError(f"{host} resolves to a non-public address; only public websites can be checked.")


def tls_info(host: str, port: int = 443, timeout: float = 10.0) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock, ctx.wrap_socket(sock, server_hostname=host) as tls:
        cert = tls.getpeercert()
        return {"version": tls.version(), "not_after": cert["notAfter"]}


class WebsiteProvider(Provider):
    key = "website"
    name = "Website & TLS"
    description = "Checks a public website for HTTPS redirect, modern TLS, certificate expiry and security headers."
    fields = (ConfigField("url", "Website URL", help="e.g. https://www.example.com", example="https://www.example.com"),)
    checks = (
        CheckDef("https_redirect", "HTTP redirects to HTTPS", ("KC-TEC-24", "KC-TEC-20")),
        CheckDef("tls_version", "TLS 1.2 or newer", ("KC-TEC-24",)),
        CheckDef("certificate", "Certificate valid for more than 14 days", ("KC-TEC-24",)),
        CheckDef("security_headers", "Security headers present", ("KC-TEC-26", "KC-TEC-20")),
    )
    setup = (
        SetupStep(
            "No credential needed",
            "Keystone makes ordinary anonymous requests to the site, like a browser. The host name must resolve to "
            "a public address: private, loopback and link-local addresses are refused.",
        ),
        SetupStep(
            "See what Keystone will see",
            "Expect a 301 or 308 redirect to https:// from the first command, and the security headers "
            "(Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options) from the second. If these "
            "work but Keystone reports unknown, the site or its firewall blocks automated requests: allow Keystone's "
            "server address or User-Agent (KeystoneISMS).",
            kind="verify",
            code="curl -sI http://{host}/ | grep -iE '^(HTTP|location)'\n"
                 "curl -sI https://{host}/ | grep -iE '^(HTTP|strict-transport-security|content-security-policy|x-content-type-options)'",
        ),
    )

    def __init__(self, client_factory=None, tls=tls_info, resolve_check=assert_public_host):
        self.client_factory = client_factory or (lambda: httpx.Client(timeout=10.0, follow_redirects=False, headers={"user-agent": USER_AGENT}))
        self.tls = tls
        self.resolve_check = resolve_check

    def _headers(self, c, url: str) -> Outcome:
        """Security headers of the page the URL finally serves. Redirects are followed over HTTPS only,
        and every new host must be public. A page that can't be read gives unknown, never fail or pass."""
        for _ in range(MAX_HOPS + 1):
            r = c.get(url)
            loc = r.headers.get("location")
            if r.status_code in REDIRECTS and loc:
                nxt = urljoin(url, loc)
                np = urlparse(nxt)
                if np.scheme != "https":
                    return Outcome("security_headers", "fail", f"The HTTPS page redirects to plain HTTP ({nxt})", {"redirect": nxt})
                try:
                    if np.hostname != urlparse(url).hostname:
                        self.resolve_check(np.hostname or "")
                except ValueError as e:
                    return Outcome("security_headers", "error", f"Redirect not followed: {e}")
                url = nxt
                continue
            if r.status_code >= 400:
                return Outcome("security_headers", "unknown", f"The site answered HTTP {r.status_code} to an automated request, so its headers could not be checked", {"status": r.status_code, "url": url})
            missing = [h for h in SECURITY_HEADERS if h not in {k.lower() for k in r.headers}]
            return Outcome("security_headers", "pass" if not missing else "fail", ("All present" if not missing else "Missing: " + ", ".join(missing)) + f" on {url}", {"missing": missing, "url": url})
        return Outcome("security_headers", "error", f"More than {MAX_HOPS} redirects")

    def run(self, config: dict, secrets: dict, session=None) -> list[Outcome]:
        url = (config.get("url") or "").strip()
        p = urlparse(url if "://" in url else f"https://{url}")
        if p.scheme not in ("http", "https") or not p.hostname:
            raise ValueError("Enter a full website URL.")
        host = p.hostname
        self.resolve_check(host)
        out = []
        with self.client_factory() as c:
            try:
                r = c.get(f"http://{host}/")
                loc = r.headers.get("location", "")
                ok = r.status_code in (301, 302, 307, 308) and loc.startswith("https://")
                out.append(Outcome("https_redirect", "pass" if ok else "fail", f"HTTP returned {r.status_code}" + (f" to {loc}" if loc else ""), {"status": r.status_code}))
            except httpx.HTTPError as e:
                out.append(Outcome("https_redirect", "error", f"HTTP request failed: {type(e).__name__}"))
            try:
                out.append(self._headers(c, f"https://{host}{p.path or '/'}"))
            except httpx.HTTPError as e:
                out.append(Outcome("security_headers", "error", f"HTTPS request failed: {type(e).__name__}"))
        try:
            info = self.tls(host)
            ok = info["version"] in ("TLSv1.2", "TLSv1.3")
            out.append(Outcome("tls_version", "pass" if ok else "fail", f"Negotiated {info['version']}", info))
            expires = datetime.strptime(info["not_after"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (expires - datetime.now(timezone.utc)).days
            out.append(Outcome("certificate", "pass" if days > 14 else "fail", f"Expires in {days} days", {"expires": expires.date().isoformat()}))
        except (OSError, ssl.SSLError, ValueError) as e:
            out += [Outcome("tls_version", "error", f"TLS connection failed: {type(e).__name__}"), Outcome("certificate", "error", "Could not read certificate")]
        return out
