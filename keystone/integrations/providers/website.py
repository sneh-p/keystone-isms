"""Public website / TLS hygiene. No credentials. Private and internal addresses are refused (SSRF guard)."""

from __future__ import annotations

import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from .base import CheckDef, ConfigField, Outcome, Provider

SECURITY_HEADERS = ("strict-transport-security", "x-content-type-options", "content-security-policy")


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
    fields = (ConfigField("url", "Website URL", help="e.g. https://www.example.com"),)
    checks = (
        CheckDef("https_redirect", "HTTP redirects to HTTPS", ("KC-TEC-24", "KC-TEC-20")),
        CheckDef("tls_version", "TLS 1.2 or newer", ("KC-TEC-24",)),
        CheckDef("certificate", "Certificate valid for more than 14 days", ("KC-TEC-24",)),
        CheckDef("security_headers", "Security headers present", ("KC-TEC-26", "KC-TEC-20")),
    )

    def __init__(self, client_factory=None, tls=tls_info, resolve_check=assert_public_host):
        self.client_factory = client_factory or (lambda: httpx.Client(timeout=10.0, follow_redirects=False))
        self.tls = tls
        self.resolve_check = resolve_check

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
                r = c.get(f"https://{host}{p.path or '/'}")
                missing = [h for h in SECURITY_HEADERS if h not in {k.lower() for k in r.headers}]
                out.append(Outcome("security_headers", "pass" if not missing else "fail", "All present" if not missing else "Missing: " + ", ".join(missing), {"missing": missing}))
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
