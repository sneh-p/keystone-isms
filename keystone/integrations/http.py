"""The one way attack surface connectors talk to vendor APIs (SC-SSRF-001/002/003).

- HTTPS only; no credentials, explicit ports or IP addresses in URLs; redirects are refused.
- Each connector declares where it may go: exact vendor hosts, or a vendor domain for customer-specific consoles
  (e.g. <tenant>.sentinelone.net). Pagination links returned by an API are checked against the same rule.
- Self-hosted servers (N-central, ConnectWise Automate) must resolve to public addresses; an internal server is
  allowed only when the operator lists its name in KEYSTONE_INTEGRATION_PRIVATE_HOSTS (never from the web UI).
- Every request connects to the address validated for it (DNS rebinding), presenting the host name for TLS.
- Timeouts, a response size cap, a page cap and polite handling of 429 Retry-After.
- Error messages name the status and endpoint, never the response body (which may echo secrets).
"""

from __future__ import annotations

from typing import Any

import ipaddress
import os
import re
import socket
import time
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

MAX_BYTES = 50 * 1024 * 1024
TIMEOUT = httpx.Timeout(30.0, connect=10.0)
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

# Tests replace this with httpx.MockTransport; production leaves it None.
TEST_TRANSPORT: httpx.BaseTransport | None = None


class ConnectorError(ValueError):
    """A readable failure (shown on the integration); ValueError so the run reports it as an error, never a pass."""


@dataclass(frozen=True)
class HostPolicy:
    hosts: frozenset[str] = frozenset()  # exact host names
    suffixes: tuple[str, ...] = ()  # ".sentinelone.net": any sub-domain of the vendor's domain
    self_hosted: bool = False  # any public host (the customer's own server), see module docstring

    def allows(self, host: str) -> bool:
        if not HOST_RE.match(host):
            return False
        if host in self.hosts or any(host.endswith(s) and len(host) > len(s) for s in self.suffixes):
            return True
        return self.self_hosted


def private_allowlist() -> set[str]:
    return {h.strip().lower() for h in os.environ.get("KEYSTONE_INTEGRATION_PRIVATE_HOSTS", "").split(",") if h.strip()}


def validate_base_url(url: str, policy: HostPolicy) -> str:
    """Normalise a base URL from configuration (https://host[/path]) and check it against the policy."""
    u = (url or "").strip()
    if "://" not in u:
        u = "https://" + u
    p = urlparse(u)
    host = (p.hostname or "").lower()
    if p.scheme != "https" or p.username or p.password or p.port or p.query or p.fragment:
        raise ConnectorError("Enter the server as https://host (no port, user name or query).")
    if not policy.allows(host):
        raise ConnectorError(f"{host or 'That address'} isn't a valid address for this connector.")
    return f"https://{host}{p.path.rstrip('/')}"


def _resolve(host: str) -> str:
    """The address to connect to: public addresses only, unless the operator allowlisted this host."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        raise ConnectorError(f"Cannot resolve {host}.") from None
    addrs = [ipaddress.ip_address(str(i[4][0]).split("%")[0]) for i in infos]
    if host in private_allowlist():
        ok = [a for a in addrs if not (a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified)]
    else:
        from keystone.integrations.providers.website import _is_public

        ok = addrs if addrs and all(_is_public(a) for a in addrs) else []
    if not ok:
        raise ConnectorError(f"{host} resolves to a non-public address. An internal server must be allowed by the server operator (KEYSTONE_INTEGRATION_PRIVATE_HOSTS).")
    return str(next((a for a in ok if a.version == 4), ok[0]))


class Api:
    """A small client bound to a host policy. Use one per connector run."""

    def __init__(self, policy: HostPolicy, headers: dict | None = None, max_pages: int = 2000):
        self.policy = policy
        self.headers = dict(headers or {})
        self.max_pages = max_pages
        self.pages = 0
        self._ips: dict[str, str] = {}

    def _check(self, url: str) -> tuple[str, str]:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        if p.scheme != "https" or p.username or p.password or (p.port not in (None, 443)):
            raise ConnectorError("Refused a non-HTTPS or unusual URL.")
        if not self.policy.allows(host):
            raise ConnectorError(f"Refused to contact {host}: not an address of this connector.")
        return host, p.path

    def request(self, method: str, url: str, *, headers: dict | None = None, retries: int = 3, **kw) -> httpx.Response:
        self.pages += 1
        if self.pages > self.max_pages:
            raise ConnectorError("Stopped: the source returned more pages than Keystone reads in one run.")
        host, path = self._check(url)
        h = {**self.headers, **(headers or {}), "Accept": (headers or {}).get("Accept", "application/json"), "User-Agent": "Keystone-ISMS"}
        ext: dict[str, Any]
        for attempt in range(retries + 1):
            if TEST_TRANSPORT is not None:
                client, target, ext = httpx.Client(transport=TEST_TRANSPORT, timeout=TIMEOUT, follow_redirects=False), url, {}
            else:
                from keystone.integrations.providers.website import _pinned

                ip = self._ips.get(host) or self._ips.setdefault(host, _resolve(host))
                target, host_header, ext = _pinned(url, ip)
                h = {**h, **host_header}
                client = httpx.Client(timeout=TIMEOUT, follow_redirects=False)
            try:
                with client, client.stream(method, target, headers=h, extensions=ext, **kw) as r:
                    size, chunks = 0, []
                    for chunk in r.iter_bytes():
                        size += len(chunk)
                        if size > MAX_BYTES:
                            raise ConnectorError(f"Response from {host} was too large.")
                        chunks.append(chunk)
                    resp = httpx.Response(r.status_code, headers=r.headers, content=b"".join(chunks), request=r.request)
            except httpx.TimeoutException:
                raise ConnectorError(f"{host} didn't answer in time.") from None
            except httpx.HTTPError as e:
                raise ConnectorError(f"Couldn't reach {host} ({type(e).__name__}).") from None
            if resp.status_code == 429 and attempt < retries:
                try:
                    wait = min(30.0, float(resp.headers.get("Retry-After", "5")))
                except ValueError:
                    wait = 5.0
                time.sleep(wait)
                continue
            if 300 <= resp.status_code < 400:
                raise ConnectorError(f"{host} redirected {path}; Keystone doesn't follow redirects.")
            if resp.status_code in (401, 403):
                raise ConnectorError(f"{host} refused access to {path} ({resp.status_code}): check the credentials and their read permissions.")
            if resp.status_code >= 400:
                raise ConnectorError(f"{host} returned {resp.status_code} for {path}.")
            return resp
        raise ConnectorError(f"{host} kept asking Keystone to slow down (429).")

    def json(self, method: str, url: str, **kw):
        r = self.request(method, url, **kw)
        try:
            return r.json()
        except ValueError:
            raise ConnectorError(f"{urlparse(url).hostname} didn't return JSON for {urlparse(url).path}.") from None


def fields_of(obj) -> list[str]:
    """Field names of a sample record (for the dry-run preview); values are never included."""
    if isinstance(obj, dict):
        return sorted(obj.keys())[:80]
    return []
