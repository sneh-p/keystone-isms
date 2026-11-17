"""SMTP delivery for email digests.

The relay host is chosen by an administrator, so it is treated as an input-chosen destination:
- SC-SSRF-002: the host is resolved once, must be public, and the connection goes to that exact IP while TLS still
  verifies the certificate for the host name. A private relay (for example an internal Exchange server) is allowed
  only when the server operator lists its name in KEYSTONE_SMTP_PRIVATE_HOSTS; it can't be enabled from the web UI.
- Only the usual submission ports are allowed, so the setting can't be used to probe other services.
- TLS is required (STARTTLS or implicit TLS) with certificate verification; there is no plain-text fallback.
- SC-SSRF-003: the password is bound to the host it was entered for (service.py clears it when the host changes),
  so it is only ever sent to that host.
"""

from __future__ import annotations

import ipaddress
import os
import re
import smtplib
import socket
import ssl
from email.message import EmailMessage
from email.utils import formataddr

ALLOWED_PORTS = (25, 465, 587, 2525)
HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
TIMEOUT = 20.0


def private_allowlist() -> set[str]:
    return {h.strip().lower() for h in os.environ.get("KEYSTONE_SMTP_PRIVATE_HOSTS", "").split(",") if h.strip()}


def validate_host(host: str) -> str:
    h = (host or "").strip().lower().rstrip(".")
    if not HOST.match(h):
        raise ValueError("Enter the relay's host name (for example smtp.office365.com), not an IP address or URL.")
    return h


def resolve(host: str) -> str:
    """The IP to connect to (SC-SSRF-002)."""
    if host in private_allowlist():
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except (socket.gaierror, UnicodeError):
            raise ValueError(f"Cannot resolve {host}.") from None
        addrs = [ipaddress.ip_address(str(i[4][0]).split("%")[0]) for i in infos]
        if any(a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified for a in addrs):
            raise ValueError(f"{host} resolves to a loopback, link-local or reserved address.")
        return str(next((a for a in addrs if a.version == 4), addrs[0]))
    from keystone.integrations.providers.website import assert_public_host

    try:
        return assert_public_host(host)
    except ValueError:
        raise ValueError(f"{host} resolves to a non-public address. To use an internal relay, the server operator "
                         "must add it to KEYSTONE_SMTP_PRIVATE_HOSTS.") from None


class _PinnedSMTP(smtplib.SMTP):
    """Connects to a validated IP; STARTTLS verifies the certificate for the original host name."""

    def __init__(self, hostname: str, ip: str, port: int):
        super().__init__(timeout=TIMEOUT)
        self.connect(ip, port)
        self._host = hostname  # used by starttls() as server_hostname


class _PinnedSMTPS(smtplib.SMTP_SSL):
    def __init__(self, hostname: str, ip: str, port: int, context: ssl.SSLContext):
        self._server_name = hostname
        super().__init__(timeout=TIMEOUT, context=context)
        self.connect(ip, port)

    def _get_socket(self, host, port, timeout):
        sock = socket.create_connection((host, port), timeout, self.source_address)
        return self.context.wrap_socket(sock, server_hostname=self._server_name)


def connect(host: str, port: int, security: str) -> smtplib.SMTP:
    if port not in ALLOWED_PORTS:
        raise ValueError(f"Port must be one of {', '.join(map(str, ALLOWED_PORTS))}.")
    ip = resolve(host)
    ctx = ssl.create_default_context()  # verifies the certificate chain and host name
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if security == "tls":
        return _PinnedSMTPS(host, ip, port, ctx)
    if security != "starttls":
        raise ValueError("Security must be STARTTLS or TLS.")
    s = _PinnedSMTP(host, ip, port)
    s.ehlo()
    if not s.has_extn("starttls"):
        s.close()
        raise ValueError("The relay does not offer STARTTLS; Keystone does not send email without encryption.")
    s.starttls(context=ctx)
    s.ehlo()
    return s


def build(sender: str, sender_name: str, to: str, subject: str, body: str, attachments: list[tuple[str, str, bytes]] | None = None) -> EmailMessage:
    """Plain-text message, optionally with attachments (filename, MIME type, bytes). EmailMessage refuses CR/LF in
    headers, so subjects, names and filenames can't inject headers."""
    m = EmailMessage()
    m["From"] = formataddr((sender_name, sender))
    m["To"] = to
    m["Subject"] = subject
    m["Auto-Submitted"] = "auto-generated"
    m.set_content(body)
    for filename, mime, data in attachments or []:
        maintype, _, subtype = mime.partition("/")
        m.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return m


def send(cfg: dict, messages: list[EmailMessage]) -> None:
    """cfg: host, port, security, username, password. One connection for the whole batch."""
    s = connect(cfg["host"], cfg["port"], cfg["security"])
    try:
        if cfg.get("username"):
            s.login(cfg["username"], cfg.get("password") or "")
        for m in messages:
            s.send_message(m)
    finally:
        try:
            s.quit()
        except (smtplib.SMTPException, OSError):
            s.close()
