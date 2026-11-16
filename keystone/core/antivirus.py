"""Virus scanning with ClamAV (clamd), for files uploaded from outside the company.

Fail closed: if the scanner can't be reached, times out or returns anything but a clean result, the upload is
refused. Uses clamd's INSTREAM command directly over its socket (no extra dependency):
https://docs.clamav.net/manual/Usage/Scanning.html#clamd

Configuration: KEYSTONE_CLAMD_SOCKET (default /var/run/clamav/clamd.ctl), or KEYSTONE_CLAMD_TCP="host:port" for a
ClamAV container. The TCP host is set by the server operator, never from the web UI.
"""

from __future__ import annotations

import os
import socket
import struct

CHUNK = 64 * 1024
TIMEOUT = 30.0


class ScannerUnavailable(RuntimeError):
    """The scanner could not give a verdict; callers must refuse the file."""


class Infected(ValueError):
    def __init__(self, signature: str):
        super().__init__("The file was rejected by the virus scanner.")
        self.signature = signature


def _connect() -> socket.socket:
    tcp = os.environ.get("KEYSTONE_CLAMD_TCP", "").strip()
    try:
        if tcp:
            host, _, port = tcp.rpartition(":")
            return socket.create_connection((host, int(port)), timeout=TIMEOUT)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect(os.environ.get("KEYSTONE_CLAMD_SOCKET", "/var/run/clamav/clamd.ctl"))
        return s
    except (OSError, ValueError) as e:
        raise ScannerUnavailable(f"virus scanner unreachable ({type(e).__name__})") from None


def _reply(s: socket.socket) -> str:
    buf = b""
    while not buf.endswith(b"\0") and len(buf) < 4096:
        part = s.recv(1024)
        if not part:
            break
        buf += part
    return buf.rstrip(b"\0").decode("utf-8", "replace").strip()


def scan(data: bytes) -> None:
    """Raise Infected or ScannerUnavailable unless clamd reports the bytes clean."""
    s = _connect()
    try:
        s.sendall(b"zINSTREAM\0")
        for i in range(0, len(data), CHUNK):
            part = data[i:i + CHUNK]
            s.sendall(struct.pack(">I", len(part)) + part)
        s.sendall(struct.pack(">I", 0))
        answer = _reply(s)
    except OSError as e:
        raise ScannerUnavailable(f"virus scan failed ({type(e).__name__})") from None
    finally:
        s.close()
    if answer.endswith("OK") and "FOUND" not in answer:
        return
    if answer.endswith("FOUND"):
        raise Infected(answer.removeprefix("stream:").removesuffix("FOUND").strip()[:200])
    raise ScannerUnavailable("virus scanner did not return a clean result")


def ping() -> bool:
    try:
        s = _connect()
    except ScannerUnavailable:
        return False
    try:
        s.sendall(b"zPING\0")
        return _reply(s) == "PONG"
    except OSError:
        return False
    finally:
        s.close()
