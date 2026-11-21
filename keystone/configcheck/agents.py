"""Agent distribution and fleet health: the scripts Keystone serves, their versions and hashes, check-ins, integrity,
and how far the agents cover the devices your other tools know about.

Integrity: every script Keystone has served is recorded (platform, version, SHA-256) from the files on disk. An agent
reports the hash of its own installed copy; a hash Keystone never served means the script was changed on that host.
This catches accidental or careless edits. It cannot stop someone with administrator rights on the host, who could
also make a modified agent report the expected hash: agents are report-only, and their reports are data, not truth.

Signed Windows agent: an administrator may put an Authenticode-signed copy at <data dir>/agents/keystone-agent.ps1.
Keystone serves it only if, without its signature block, it is exactly the script shipped with this version, so a
signed file can't be used to hand out a different script.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.db import utcnow
from keystone.core.settings import PROJECT_ROOT, get_settings

from .models import AgentRelease, ConfigTarget

_LOG = logging.getLogger(__name__)
AGENTS_DIR = PROJECT_ROOT / "agents"
AGENT_FILES = {"windows": ("windows", "keystone-agent.ps1"), "linux": ("linux", "keystone-agent.sh"), "macos": ("macos", "keystone-agent.sh")}
DOWNLOAD_NAMES = {"windows": "keystone-agent.ps1", "linux": "keystone-agent.sh", "macos": "keystone-agent-macos.sh"}
_VERSION = {"windows": re.compile(r"\$script:AgentVersion = '(\d+\.\d+\.\d+)'"), "linux": re.compile(r'^AGENT_VERSION="(\d+\.\d+\.\d+)"', re.M),
            "macos": re.compile(r'^AGENT_VERSION="(\d+\.\d+\.\d+)"', re.M)}
SIGNATURE_MARK = b"# SIG # Begin signature block"
MAX_SIGNED_BYTES = 4 * 1024 * 1024
CHECKIN_HOURS = 1  # agents 1.2+ check in every hour
SILENT_AFTER_HOURS = 3  # no check-in for this long: the agent has gone quiet
COVERAGE_DAYS = 30  # devices other tools saw in this many days count for coverage
SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class AgentFile:
    platform: str
    data: bytes
    version: str
    sha256: str
    signed: bool


def _normalise(data: bytes) -> bytes:
    return data.removeprefix(b"\xef\xbb\xbf").replace(b"\r\n", b"\n").rstrip()


def _signed_windows(shipped: bytes) -> bytes | None:
    path = get_settings().data_dir / "agents" / "keystone-agent.ps1"
    if not path.is_file() or path.stat().st_size > MAX_SIGNED_BYTES:
        return None
    data = path.read_bytes()
    cut = data.find(SIGNATURE_MARK)
    if cut < 0:
        _LOG.warning("ignoring %s: it has no signature block", path)
        return None
    if _normalise(data[:cut]) != _normalise(shipped):
        _LOG.warning("ignoring %s: without its signature it differs from the agent shipped with this version", path)
        return None
    return data


def agent_file(platform: str) -> AgentFile:
    if platform not in AGENT_FILES:
        raise LookupError("Unknown agent.")
    folder, name = AGENT_FILES[platform]
    shipped = (AGENTS_DIR / folder / name).read_bytes()
    m = _VERSION[platform].search(shipped.decode("utf-8", "replace"))
    version = m.group(1) if m else "0.0.0"
    signed = _signed_windows(shipped) if platform == "windows" else None
    data = signed if signed is not None else shipped
    return AgentFile(platform, data, version, hashlib.sha256(data).hexdigest(), signed is not None)


def record_releases(session: Session) -> dict[str, AgentFile]:
    """Remember the scripts currently served, so hosts running them are recognised later."""
    files = {p: agent_file(p) for p in AGENT_FILES}
    for f in files.values():
        if session.scalar(select(AgentRelease.id).where(AgentRelease.platform == f.platform, AgentRelease.sha256 == f.sha256)) is None:
            session.add(AgentRelease(platform=f.platform, version=f.version, sha256=f.sha256, signed=f.signed, first_seen=utcnow()))
    session.flush()
    return files


def _ver(v: str | None) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in (v or "").split(".")[:3])
    except ValueError:
        return ()


def state(session: Session, t: ConfigTarget, current: dict[str, AgentFile] | None = None) -> dict:
    """Integrity (ok | modified | unknown), whether a newer agent is available, and whether the agent has gone quiet."""
    if t.kind != "agent":
        return {"integrity": None, "outdated": False, "latest_version": None, "silent": False, "checks_in": False, "last_contact": t.facts_at}
    files = current or {p: agent_file(p) for p in AGENT_FILES}
    latest = files[t.platform].version if t.platform in files else None
    integrity = "unknown"
    if t.agent_sha256:
        known = session.scalar(select(AgentRelease.id).where(AgentRelease.platform == t.platform, AgentRelease.sha256 == t.agent_sha256))
        integrity = "ok" if known is not None else "modified"
    contact = max((x for x in (t.last_seen_at, t.facts_at) if x is not None), default=None)
    silent = bool(t.revoked_at is None and t.last_seen_at is not None and (contact is None or contact < utcnow() - timedelta(hours=SILENT_AFTER_HOURS)))
    return {"integrity": integrity, "outdated": bool(latest and _ver(t.agent_version) and _ver(t.agent_version) < _ver(latest)), "latest_version": latest,
            "silent": silent, "checks_in": t.last_seen_at is not None, "last_contact": contact}


def clean_sha(v: str | None) -> str | None:
    v = (v or "").strip().lower()
    return v if SHA256.match(v) else None


def report_due(t: ConfigTarget, report_hours: int) -> bool:
    """A full report is due when the last one is older than the report interval (less a little, so hourly check-ins
    don't push it an hour late)."""
    return t.facts_at is None or t.facts_at < utcnow() - timedelta(hours=report_hours) + timedelta(minutes=10)


# ---- linking hosts to the attack surface inventory and the asset register --------------------------------------------

def short_name(name: str | None) -> str:
    return (name or "").strip().lower().split(".")[0]


def link(session: Session, t: ConfigTarget, assets: bool = True) -> None:
    """Link an agent host to the attack surface device with the same host name and, when `assets`, to an asset (the
    device's, or the only asset with that name). Links an administrator set are never replaced."""
    from keystone.asm.models import AsmDevice

    from .service import suggest_assets

    if t.kind != "agent":
        return
    host = short_name(t.hostname or t.name)
    if t.device_id is None and host:
        devices = list(session.scalars(select(AsmDevice).where(AsmDevice.hostname == host, AsmDevice.retired.is_(False)).limit(2)))
        if len(devices) == 1:
            t.device_id = devices[0].id
    if t.asset_id is None and assets:
        dev = session.get(AsmDevice, t.device_id) if t.device_id else None
        if dev is not None and dev.asset_id:
            t.asset_id = dev.asset_id
        else:
            found = suggest_assets(session, t, limit=2)
            if len(found) == 1:
                t.asset_id = found[0].id


def coverage(session: Session) -> dict:
    """Devices your other tools reported recently without a Keystone agent, agent hosts without endpoint security, and
    agent hosts no other tool knows."""
    from keystone.asm.models import AsmDevice, AsmSourceRecord

    since = utcnow() - timedelta(days=COVERAGE_DAYS)
    devices = [d for d in session.scalars(select(AsmDevice).where(AsmDevice.retired.is_(False), AsmDevice.device_type.in_(("workstation", "server"))))
               if d.last_seen is None or d.last_seen >= since]
    cats: dict[int, set[str]] = {}
    for device_id, category in session.execute(select(AsmSourceRecord.device_id, AsmSourceRecord.category)):
        cats.setdefault(device_id, set()).add(category)
    edr_source = any("edr" in c for c in cats.values())
    agents = list(session.scalars(select(ConfigTarget).where(ConfigTarget.kind == "agent", ConfigTarget.revoked_at.is_(None))))
    hosts = {short_name(t.hostname or t.name) for t in agents} | {short_name(t.name) for t in agents}
    linked = {t.device_id for t in agents if t.device_id}
    by_id = {d.id: d for d in devices}

    def dev_row(d) -> dict:
        return {"id": d.id, "name": d.name, "hostname": d.hostname, "os": d.os, "type": d.device_type, "last_seen": d.last_seen, "tools": sorted(cats.get(d.id, ()))}

    def target_row(t) -> dict:
        return {"id": t.id, "name": t.name, "platform": t.platform, "device_id": t.device_id}

    no_agent = [dev_row(d) for d in devices if d.id not in linked and (d.hostname or "") not in hosts]
    no_edr = [target_row(t) for t in agents if edr_source and t.device_id in by_id and "edr" not in cats.get(t.device_id, set())]
    unknown = [target_row(t) for t in agents if t.device_id is None or t.device_id not in by_id]
    covered = len(devices) - len(no_agent)
    return {"devices": len(devices), "with_agent": covered, "percent": round(100 * covered / len(devices)) if devices else None, "edr_source": edr_source,
            "no_agent": no_agent[:500], "no_agent_count": len(no_agent), "no_edr": no_edr[:500], "not_in_tools": unknown[:500], "days": COVERAGE_DAYS}
