"""Vulnerabilities in the Linux packages Keystone agents report, from the public OSV data (https://osv.dev).

Decided by human:sneh (2026-11-21): download whole files, match locally. Keystone fetches
`https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip` for each distribution the hosts run (Debian,
Ubuntu, AlmaLinux, Rocky Linux), at most once a day and only when the file changed (ETag), so no outside party learns
which software the organisation runs. The archive is read entry by entry in memory, with limits on entry size, entry
count and total size (SC-FILE-003); nothing from it is extracted to disk or executed.

Only advisories with a fixed version are matched: they say what to upgrade to. Severity comes from the advisory where
it gives one; otherwise "medium", and KEV/EPSS (keystone/asm/vulnintel.py) still raise the priority of exploited ones.
"""

from __future__ import annotations

import json
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

from keystone.core.settings import get_settings
from keystone.integrations.http import Api, ConnectorError, HostPolicy

OSV_HOST = "osv-vulnerabilities.storage.googleapis.com"
OSV_POLICY = HostPolicy(hosts=frozenset({OSV_HOST}))
MAX_DOWNLOAD = 2 * 1024 * 1024 * 1024  # an ecosystem archive; refused if larger
MAX_ENTRY = 8 * 1024 * 1024  # one advisory
MAX_ENTRIES = 2_000_000
MAX_TOTAL = 16 * 1024 * 1024 * 1024  # uncompressed, across all entries read
SEVERITY_WORDS = {"critical": "critical", "high": "high", "important": "high", "medium": "medium", "moderate": "medium", "low": "low", "negligible": "low"}


# ---- version ordering ------------------------------------------------------------------------------------------------

def _dpkg_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_part(a: str, b: str) -> int:
    """Debian's verrevcmp: non-digit runs compared by character order (~ sorts before anything, even the end), then
    digit runs numerically."""
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) else 0
            bc = _dpkg_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_dpkg(v: str) -> tuple[int, str, str]:
    epoch, _, rest = v.partition(":") if ":" in v else ("0", "", v)
    upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch) if epoch.isdigit() else 0, upstream, revision


def dpkg_compare(a: str, b: str) -> int:
    """<0, 0 or >0, as dpkg --compare-versions orders Debian and Ubuntu versions."""
    ea, ua, ra = _split_dpkg(a)
    eb, ub, rb = _split_dpkg(b)
    if ea != eb:
        return ea - eb
    return _dpkg_part(ua, ub) or _dpkg_part(ra, rb)


def _rpm_part(a: str, b: str) -> int:
    """rpm's rpmvercmp: alphanumeric segments, digits numerically, ~ sorts before everything, ^ after the base version."""
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not (a[i].isascii() and a[i].isalnum()) and a[i] not in "~^":
            i += 1
        while j < len(b) and not (b[j].isascii() and b[j].isalnum()) and b[j] not in "~^":
            j += 1
        ta, tb = (i < len(a) and a[i] == "~"), (j < len(b) and b[j] == "~")
        if ta or tb:
            if not ta:
                return 1
            if not tb:
                return -1
            i += 1
            j += 1
            continue
        ca, cb = (i < len(a) and a[i] == "^"), (j < len(b) and b[j] == "^")
        if ca or cb:
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if not ca:
                return 1
            if not cb:
                return -1
            i += 1
            j += 1
            continue
        if i >= len(a) or j >= len(b):
            break
        numeric = a[i].isdigit()
        si, sj = i, j
        if numeric:
            while i < len(a) and a[i].isdigit():
                i += 1
            while j < len(b) and b[j].isdigit():
                j += 1
        else:
            while i < len(a) and a[i].isascii() and a[i].isalpha():
                i += 1
            while j < len(b) and b[j].isascii() and b[j].isalpha():
                j += 1
        sa, sb = a[si:i], b[sj:j]
        if not sb:
            return 1 if numeric else -1
        if numeric:
            sa, sb = sa.lstrip("0"), sb.lstrip("0")
            if len(sa) != len(sb):
                return 1 if len(sa) > len(sb) else -1
        if sa != sb:
            return 1 if sa > sb else -1
    if i >= len(a) and j >= len(b):
        return 0
    return 1 if i < len(a) else -1


def _split_rpm(v: str) -> tuple[int, str, str]:
    epoch, _, rest = v.partition(":") if ":" in v else ("0", "", v)
    version, _, release = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch) if epoch.isdigit() else 0, version, release


def rpm_compare(a: str, b: str) -> int:
    """<0, 0 or >0, as rpm orders epoch:version-release."""
    ea, va, ra = _split_rpm(a)
    eb, vb, rb = _split_rpm(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _rpm_part(va, vb) or (_rpm_part(ra, rb) if ra and rb else 0)


# ---- distributions -----------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Release:
    ecosystem: str  # OSV's name for the release, e.g. "Debian:12"
    archive: str  # the top-level OSV directory, e.g. "Debian"
    compare: str  # dpkg | rpm


def release_of(os_id: str | None, version_id: str | None) -> Release | None:
    """The OSV ecosystem of a host, from /etc/os-release ID and VERSION_ID. None: not matched (shown as inventory only)."""
    i, v = (os_id or "").strip().lower(), (version_id or "").strip()
    if not re.fullmatch(r"[0-9][0-9.]{0,9}", v):
        return None
    major = v.split(".")[0]
    if i == "debian":
        return Release(f"Debian:{major}", "Debian", "dpkg")
    if i == "ubuntu" and re.fullmatch(r"\d{2}\.\d{2}", v):
        lts = v.endswith(".04") and int(major) % 2 == 0
        return Release(f"Ubuntu:{v}:LTS" if lts else f"Ubuntu:{v}", "Ubuntu", "dpkg")
    if i == "almalinux":
        return Release(f"AlmaLinux:{major}", "AlmaLinux", "rpm")
    if i == "rocky":
        return Release(f"Rocky Linux:{major}", "Rocky Linux", "rpm")
    return None


# ---- download and read -------------------------------------------------------------------------------------------------

def cache_dir() -> Path:
    d = get_settings().data_dir / "osv"
    d.mkdir(parents=True, exist_ok=True)
    return d


def fetch(archive: str) -> Path:
    """Download an ecosystem archive when it changed since the last run (ETag). Returns the cached file."""
    if archive not in ("Debian", "Ubuntu", "AlmaLinux", "Rocky Linux"):
        raise ValueError("Unknown OSV archive.")
    safe = archive.replace(" ", "_")
    dest, tag_file = cache_dir() / f"{safe}.zip", cache_dir() / f"{safe}.etag"
    old = tag_file.read_text().strip() if tag_file.exists() and dest.exists() else None
    new = Api(OSV_POLICY).download(f"https://{OSV_HOST}/{quote(archive)}/all.zip", dest, max_bytes=MAX_DOWNLOAD, etag=old)
    if new and new != old:
        tag_file.write_text(new)
    return dest


@dataclass
class Advisory:
    id: str
    aliases: list[str]
    summary: str
    severity: str | None
    ranges: list[list[dict]] = field(default_factory=list)  # ECOSYSTEM events per affected entry


def _severity(doc: dict, affected: dict) -> str | None:
    for src in (affected.get("ecosystem_specific") or {}, affected.get("database_specific") or {}, doc.get("database_specific") or {}):
        word = src.get("severity") or src.get("urgency") if isinstance(src, dict) else None
        if isinstance(word, str) and word.lower() in SEVERITY_WORDS:
            return SEVERITY_WORDS[word.lower()]
    for s in doc.get("severity") or []:
        score = str(s.get("score") or "").lower()
        if score in SEVERITY_WORDS:
            return SEVERITY_WORDS[score]
    return None


def read(path: Path, ecosystems: set[str], packages: dict[str, set[str]]) -> dict[tuple[str, str], list[Advisory]]:
    """Advisories for the (ecosystem, package) pairs in use, from one archive. Entries are read one at a time, within
    the size limits; anything malformed is skipped."""
    out: dict[tuple[str, str], list[Advisory]] = {}
    total = 0
    try:
        z = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        raise ConnectorError("The OSV archive is damaged; it is downloaded again on the next run.") from None
    with z:
        infos = z.infolist()
        if len(infos) > MAX_ENTRIES:
            raise ConnectorError("The OSV archive has more entries than Keystone reads.")
        for info in infos:
            if not info.filename.endswith(".json") or "/" in info.filename or info.file_size > MAX_ENTRY:
                continue
            total += info.file_size
            if total > MAX_TOTAL:
                raise ConnectorError("The OSV archive is larger than Keystone reads.")
            with z.open(info) as f:
                raw = f.read(MAX_ENTRY + 1)
            if len(raw) > MAX_ENTRY:
                continue
            try:
                doc = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(doc, dict) or doc.get("withdrawn"):
                continue
            for aff in doc.get("affected") or []:
                pkg = aff.get("package") or {}
                eco, name = str(pkg.get("ecosystem") or ""), str(pkg.get("name") or "")
                if eco not in ecosystems or name not in packages.get(eco, ()):
                    continue
                ranges = [r.get("events") or [] for r in aff.get("ranges") or [] if r.get("type") == "ECOSYSTEM"]
                if not any(any("fixed" in e for e in r) for r in ranges):
                    continue  # no fixed version yet: nothing to upgrade to
                adv = Advisory(id=str(doc.get("id"))[:100], aliases=[str(a)[:40] for a in (doc.get("aliases") or []) if isinstance(a, str)][:20],
                               summary=str(doc.get("summary") or doc.get("details") or "")[:300], severity=_severity(doc, aff), ranges=ranges)
                out.setdefault((eco, name), []).append(adv)
    return out


def affected(version: str, ranges: list[list[dict]], compare: str) -> str | None:
    """The fixed version if `version` is inside one of the ranges, else None."""
    cmp = dpkg_compare if compare == "dpkg" else rpm_compare
    for events in ranges:
        introduced: str | None = None
        for e in events:
            if "introduced" in e:
                introduced = str(e["introduced"])
            elif "fixed" in e and introduced is not None:
                fixed = str(e["fixed"])
                if (introduced == "0" or cmp(version, introduced) >= 0) and cmp(version, fixed) < 0:
                    return fixed
                introduced = None
    return None


def cves(adv: Advisory) -> list[str]:
    found = [a for a in adv.aliases if a.startswith("CVE-")]
    m = re.search(r"CVE-\d{4}-\d{4,7}", adv.id)
    if m and m.group(0) not in found:
        found.insert(0, m.group(0))
    return found
