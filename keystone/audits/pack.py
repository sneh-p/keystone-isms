"""Audit pack: one ZIP with what an auditor needs for an audit.

Contents: the Statement of Applicability per enabled framework, the approved version of every policy, current
evidence for the audit's controls (all controls when the audit has none), evidence linked to its requests, the
request list, and a manifest with SHA-256 hashes.

SC-FILE-001 / SC-FILE-003: every entry name is built here from codes, ids and a slug; no user-supplied name or path
reaches the archive structure, so nothing can escape the folders on extraction. The total size is capped, and the
archive is written to a temporary file rather than held in memory.
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
import tempfile
import zipfile
from pathlib import Path

from sqlalchemy.orm import Session

from keystone.controls import service as ctl
from keystone.core.attachments import ALLOWED_EXTENSIONS, Attachment, read_attachment
from keystone.core.audit import log_event
from keystone.core.services import authorize, get_or_404
from keystone.frameworks import service as fw
from keystone.org.service import get_org
from keystone.policies import service as pol
from keystone.reporting import exports

from .models import Audit
from .service import requests_for

MAX_PACK_BYTES = 500 * 1024 * 1024


class PackTooLarge(ValueError):
    pass


def _slug(text: str, n: int = 60) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")[:n] or "item"


def _ext(att: Attachment) -> str:
    ext = Path(att.filename).suffix.lower()
    return ext if ext in ALLOWED_EXTENSIONS else ".bin"


def build(session: Session, actor, audit_id: int) -> tuple[tempfile.SpooledTemporaryFile, str, int]:
    """Returns (file positioned at 0, download name, number of files)."""
    authorize(session, actor, "read")
    a = get_or_404(session, Audit, audit_id)
    org = get_org(session)
    out = tempfile.SpooledTemporaryFile(max_size=32 * 1024 * 1024)
    manifest: list[tuple[str, str, str]] = []
    total = 0

    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        def add(name: str, data: bytes, source: str) -> None:
            nonlocal total
            total += len(data)
            if total > MAX_PACK_BYTES:
                raise PackTooLarge(f"The audit pack would exceed {MAX_PACK_BYTES // (1024 * 1024)} MB; narrow the audit's controls.")
            z.writestr(name, data)
            manifest.append((name, hashlib.sha256(data).hexdigest(), source))

        for f in fw.frameworks(session):
            rows = ctl.soa_rows(session, f.id)
            add(f"soa/SoA_{_slug(f.code, 40)}.xlsx", exports.soa_xlsx(org.name if org else "", f"{f.name} {f.version}", rows, "as of export"), f"Statement of Applicability, {f.name} {f.version}")

        for d in pol.documents(session):
            v = pol.current_version(session, d)
            if d.status != "approved" or v is None:
                continue
            base = f"policies/{_slug(d.code, 30)}_{_slug(d.title)}_v{_slug(v.version_label, 10)}"
            if v.attachment_id:
                att = session.get(Attachment, v.attachment_id)
                if att:
                    add(base + _ext(att), read_attachment(att), f"{d.code} {d.title} v{v.version_label}")
            if v.body:
                add(base + ".md", v.body.encode(), f"{d.code} {d.title} v{v.version_label} (text)")

        all_controls = fw.controls(session)
        codes = {c.id: c.code for c in all_controls}
        controls = list(a.controls) or all_controls
        seen: set[int] = set()
        reqs = requests_for(session, a.id)
        evidence = [e for c in controls for e in ctl.evidence_for(session, c.id) if ctl.evidence_state(e) in ("current", "expiring")]
        evidence += [e for r in reqs for e in r.evidence]
        for e in evidence:
            if e.id in seen:
                continue
            seen.add(e.id)
            code = _slug(codes.get(e.common_control_id, str(e.common_control_id)), 30)
            base = f"evidence/{code}/{e.id}_{_slug(e.title)}"
            if e.attachment_id:
                att = session.get(Attachment, e.attachment_id)
                if att:
                    add(base + _ext(att), read_attachment(att), f"Evidence {e.id}: {e.title}")
            elif e.url or e.description:
                add(base + ".txt", f"{e.title}\n{e.url or ''}\n\n{e.description or ''}\n".encode(), f"Evidence {e.id}: {e.title} (link/note)")

        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "title", "status", "due", "control", "evidence ids", "comments"])
        for r in reqs:
            w.writerow([r.id, exports.safe_cell(r.title), r.status, r.due_date or "", r.common_control_id or "", " ".join(str(e.id) for e in r.evidence), len(r.comments)])
        add("requests.csv", buf.getvalue().encode(), "Evidence request list")

        m = io.StringIO()
        mw = csv.writer(m)
        mw.writerow(["file", "sha256", "source"])
        for row in manifest:
            mw.writerow([row[0], row[1], exports.safe_cell(row[2])])
        z.writestr("manifest.csv", m.getvalue())

    log_event(session, actor, "export", "Audit", a.id, f"Audit pack downloaded ({len(manifest)} files, {total} bytes)")
    out.seek(0)
    return out, f"audit-pack_{_slug(a.title, 40)}.zip", len(manifest)
