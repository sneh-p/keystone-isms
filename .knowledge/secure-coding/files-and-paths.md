---
type: Secure Coding Standard
title: Files and Paths
description: Path traversal, uploads, spreadsheets and other zip-based formats, XML parsing and serving stored files.
tags: [security, backend, files, uploads]
rule_prefix: SC-FILE
applies_to: ["keystone/core/attachments.py", "keystone/**/*.py", "scripts/**/*.py"]
load_when: ["open(), pathlib or os.path with input", "UploadFile", "openpyxl, python-docx or zipfile", "XML parsing", "serving stored files", "imports of framework packs or collector output"]
status: stable
verified: { by: human:sneh, at: 2026-11-16T20:00:00Z }
generated: { by: claude/claude-opus-5-5, at: 2026-11-16T00:00:00Z }
stale_after: 2027-05-16T00:00:00Z
---

# Rules

### SC-FILE-001 — Contain every path
**MUST · critical** · Semgrep `sc-file-001-path-from-input` · CWE-22 · ASVS V5

Prefer server-generated names to user-supplied filenames: attachments are stored content-addressed by SHA-256
(`keystone/core/attachments.py`) and the original name is only metadata, cleaned by `safe_filename()`. When input
must name a file, resolve the path and confirm it stays under the base directory.

```python
from pathlib import Path

BASE = settings.attachments_dir.resolve()


def resolve_inside(user_path: str) -> Path:
    target = (BASE / user_path).resolve()
    if not target.is_relative_to(BASE):
        raise PermissionDenied("path_outside_base")
    return target
```

### SC-FILE-002 — Uploads are hostile
**MUST · critical** · CWE-434 · ASVS V5

- Enforce the size limit (`KEYSTONE_MAX_UPLOAD_MB`) before processing.
- Allowlist types by content (magic numbers in `ALLOWED_MAGIC`), not by extension or client `Content-Type`.
- Store uploads under generated names, outside the web root (`<data dir>/attachments/`).
- Serve them with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, and verify the SHA-256
  on read.
- Treat SVG and HTML as active content (they are not on the allowlist).
- Never execute, import or `exec` an uploaded file.
- Files from outside the company (vendor portal uploads) are scanned by ClamAV before storage, and refused when the
  scanner can't give a clean verdict (`keystone/core/antivirus.py`).
- The document viewer never serves files inline: it fetches the bytes and builds a Blob with a type it chooses (PDF,
  images, plain text); HTML and SVG are never rendered.

### SC-FILE-003 — Extract archives defensively
**MUST · high** · `keystone/core/safe_files.check_zip()` · CWE-22, CWE-409

`.xlsx` and `.docx` files are zip archives. Before opening an untrusted one with openpyxl or python-docx, call
`check_zip(data)`, which rejects archives with too many entries, a total uncompressed size over the cap, an
extreme compression ratio, or entries with absolute paths or `..` segments. Never call `ZipFile.extractall()` on
untrusted archives.

### SC-FILE-004 — No external entities in XML
**MUST · high** · ruff `S313`–`S320` · CWE-611

Parse untrusted XML only with `defusedxml`. `defusedxml` is a runtime dependency so that openpyxl, which detects
it, parses uploaded spreadsheets safely; `keystone/core/safe_files.py` asserts it is active at import time. Never
use `xml.etree`, `xml.dom.minidom`, `xml.sax` or `lxml` with entity resolution on untrusted input.
