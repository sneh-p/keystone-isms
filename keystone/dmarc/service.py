"""DMARC aggregate reports (RFC 7489): upload the XML your mail provider sends (plain, .gz or .zip), and see which
sources send mail as your domains and whether it passes authentication.

The file is untrusted: at most 10 MB uploaded and 50 MB once decompressed, a zip may hold at most 5 entries of which
only .xml ones are read, and XML is parsed with defusedxml with DTDs refused (SC-FILE-004). The file itself isn't
kept; only the report's figures are."""

from __future__ import annotations

import gzip
import io
import ipaddress
import zipfile
from datetime import UTC, datetime, timedelta

from defusedxml import ElementTree as SafeET
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from keystone.core.services import authorize

from .models import DmarcRecord, DmarcReport

MAX_UPLOAD = 10 * 1024 * 1024
MAX_XML = 50 * 1024 * 1024
MAX_ZIP_ENTRIES = 5
MAX_RECORDS = 20000


def _bounded_read(stream, limit: int) -> bytes:
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("The report is too large once decompressed.")
    return data


def xml_documents(filename: str, data: bytes) -> list[bytes]:
    """The XML documents in an upload: plain XML, gzip, or a zip of XML files."""
    if len(data) > MAX_UPLOAD:
        raise ValueError("Upload reports of at most 10 MB.")
    name = filename.lower()
    if name.endswith(".gz") or data[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
            return [_bounded_read(g, MAX_XML)]
    if name.endswith(".zip") or data[:4] == b"PK\x03\x04":
        out, total = [], 0
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            entries = z.infolist()
            if len(entries) > MAX_ZIP_ENTRIES:
                raise ValueError(f"A zip may hold at most {MAX_ZIP_ENTRIES} files.")
            for e in entries:
                if e.is_dir() or not e.filename.lower().endswith(".xml"):
                    continue
                with z.open(e) as f:
                    doc = _bounded_read(f, MAX_XML - total)
                total += len(doc)
                out.append(doc)
        if not out:
            raise ValueError("The zip holds no XML report.")
        return out
    if name.endswith(".xml") or data.lstrip()[:5] == b"<?xml" or data.lstrip()[:1] == b"<":
        return [data]
    raise ValueError("Upload a DMARC aggregate report: .xml, .xml.gz or .zip.")


def _text(el, path: str) -> str | None:
    x = el.find(path)
    return x.text.strip() if x is not None and x.text else None


def parse(doc: bytes) -> dict:
    try:
        root = SafeET.fromstring(doc, forbid_dtd=True)
    except (SafeET.ParseError, ValueError) as e:
        raise ValueError("This isn't a readable DMARC report (XML).") from e
    if root.tag != "feedback":
        raise ValueError("This isn't a DMARC aggregate report.")
    org, rid = _text(root, "report_metadata/org_name"), _text(root, "report_metadata/report_id")
    begin, end, domain = _text(root, "report_metadata/date_range/begin"), _text(root, "report_metadata/date_range/end"), _text(root, "policy_published/domain")
    if not (org and rid and begin and end and domain):
        raise ValueError("The report is missing its sender, id, dates or domain.")
    records = []
    for rec in root.findall("record")[:MAX_RECORDS]:
        ip = _text(rec, "row/source_ip") or ""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        try:
            count = max(0, min(int(_text(rec, "row/count") or 0), 10**9))
        except ValueError:
            continue
        records.append({"source_ip": ip, "count": count, "disposition": (_text(rec, "row/policy_evaluated/disposition") or "")[:20] or None,
                        "dkim": (_text(rec, "row/policy_evaluated/dkim") or "")[:20] or None, "spf": (_text(rec, "row/policy_evaluated/spf") or "")[:20] or None,
                        "header_from": (_text(rec, "identifiers/header_from") or "")[:253] or None})
    try:
        starts = datetime.fromtimestamp(int(begin), UTC).replace(tzinfo=None)
        ends = datetime.fromtimestamp(int(end), UTC).replace(tzinfo=None)
    except (ValueError, OverflowError, OSError) as err:
        raise ValueError("The report's dates aren't readable.") from err
    return {"org_name": org[:200], "report_id": rid[:200], "domain": domain.lower()[:253], "policy": (_text(root, "policy_published/p") or "")[:20] or None,
            "begin": starts, "end": ends, "records": records}


def upload(session: Session, actor, filename: str, data: bytes) -> dict:
    authorize(session, actor, "integration.manage")
    added, skipped = 0, 0
    for doc in xml_documents(filename, data):
        r = parse(doc)
        if session.scalar(select(DmarcReport.id).where(DmarcReport.org_name == r["org_name"], DmarcReport.report_id == r["report_id"])):
            skipped += 1
            continue
        rep = DmarcReport(org_name=r["org_name"], report_id=r["report_id"], domain=r["domain"], policy=r["policy"], begin=r["begin"], end=r["end"],
                          messages=sum(x["count"] for x in r["records"]))
        session.add(rep)
        session.flush()
        for x in r["records"]:
            session.add(DmarcRecord(report_id=rep.id, **x))
        added += 1
    session.flush()
    return {"added": added, "already_had": skipped}


def summary(session: Session, actor, days: int = 90) -> dict:
    """Per sending source: messages, and how many passed DMARC (aligned SPF or DKIM)."""
    authorize(session, actor, "read")
    since = datetime.now() - timedelta(days=days)
    reports = list(session.scalars(select(DmarcReport).where(DmarcReport.end >= since).order_by(DmarcReport.end.desc())))
    ids = [r.id for r in reports]
    sources: dict[tuple[str, str], dict] = {}
    if ids:
        for rec in session.scalars(select(DmarcRecord).where(DmarcRecord.report_id.in_(ids))):
            k = (rec.source_ip, rec.header_from or "")
            s = sources.setdefault(k, {"source_ip": rec.source_ip, "header_from": rec.header_from, "messages": 0, "passed": 0, "quarantined_or_rejected": 0})
            s["messages"] += rec.count
            s["passed"] += rec.count if "pass" in (rec.dkim, rec.spf) else 0
            s["quarantined_or_rejected"] += rec.count if rec.disposition in ("quarantine", "reject") else 0
    rows = sorted(sources.values(), key=lambda s: (s["passed"] >= s["messages"], -s["messages"]))
    total = sum(s["messages"] for s in rows)
    return {"reports": [{"id": r.id, "org_name": r.org_name, "domain": r.domain, "policy": r.policy, "begin": r.begin, "end": r.end, "messages": r.messages} for r in reports],
            "sources": rows, "messages": total, "passed": sum(s["passed"] for s in rows),
            "domains": sorted({r.domain for r in reports}), "count": session.scalar(select(func.count(DmarcReport.id))) or 0}
