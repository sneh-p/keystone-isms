"""SC-FILE-003 / SC-FILE-004: untrusted office files are checked before parsing."""

import io
import zipfile

import pytest

from keystone.answers import service as sq
from keystone.core import safe_files
from keystone.core.safe_files import UnsafeFile, check_zip


def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_rejects_zip_slip_and_absolute_names():
    for name in ("../evil.xml", "xl/../../evil.xml", "/etc/passwd", "C:/x.xml", "..\\evil.xml"):
        with pytest.raises(UnsafeFile, match="unsafe entry"):
            check_zip(_zip({name: b"x"}))


def test_rejects_bombs_and_too_many_entries(monkeypatch):
    with pytest.raises(UnsafeFile, match="compressed suspiciously"):
        check_zip(_zip({"a.xml": b"\0" * (11 * 1024 * 1024)}))
    monkeypatch.setattr(safe_files, "MAX_TOTAL_UNCOMPRESSED", 1000)
    with pytest.raises(UnsafeFile, match="expands"):
        check_zip(_zip({"a.xml": b"a" * 600, "b.xml": b"b" * 600}))
    monkeypatch.setattr(safe_files, "MAX_ENTRIES", 3)
    with pytest.raises(UnsafeFile, match="too many"):
        check_zip(_zip({f"{i}.xml": b"x" for i in range(4)}))
    with pytest.raises(UnsafeFile, match="not a valid"):
        check_zip(b"PK\x03\x04 not really a zip")


def test_xml_parsing_is_defused():
    safe_files.require_defused_xml()  # fails closed if defusedxml is missing


def test_xxe_spreadsheet_is_not_expanded(users, session):
    """A workbook whose shared strings use an external entity must not leak file contents."""
    from openpyxl import Workbook

    wb = Workbook()
    wb.active.append(["Question"])
    wb.active.append(["Do you encrypt laptops?"])
    buf = io.BytesIO()
    wb.save(buf)
    src = zipfile.ZipFile(io.BytesIO(buf.getvalue()))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for info in src.infolist():
            data = src.read(info.filename)
            if info.filename == "xl/worksheets/sheet1.xml":
                data = data.replace(b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>", b"")
                data = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>' + data
            z.writestr(info, data)
    with pytest.raises(ValueError):
        sq.create(session, users["admin"], title="XXE", filename="x.xlsx", data=out.getvalue())


def test_bomb_upload_is_refused_with_reason(users, session):
    with pytest.raises(UnsafeFile, match="compressed suspiciously"):
        sq.create(session, users["admin"], title="Bomb", filename="b.xlsx", data=_zip({"[Content_Types].xml": b"\0" * (11 * 1024 * 1024)}))
