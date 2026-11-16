"""Guards for parsing untrusted zip-based office files (SC-FILE-003, SC-FILE-004).

.xlsx and .docx files are zip archives of XML. Before an uploaded one is opened with openpyxl or
python-docx, `check_zip` rejects zip bombs and path tricks, and openpyxl must be parsing XML through
defusedxml so external entities and entity expansion are refused.
"""

from __future__ import annotations

import io
import zipfile

import openpyxl.xml

MAX_ENTRIES = 2_000
MAX_TOTAL_UNCOMPRESSED = 200 * 1024 * 1024  # 200 MB
MAX_RATIO = 200  # uncompressed / compressed, per entry


class UnsafeFile(ValueError):
    """The upload is not safe to parse. The message is shown to the user."""


def require_defused_xml() -> None:
    """Fail closed if openpyxl would parse XML without defusedxml (SC-FILE-004)."""
    if not openpyxl.xml.DEFUSEDXML:
        raise RuntimeError("defusedxml is required to parse uploaded spreadsheets safely. Install the 'defusedxml' package.")


def check_zip(data: bytes) -> None:
    """Reject archives that are malformed, too large when expanded, or contain unsafe entry names."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise UnsafeFile("The file is not a valid Office document.") from e
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise UnsafeFile("The file contains too many parts to be processed safely.")
        total = 0
        for info in infos:
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or ".." in name.split("/") or (len(name) > 1 and name[1] == ":"):
                raise UnsafeFile("The file contains an unsafe entry name.")
            total += info.file_size
            if total > MAX_TOTAL_UNCOMPRESSED:
                raise UnsafeFile("The file expands to more data than can be processed safely.")
            if info.compress_size and info.file_size / info.compress_size > MAX_RATIO and info.file_size > 10 * 1024 * 1024:
                raise UnsafeFile("The file is compressed suspiciously well and was not processed.")


def open_untrusted_workbook(data: bytes, **kwargs):
    """openpyxl.load_workbook for uploaded bytes, after the zip and XML guards."""
    from openpyxl import load_workbook

    require_defused_xml()
    check_zip(data)
    return load_workbook(io.BytesIO(data), **kwargs)
