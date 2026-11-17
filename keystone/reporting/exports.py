"""XLSX / DOCX exports. All cell text is sanitised against spreadsheet formula injection."""

from __future__ import annotations

import io
from datetime import date, datetime
from typing import Any, Iterable, Sequence

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value: Any) -> Any:
    """Neutralise values a spreadsheet would treat as formulas (CWE-1236)."""
    if isinstance(value, str) and value.startswith(FORMULA_PREFIXES):
        return "'" + value
    if isinstance(value, (list, tuple, set)):
        return safe_cell(", ".join(str(v) for v in value))
    if isinstance(value, dict):
        return safe_cell(str(value))
    if value is None:
        return ""
    return value


def xlsx(sheets: dict[str, tuple[Sequence[str], Iterable[Sequence[Any]]]], title: str | None = None) -> bytes:
    wb = Workbook()
    wb.remove(wb.active)
    head_fill = PatternFill("solid", fgColor="E1E0D9")
    for name, (headers, rows) in sheets.items():
        ws = wb.create_sheet(name[:31])
        start = 1
        if title:
            ws.cell(row=1, column=1, value=safe_cell(title)).font = Font(bold=True, size=13)
            start = 3
        for col, h in enumerate(headers, 1):
            c = ws.cell(row=start, column=col, value=safe_cell(h))
            c.font, c.fill = Font(bold=True), head_fill
        widths = [len(str(h)) for h in headers]
        for r_i, row in enumerate(rows, start + 1):
            for col, v in enumerate(row, 1):
                cell = ws.cell(row=r_i, column=col, value=safe_cell(v))
                cell.alignment = Alignment(wrap_text=True, vertical="top")
                if isinstance(v, (date, datetime)):
                    cell.number_format = "yyyy-mm-dd"
                widths[col - 1] = max(widths[col - 1], min(60, len(str(v or ""))))
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[get_column_letter(i)].width = max(8, min(60, w + 2))
        ws.freeze_panes = ws.cell(row=start + 1, column=1)
        ws.auto_filter.ref = f"A{start}:{get_column_letter(len(headers))}{ws.max_row}"
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


SOA_HEADERS = ["Ref", "Requirement", "Applicable", "Justification", "Implementation status", "Keystone controls", "Related risks", "Current evidence", "Last test"]


def soa_table(rows, include_licensed_text: bool = False) -> tuple[list[str], list[list]]:
    headers = list(SOA_HEADERS)
    if include_licensed_text:
        headers.insert(2, "Official text (licensed)")
    out = []
    for r in rows:
        test = f"{r.last_test.replace('_', ' ')} ({r.last_tested_on.isoformat()})" if r.last_test and r.last_tested_on else ""
        line = [r.requirement.ref, r.requirement.title, "Yes" if r.applicable else "No", r.justification, r.implementation.replace("_", " "), r.controls, r.risks, r.evidence, test]
        if include_licensed_text:
            line.insert(2, r.requirement.licensed_text or "")
        out.append(line)
    return headers, out


def soa_xlsx(org_name: str, framework_label: str, rows, version_note: str, include_licensed_text: bool = False) -> bytes:
    headers, data = soa_table(rows, include_licensed_text)
    return xlsx({"Statement of Applicability": (headers, data)}, title=f"{org_name}: Statement of Applicability, {framework_label} ({version_note})")


def soa_docx(org_name: str, framework_label: str, rows, version_note: str, include_licensed_text: bool = False) -> bytes:
    from docx import Document
    from docx.shared import Pt

    doc = Document()
    doc.add_heading(f"Statement of Applicability: {framework_label}", level=0)
    doc.add_paragraph(f"{org_name} · {version_note} · generated {date.today().isoformat()} by Keystone ISMS")
    applicable = sum(1 for r in rows if r.applicable)
    doc.add_paragraph(f"{len(rows)} requirements: {applicable} applicable, {len(rows) - applicable} excluded.")
    headers, data = soa_table(rows, include_licensed_text)
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Light Grid Accent 1"
    for i, h in enumerate(headers):
        table.rows[0].cells[i].text = h
    for line in data:
        cells = table.add_row().cells
        for i, v in enumerate(line):
            cells[i].text = str(safe_cell(v))
    for row in table.rows:
        for cell in row.cells:
            for p in cell.paragraphs:
                for run in p.runs:
                    run.font.size = Pt(8)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()
