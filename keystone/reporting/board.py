"""One-page board report (Word or PDF): where the ISMS stands, how it moved, and what needs a decision."""

from __future__ import annotations

import io
from datetime import date

from sqlalchemy.orm import Session

from keystone.core.audit import log_event
from keystone.core.services import authorize

from . import dashboard
from .exports import safe_cell

LEVEL_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def summary(session: Session, on: date | None = None) -> dict:
    """The figures the report shows (also used by tests)."""
    from keystone.risk import service as risk
    from keystone.tasks import service as tsk

    on = on or date.today()
    ov = dashboard.overview(session, on)
    current = dashboard.metrics(session, on, ov)
    tr = dashboard.trend(session, current, on)
    first = {k: next((x for x in v if x is not None), None) for k, v in tr["series"].items()}
    open_risks = [r for r in risk.list_risks(session) if r.status != "closed"]
    top = sorted(open_risks, key=lambda r: (LEVEL_RANK.get(risk.current_level(r) or "Low", 4), r.ref))[:5]
    open_tasks = tsk.list_tasks(session, include_closed=False)
    return {
        "on": on, "weeks": len(tr["days"]), "coverage": [(n, c) for n, c in ov["coverage"]], "current": current, "first": first,
        "risk_levels": ov["risk_levels"], "top_risks": [(r.ref, r.title, risk.current_level(r) or "Not assessed", r.treatment_option or "undecided") for r in top],
        "open_incidents": ov["open_incidents"], "open_ncs": ov["open_ncs"], "audit": ov["audit_coverage"], "audit_pct": ov["audit_coverage_pct"],
        "tasks_open": len(open_tasks), "tasks_overdue": sum(1 for t in open_tasks if tsk.overdue(t, on)),
        "attention": [(a["count"], a["text"]) for a in ov["attention"]],
    }


def _change(now, then, unit="") -> str:
    if now is None or then is None:
        return ""
    d = round(now - then, 1)
    return "no change" if d == 0 else f"{'+' if d > 0 else '−'}{abs(d):g}{unit}"


def report_docx(session: Session, actor) -> bytes:
    authorize(session, actor, "read")
    from docx import Document
    from docx.shared import Pt

    from keystone.org.service import get_org

    s = summary(session)
    org = get_org(session)
    doc = Document()
    st = doc.styles["Normal"]
    st.font.size = Pt(10)
    doc.add_heading(f"Information security: board summary", level=0)
    doc.add_paragraph(f"{org.name if org else ''} · {s['on']:%d %B %Y} · changes compare with {s['weeks']} weeks ago · Keystone ISMS")

    doc.add_heading("Headlines", level=1)
    c, f = s["current"], s["first"]
    rows = [
        ("Average framework readiness", f"{c['readiness_pct']}%", _change(c["readiness_pct"], f.get("readiness_pct"), " pts")),
        ("Controls implemented", str(c["controls_implemented"]), _change(c["controls_implemented"], f.get("controls_implemented"))),
        ("Controls audited in 3 years", f"{s['audit']['audited']} of {s['audit']['applicable']} ({s['audit_pct']}%)", _change(c["controls_audited"], f.get("controls_audited"))),
        ("Open risks (critical or high)", f"{c['open_risks']} ({c['high_risks']})", _change(c["high_risks"], f.get("high_risks"))),
        ("Open incidents / nonconformities", f"{s['open_incidents']} / {s['open_ncs']}", ""),
        ("Overdue tasks", f"{s['tasks_overdue']} of {s['tasks_open']} open", _change(c["tasks_overdue"], f.get("tasks_overdue"))),
    ]
    t = doc.add_table(rows=1, cols=3)
    t.style = "Light Grid Accent 1"
    for i, h in enumerate(("Measure", "Now", "Change")):
        t.rows[0].cells[i].text = h
    for row in rows:
        cells = t.add_row().cells
        for i, v in enumerate(row):
            cells[i].text = str(safe_cell(v))

    doc.add_heading("Framework readiness", level=1)
    for name, cov in s["coverage"]:
        doc.add_paragraph(f"{name}: {cov['implemented_pct']}% of {cov['applicable']} requirements implemented", style="List Bullet")

    doc.add_heading("Top risks", level=1)
    if s["top_risks"]:
        t = doc.add_table(rows=1, cols=4)
        t.style = "Light Grid Accent 1"
        for i, h in enumerate(("Risk", "Title", "Level", "Treatment")):
            t.rows[0].cells[i].text = h
        for row in s["top_risks"]:
            cells = t.add_row().cells
            for i, v in enumerate(row):
                cells[i].text = str(safe_cell(v))
    else:
        doc.add_paragraph("No open risks.")

    doc.add_heading("Needs a decision or attention", level=1)
    items = s["attention"][:8]
    if not items:
        doc.add_paragraph("Nothing overdue.")
    for n, text in items:
        doc.add_paragraph(f"{n} {safe_cell(text)}", style="List Bullet")

    buf = io.BytesIO()
    doc.save(buf)
    log_event(session, actor, "export", "Report", None, "Board summary exported")
    return buf.getvalue()


def _rows(s: dict) -> list[tuple[str, str, str]]:
    c, f = s["current"], s["first"]
    return [
        ("Average framework readiness", f"{c['readiness_pct']}%", _change(c["readiness_pct"], f.get("readiness_pct"), " pts")),
        ("Controls implemented", str(c["controls_implemented"]), _change(c["controls_implemented"], f.get("controls_implemented"))),
        ("Controls audited in 3 years", f"{s['audit']['audited']} of {s['audit']['applicable']} ({s['audit_pct']}%)", _change(c["controls_audited"], f.get("controls_audited"))),
        ("Open risks (critical or high)", f"{c['open_risks']} ({c['high_risks']})", _change(c["high_risks"], f.get("high_risks"))),
        ("Open incidents / nonconformities", f"{s['open_incidents']} / {s['open_ncs']}", ""),
        ("Overdue tasks", f"{s['tasks_overdue']} of {s['tasks_open']} open", _change(c["tasks_overdue"], f.get("tasks_overdue"))),
    ]


def report_pdf(session: Session, actor) -> bytes:
    """The same board summary as a PDF (ReportLab). All text is escaped before ReportLab's markup is applied."""
    from xml.sax.saxutils import escape

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import ListFlowable, ListItem, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    from keystone.org.service import get_org

    authorize(session, actor, "read")
    s = summary(session)
    org = get_org(session)
    base = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=base["Heading2"], fontSize=12, spaceBefore=10, spaceAfter=4)
    body = ParagraphStyle("b", parent=base["Normal"], fontSize=9.5, leading=12.5)
    grid = TableStyle([("FONTSIZE", (0, 0), (-1, -1), 9), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#bbbbbb")),
                       ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f2f2f2")), ("VALIGN", (0, 0), (-1, -1), "TOP")])

    def p(text: str) -> Paragraph:
        return Paragraph(escape(str(text)), body)

    story: list = [Paragraph("Information security: board summary", ParagraphStyle("t", parent=base["Title"], fontSize=17, alignment=0)),
                   p(f"{org.name if org else ''} · {s['on']:%d %B %Y} · changes compare with {s['weeks']} weeks ago · Keystone ISMS"), Spacer(1, 6),
                   Paragraph("Headlines", h1), Table([["Measure", "Now", "Change"]] + [list(r) for r in _rows(s)], colWidths=[85 * mm, 50 * mm, 35 * mm], style=grid),
                   Paragraph("Framework readiness", h1)]
    story.append(ListFlowable([ListItem(p(f"{n}: {cov['implemented_pct']}% of {cov['applicable']} requirements implemented")) for n, cov in s["coverage"]] or [ListItem(p("No frameworks enabled."))], bulletType="bullet"))
    story.append(Paragraph("Top risks", h1))
    if s["top_risks"]:
        story.append(Table([["Risk", "Title", "Level", "Treatment"]] + [[r[0], p(r[1]), r[2], r[3]] for r in s["top_risks"]], colWidths=[22 * mm, 88 * mm, 28 * mm, 32 * mm], style=grid))
    else:
        story.append(p("No open risks."))
    story.append(Paragraph("Needs a decision or attention", h1))
    items = s["attention"][:8]
    story.append(ListFlowable([ListItem(p(f"{n} {text}")) for n, text in items], bulletType="bullet") if items else p("Nothing overdue."))
    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                      title="Board summary", author=org.name if org else "Keystone ISMS").build(story)
    log_event(session, actor, "export", "Report", None, "Board summary exported (PDF)")
    return buf.getvalue()
