"""One-page board report (Word): where the ISMS stands, how it moved, and what needs a decision."""

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
