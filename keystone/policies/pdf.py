"""Versioned policy PDFs (ReportLab).

Each PDF names the exact version, its approval e-signature and the SHA-256 fingerprint of its content, and draft
versions carry a DRAFT mark on every page. The body is Markdown rendered as headings, lists and paragraphs. ReportLab's
Paragraph understands a small markup language, so every piece of text is escaped first and only bold and italics are
added back: policy text can't inject markup, links or images into the PDF.
"""

from __future__ import annotations

import io
import re
from xml.sax.saxutils import escape

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.audit import log_event
from keystone.core.services import authorize, get_or_404

from .models import PolicyAcknowledgement, PolicyVersion
from .service import content_hash

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _inline(text: str) -> str:
    """Escape, then allow **bold** and *italic* only."""
    t = escape(text)
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"(?<![*\w])\*(?!\s)(.+?)(?<!\s)\*(?![*\w])", r"<i>\1</i>", t)
    return t


def _markdown(md: str, styles) -> list:
    from reportlab.platypus import ListFlowable, ListItem, Paragraph, Spacer

    out: list = []
    bullets: list = []
    para: list[str] = []

    def flush_para() -> None:
        if para:
            out.append(Paragraph(_inline(" ".join(para)), styles["Body"]))
            para.clear()

    def flush_list() -> None:
        if bullets:
            out.append(ListFlowable([ListItem(Paragraph(_inline(b), styles["Body"]), leftIndent=12) for b in bullets], bulletType="bullet", start="•", leftIndent=12))
            bullets.clear()

    for raw in md.splitlines():
        line = raw.rstrip()
        m = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            flush_para()
            flush_list()
            out.append(Paragraph(_inline(m.group(2)), styles[f"H{min(len(m.group(1)), 3)}"]))
        elif re.match(r"^\s*([-*]|\d+\.)\s+", line):
            flush_para()
            bullets.append(re.sub(r"^\s*([-*]|\d+\.)\s+", "", line))
        elif not line.strip():
            flush_para()
            flush_list()
            out.append(Spacer(1, 4))
        else:
            flush_list()
            para.append(line.strip())
    flush_para()
    flush_list()
    return out


def version_pdf(session: Session, actor, version_id: int, with_signatures: bool = False) -> tuple[bytes, str]:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    from keystone.core.attachments import Attachment
    from keystone.core.auth import User
    from keystone.org.service import get_org

    authorize(session, actor, "policy.write" if with_signatures else "read")
    v = get_or_404(session, PolicyVersion, version_id)
    doc = v.document
    approved = v.status in ("approved", "superseded")
    digest = v.content_sha256 if approved and v.content_sha256 else content_hash(session, v)
    users: dict[int | None, str] = {u.id: u.display_name for u in session.scalars(select(User))}
    org = get_org(session)

    base = getSampleStyleSheet()
    styles = {
        "Title": ParagraphStyle("t", parent=base["Title"], fontSize=18, spaceAfter=2, alignment=0),
        "Sub": ParagraphStyle("s", parent=base["Normal"], fontSize=10, textColor=colors.HexColor("#555555"), spaceAfter=10),
        "H1": ParagraphStyle("h1", parent=base["Heading1"], fontSize=14, spaceBefore=10, spaceAfter=4),
        "H2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=12, spaceBefore=8, spaceAfter=3),
        "H3": ParagraphStyle("h3", parent=base["Heading3"], fontSize=10.5, spaceBefore=6, spaceAfter=2),
        "Body": ParagraphStyle("b", parent=base["Normal"], fontSize=9.5, leading=13),
        "Small": ParagraphStyle("sm", parent=base["Normal"], fontSize=8, leading=10, textColor=colors.HexColor("#444444")),
    }
    grid = TableStyle([("FONTSIZE", (0, 0), (-1, -1), 8.5), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#bbbbbb")),
                       ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f2f2f2"))])
    approval = (f"{users.get(v.approved_by_id, '?')} on {v.approved_at:%Y-%m-%d %H:%M} UTC" + (f", signed “{v.approval_signed_name}”" if v.approval_signed_name else "")) if v.approved_at else "Not approved"
    att = session.get(Attachment, v.attachment_id) if v.attachment_id else None
    meta = [["Document", f"{doc.code} {doc.title}"], ["Version", f"{v.version_label} ({v.status})"], ["Owner", users.get(doc.owner_id, "—") if doc.owner_id else "—"],
            ["Approved", approval], ["Next review", doc.next_review_date.isoformat() if doc.next_review_date and approved else "—"],
            ["Fingerprint", Paragraph(f"SHA-256 {digest}" + ("" if approved else " (draft: changes with every edit)"), styles["Small"])]]
    if att:
        meta.append(["Attached file", f"{att.filename} (SHA-256 {att.sha256[:16]}…)"])
    story: list = [Paragraph(_inline(f"{doc.code} {doc.title}"), styles["Title"]),
                   Paragraph(_inline(f"{org.name if org else 'Keystone ISMS'} · version {v.version_label}"), styles["Sub"]),
                   Table([[k, Paragraph(_inline(str(val)), styles["Small"]) if isinstance(val, str) else val] for k, val in meta], colWidths=[32 * mm, 140 * mm], style=grid),
                   Spacer(1, 8)]
    if v.change_summary:
        story += [Paragraph("Changes in this version", styles["H3"]), Paragraph(_inline(v.change_summary), styles["Body"]), Spacer(1, 6)]
    story += _markdown(v.body or "", styles) if (v.body or "").strip() else [Paragraph(_inline(f"The policy text is in the attached file {att.filename}." if att else "No text."), styles["Body"])]

    history = [x for x in sorted(doc.versions, key=lambda x: x.id) if x.status in ("approved", "superseded")]
    if history:
        story += [Spacer(1, 10), Paragraph("Version history", styles["H2"]),
                  Table([["Version", "Approved", "By", "Changes"]] + [[h.version_label, f"{h.approved_at:%Y-%m-%d}" if h.approved_at else "", users.get(h.approved_by_id, ""),
                                                                      Paragraph(_inline((h.change_summary or "")[:300]), styles["Small"])] for h in history],
                        colWidths=[18 * mm, 24 * mm, 40 * mm, 90 * mm], style=TableStyle([("FONTSIZE", (0, 0), (-1, -1), 8), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#bbbbbb")),
                                                                                         ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f2f2f2")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))]
    if with_signatures:
        acks = list(session.scalars(select(PolicyAcknowledgement).where(PolicyAcknowledgement.version_id == v.id).order_by(PolicyAcknowledgement.acknowledged_at)))
        story += [Spacer(1, 10), Paragraph(f"Acknowledgements ({len(acks)})", styles["H2"])]
        if acks:
            story.append(Table([["Name", "Signed as", "When (UTC)", "Fingerprint"]] + [[users.get(a.user_id, "?"), a.signed_name or "(click, no typed name)", f"{a.acknowledged_at:%Y-%m-%d %H:%M}",
                                                                                   "matches" if a.content_sha256 == digest else ("not recorded" if not a.content_sha256 else "DIFFERENT")] for a in acks],
                               colWidths=[45 * mm, 45 * mm, 32 * mm, 50 * mm], repeatRows=1,
                               style=TableStyle([("FONTSIZE", (0, 0), (-1, -1), 8), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#bbbbbb")), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f2f2f2"))])))

    footer = f"{doc.code} v{v.version_label} · SHA-256 {digest[:16]}…"

    def page(canvas, d) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#666666"))
        canvas.drawString(18 * mm, 10 * mm, footer)
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {d.page}")
        if not approved:
            canvas.setFont("Helvetica-Bold", 60)
            canvas.setFillColor(colors.Color(0.85, 0.2, 0.2, alpha=0.12))
            canvas.translate(A4[0] / 2, A4[1] / 2)
            canvas.rotate(45)
            canvas.drawCentredString(0, 0, "DRAFT")
        canvas.restoreState()

    buf = io.BytesIO()
    pdf = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
                            title=f"{doc.code} {doc.title} v{v.version_label}", author=org.name if org else "Keystone ISMS", subject=f"SHA-256 {digest}")
    pdf.build(story, onFirstPage=page, onLaterPages=page)
    log_event(session, actor, "export", "PolicyVersion", v.id, f"PDF of {doc.code} v{v.version_label}" + (" with acknowledgements" if with_signatures else ""))
    return buf.getvalue(), f"{_SAFE_NAME.sub('-', doc.code)}-v{_SAFE_NAME.sub('-', v.version_label)}.pdf"
