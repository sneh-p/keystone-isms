"""Phase 4: control implementation, evidence, SoA, exports."""

import io
from datetime import date, timedelta

import pytest
from openpyxl import load_workbook
from sqlalchemy import select

from keystone.controls import service as ctl
from keystone.core.rbac import PermissionDenied
from keystone.frameworks.models import Requirement
from keystone.frameworks.service import control_by_code, framework_by_code
from keystone.reporting import exports
from keystone.risk import service as risk


def _c(session, code):
    return control_by_code(session, code)


def test_update_control_rules(content, session, users):
    c = _c(session, "KC-TEC-05")
    ctl.update_control(session, users["control_owner"], c.id, status="partial", implementation_notes="MFA for admins")
    assert c.status == "partial" and c.next_review_date == date.today() + timedelta(days=365)
    with pytest.raises(ValueError, match="not applicable"):
        ctl.update_control(session, users["control_owner"], c.id, status="not_applicable")
    with pytest.raises(ValueError, match="not editable"):
        ctl.update_control(session, users["control_owner"], c.id, code="X")
    with pytest.raises(PermissionDenied):
        ctl.update_control(session, users["risk_owner"], c.id, status="implemented")
    with pytest.raises(ValueError, match="interval"):
        ctl.update_control(session, users["control_owner"], c.id, review_interval_days=5)


def test_evidence_kinds_and_states(content, session, users):
    c = _c(session, "KC-TEC-13")
    u = users["control_owner"]
    f = ctl.add_evidence(session, u, c.id, title="Backup report", kind="file", filename="report.pdf", data=b"%PDF-1.4 x", valid_until=date.today() + timedelta(days=10))
    assert f.attachment_id and ctl.evidence_state(f) == "expiring"
    link = ctl.add_evidence(session, u, c.id, title="Runbook", kind="link", url="https://wiki.alpineskihouse.example/backup")
    assert ctl.evidence_state(link) == "current"
    with pytest.raises(ValueError, match="http"):
        ctl.add_evidence(session, u, c.id, title="x", kind="link", url="javascript:alert(1)")
    with pytest.raises(ValueError, match="description"):
        ctl.add_evidence(session, u, c.id, title="x", kind="note")
    with pytest.raises(ValueError, match="before"):
        ctl.add_evidence(session, u, c.id, title="x", kind="note", description="d", collected_on=date.today(), valid_until=date.today() - timedelta(days=1))
    assert ctl.evidence_state(f, on=date.today() + timedelta(days=11)) == "expired"
    ctl.review_evidence(session, u, link.id, superseded=True)
    assert ctl.evidence_state(link) == "superseded"


def test_control_attention(content, session, users):
    c = _c(session, "KC-ORG-01")
    ctl.update_control(session, users["admin"], c.id, status="implemented")
    att = ctl.control_attention(session)
    assert c in att["implemented_without_evidence"]
    ctl.add_evidence(session, users["admin"], c.id, title="Policy approval minutes", kind="note", description="Board approved v3")
    assert c not in ctl.control_attention(session)["implemented_without_evidence"]
    c.next_review_date = date.today() - timedelta(days=1)
    assert c in ctl.control_attention(session)["review_overdue"]
    ctl.review_control(session, users["admin"], c.id)
    assert c not in ctl.control_attention(session)["review_overdue"]


# ---- SoA -------------------------------------------------------------------------------------

def _rows(session, code="ISO27001_2022"):
    return {r.requirement.ref: r for r in ctl.soa_rows(session, framework_by_code(session, code).id)}


def test_soa_defaults_and_derivation(content, session, users):
    rows = _rows(session)
    assert len(rows) == 123 and all(r.applicable for r in rows.values())
    assert rows["A.8.13"].justification_source == "baseline"
    # Link a risk -> justification cites the risk
    r = risk.save_risk(session, users["admin"], title="Data loss", inherent_likelihood=3, inherent_impact=4, control_ids=[_c(session, "KC-TEC-13").id])
    rows = _rows(session)
    assert rows["A.8.13"].risks == [r.ref] and "RSK-0001" in rows["A.8.13"].justification
    # Control marked N/A -> requirement excluded with the control's justification
    ctl.update_control(session, users["admin"], _c(session, "KC-PHY-12").id, status="not_applicable", na_justification="No cabling we control.")
    row = _rows(session)["A.7.12"]
    assert not row.applicable and row.justification_source == "controls_na" and "No cabling" in row.justification


def test_soa_decision_overrides_and_requires_justification(content, session, users):
    req = session.scalar(select(Requirement).where(Requirement.ref == "A.8.30"))
    with pytest.raises(ValueError, match="justification"):
        ctl.set_soa_entry(session, users["admin"], req.id, False, "")
    with pytest.raises(PermissionDenied):
        ctl.set_soa_entry(session, users["control_owner"], req.id, False, "x")
    ctl.set_soa_entry(session, users["admin"], req.id, False, "We do no outsourced development.")
    row = _rows(session)["A.8.30"]
    assert not row.applicable and row.implementation == "not_applicable" and row.justification_source == "decision"
    ctl.clear_soa_entry(session, users["admin"], req.id)
    assert _rows(session)["A.8.30"].applicable


def test_soa_approval_versions_and_changes(content, session, users):
    fw = framework_by_code(session, "ISO27001_2022")
    a1 = ctl.approve_soa(session, users["admin"], fw.id, "Initial")
    assert a1.version == 1 and len(a1.snapshot) == 123
    assert ctl.soa_changes_since_approval(session, fw.id) == []
    ctl.update_control(session, users["admin"], _c(session, "KC-TEC-24").id, status="implemented")
    assert ctl.soa_changes_since_approval(session, fw.id) == ["A.8.24"]
    assert ctl.approve_soa(session, users["admin"], fw.id).version == 2


# ---- exports ---------------------------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [("=HYPERLINK(\"x\")", "'=HYPERLINK(\"x\")"), ("+1", "'+1"), ("-cmd", "'-cmd"), ("@SUM", "'@SUM"), ("ok", "ok"), (None, ""), (["a", "b"], "a, b"), (5, 5)])
def test_safe_cell(value, expected):
    assert exports.safe_cell(value) == expected


def test_soa_xlsx_and_docx(content, session, users):
    from docx import Document

    fw = framework_by_code(session, "SOC2_TSC_2017")
    rows = ctl.soa_rows(session, fw.id)
    rows[0].justification = "=cmd|' /C calc'!A0"
    data = exports.soa_xlsx("Alpine Ski House", "SOC 2", rows, "draft")
    ws = load_workbook(io.BytesIO(data)).active
    assert ws["A3"].value == "Ref" and ws.max_row == 3 + len(rows)
    assert ws["D4"].value.startswith("'=")
    doc = Document(io.BytesIO(exports.soa_docx("Alpine Ski House", "SOC 2", rows, "draft")))
    assert len(doc.tables[0].rows) == len(rows) + 1


def test_licensed_text_only_exported_when_asked(content, session, users):
    from keystone.frameworks.loader import import_licensed_text

    import_licensed_text(session, users["admin"], "ISO27001_2022", [{"ref": "A.5.1", "text": "OFFICIAL"}])
    rows = ctl.soa_rows(session, framework_by_code(session, "ISO27001_2022").id)
    assert b"OFFICIAL" not in _xlsx_text(exports.soa_xlsx("O", "ISO", rows, "d"))
    assert b"OFFICIAL" in _xlsx_text(exports.soa_xlsx("O", "ISO", rows, "d", include_licensed_text=True))


def _xlsx_text(data: bytes) -> bytes:
    import zipfile
    z = zipfile.ZipFile(io.BytesIO(data))
    return b"".join(z.read(n) for n in z.namelist() if n.endswith(".xml"))
