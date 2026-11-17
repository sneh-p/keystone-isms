"""Risk depth: the risk treatment plan export (6.1.3 e) and records linked to a risk."""

from io import BytesIO

from openpyxl import load_workbook

from keystone.core.db import utcnow
from keystone.incidents import service as incidents
from keystone.risk import service as risk

from .conftest import api_login


def test_treatment_plan_and_links(api, ready_users, db):
    with db.session_scope() as s:
        from keystone.core.auth import User

        admin = s.get(User, ready_users["admin"].id)
        r = risk.save_risk(s, admin, title="Laptop theft", category="technology", owner_id=admin.id, inherent_likelihood=3, inherent_impact=4, treatment_option="mitigate")
        risk.save_action(s, admin, r.id, title="Enable disk encryption", owner_id=admin.id)
        risk.save_risk(s, admin, title="Untreated one", category="technology", owner_id=admin.id)
        incidents.report_incident(s, admin, title="Laptop stolen", detected_at=utcnow(), risk_id=r.id)
        rid = r.id
    api_login(api, ready_users["viewer"].username)
    resp = api.get("/api/risks/treatment-plan.xlsx")
    assert resp.status_code == 200
    rows = list(load_workbook(BytesIO(resp.content)).active.iter_rows(values_only=True))
    header = next(i for i, x in enumerate(rows) if x and x[0] == "Risk")
    body = rows[header + 1:]
    assert any(x[1] == "Laptop theft" and x[4] == "mitigate" and x[7] == "Enable disk encryption" for x in body)
    assert any(x[1] == "Untreated one" and not x[7] for x in body)  # risks without actions still appear
    detail = api.get(f"/api/risks/{rid}").json()
    assert [i["title"] for i in detail["incidents"]] == ["Laptop stolen"] and detail["vendors"] == []
