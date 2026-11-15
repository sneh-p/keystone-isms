"""Fictional demo organisation used by scripts/seed_demo.py and the UI tests.

Everything is invented (".example" domains, made-up people). Never put real data here.
"""

from __future__ import annotations

from datetime import date, timedelta

from sqlalchemy.orm import Session

from keystone.assets import service as assets
from keystone.controls import service as controls
from keystone.core import auth
from keystone.core.rbac import Role
from keystone.frameworks import loader
from keystone.frameworks.service import control_by_code
from keystone.org import service as org
from keystone.risk import service as risk
from keystone.tprm import service as tprm

DEMO_PASSWORD = "Demo-Password-2026!"

PEOPLE = [
    ("mia.isms", "Mia Novak", Role.ISMS_MANAGER),
    ("raj.risk", "Raj Patel", Role.RISK_OWNER),
    ("lena.ctl", "Lena Fischer", Role.CONTROL_OWNER),
    ("omar.audit", "Omar Haddad", Role.AUDITOR),
    ("sam.view", "Sam Jones", Role.VIEWER),
]


def seed(session: Session, admin) -> dict:
    """Populate an empty database (after the first admin exists). Returns handles for tests."""
    people = {"admin": admin}
    for username, name, role in PEOPLE:
        people[username] = auth.create_user(session, admin, username=username, display_name=name, password=DEMO_PASSWORD, role=role, email=f"{username}@alpineskihouse.example", must_change_password=False)
    loader.seed_content(session, admin)

    org.save_org(
        session, admin, name="Alpine Ski House", legal_name="Alpine Ski House AG", industry="Leisure and hospitality",
        description="Ski resort operator with online booking, rental shops and three hotels.",
        internal_issues="Small IT team; seasonal staff; legacy booking platform.",
        external_issues="Ransomware targeting hospitality; card payment rules; GDPR.",
        scope_statement="Information security of the online booking platform, hotel operations systems and corporate IT supporting them, at the Geneva head office and three resort sites.",
        scope_exclusions="Lift control systems (operated and certified by the lift manufacturer).",
        risk_appetite="Low appetite for risks to guest personal and payment data; moderate for availability outside peak season.",
    )
    org.approve_scope(session, admin)
    mia, raj, lena = people["mia.isms"], people["raj.risk"], people["lena.ctl"]
    org.add_interested_party(session, admin, name="Guests", party_type="external", needs="Personal and card data kept confidential; bookings available.", addressed_by="Privacy and PCI controls; availability objectives.")
    org.add_interested_party(session, admin, name="Card acquirer", party_type="external", needs="PCI DSS compliance.", addressed_by="Annual PCI assessment.")
    org.add_isms_role(session, admin, title="Information Security Officer", user_id=mia.id, responsibilities="Runs the ISMS and reports to the board quarterly.")
    org.save_objective(session, admin, title="Phishing-resistant MFA for all staff", measure="% of accounts with FIDO2 or Authenticator number matching", target="100%", current_value="72%", owner_id=mia.id, due_date=date.today() + timedelta(days=120), status="at_risk")
    org.save_objective(session, admin, title="Restore booking platform within 4 hours", measure="Tested recovery time", target="<= 4h", current_value="6h", owner_id=lena.id, due_date=date.today() + timedelta(days=200), status="on_track")

    booking = assets.save_asset(session, admin, name="Online booking platform", asset_type="application", classification="confidential", confidentiality=5, integrity=4, availability=5, contains_personal_data=True, owner_id=raj.id, location="Cloud (EU)")
    guestdb = assets.save_asset(session, admin, name="Guest database", asset_type="information", classification="restricted", confidentiality=5, integrity=4, availability=4, contains_personal_data=True, owner_id=raj.id)
    m365 = assets.save_asset(session, admin, name="Microsoft 365 tenant", asset_type="cloud_service", classification="confidential", confidentiality=4, integrity=4, availability=4, owner_id=lena.id)
    assets.save_asset(session, admin, name="Hotel file servers", asset_type="hardware", classification="internal", confidentiality=3, integrity=3, availability=4, owner_id=lena.id, location="Resort sites")

    c_backup, c_mfa, c_vuln, c_supplier = (control_by_code(session, c) for c in ("KC-TEC-13", "KC-TEC-05", "KC-TEC-08", "KC-ORG-19"))
    r1 = risk.save_risk(session, raj, title="Ransomware encrypts booking platform and backups", category="technology", owner_id=raj.id, threat="Criminal ransomware groups", vulnerability="Backups reachable from the domain", consequence="Bookings unavailable during peak season", inherent_likelihood=4, inherent_impact=5, residual_likelihood=2, residual_impact=5, treatment_option="mitigate", asset_ids=[booking.id], control_ids=[c_backup.id, c_vuln.id])
    risk.set_status(session, raj, r1.id, "treatment")
    risk.save_action(session, raj, r1.id, title="Immutable off-site backup copy", common_control_id=c_backup.id, owner_id=lena.id, due_date=date.today() + timedelta(days=45))
    risk.save_action(session, raj, r1.id, title="Quarterly restore test", owner_id=lena.id, due_date=date.today() - timedelta(days=5))
    risk.run_fair(session, raj, r1.id, {"tef": [0.3, 1, 3], "tcap": [0.5, 0.7, 0.95], "cs": [0.4, 0.6, 0.8], "plm": [50_000, 250_000, 1_500_000], "slef": [0.1, 0.3, 0.6], "slm": [20_000, 100_000, 800_000]}, iterations=5000, seed=1)
    r2 = risk.save_risk(session, raj, title="Account takeover of staff Microsoft 365 accounts", category="technology", owner_id=raj.id, inherent_likelihood=4, inherent_impact=4, treatment_option="mitigate", asset_ids=[m365.id], control_ids=[c_mfa.id])
    r3 = risk.save_risk(session, mia, title="Booking vendor mishandles guest data", category="third_party", owner_id=mia.id, inherent_likelihood=3, inherent_impact=4, residual_likelihood=2, residual_impact=4, treatment_option="accept", asset_ids=[guestdb.id], control_ids=[c_supplier.id])
    risk.accept_risk(session, admin, r3.id, "Contractual DPA and annual assessment in place; residual within appetite.")
    risk.save_risk(session, mia, title="Seasonal staff not trained before start", category="people", owner_id=mia.id, inherent_likelihood=4, inherent_impact=2, review_date=date.today() - timedelta(days=3))

    for code, status in {"KC-TEC-13": "partial", "KC-TEC-05": "partial", "KC-ORG-01": "implemented", "KC-GOV-01": "implemented", "KC-GOV-04": "implemented", "KC-ORG-09": "implemented", "KC-PHY-12": "not_applicable"}.items():
        ctl = control_by_code(session, code)
        ctl.status = status
        if status == "not_applicable":
            ctl.na_justification = "No cabling under our control: all sites use the landlord's managed network."
    session.flush()
    controls.add_evidence(session, lena, control_by_code(session, "KC-TEC-13").id, title="Backup job report, October", kind="file", filename="backup-report.pdf", data=b"%PDF-1.4 demo backup report", valid_until=date.today() + timedelta(days=20))
    controls.add_evidence(session, admin, control_by_code(session, "KC-ORG-01").id, title="Board approval of policy set v3", kind="note", description="Approved at the board meeting; minutes item 4.")
    controls.add_evidence(session, lena, control_by_code(session, "KC-TEC-05").id, title="Conditional Access policy export", kind="link", url="https://intranet.alpineskihouse.example/it/ca-policies", collected_on=date.today() - timedelta(days=200), valid_until=date.today() - timedelta(days=2))
    from keystone.frameworks.service import framework_by_code
    controls.approve_soa(session, admin, framework_by_code(session, "ISO27001_2022").id, "Initial SoA")
    tprm.load_default_templates(session, admin)
    fab = tprm.save_vendor(session, mia, name="Fabrikam Backup", website="https://fabrikambackup.example", services="Microsoft 365 backup", status="active", data_sensitivity="restricted", operational_criticality="high", access_level="tenant_wide", processes_personal_data=True, dpa_signed=True, owner_id=mia.id, contract_start=date.today() - timedelta(days=300), contract_end=date.today() + timedelta(days=40), asset_ids=[m365.id])
    nw = tprm.save_vendor(session, mia, name="Northwind Signatures", website="northwindsignatures.example", services="Email signature management", status="active", data_sensitivity="internal", operational_criticality="low", access_level="tenant_wide", processes_personal_data=True, dpa_signed=False, owner_id=lena.id)
    tprm.save_vendor(session, mia, name="Litware Scheduler", website="litware-scheduler.example", services="Staff shift scheduling", status="active", data_sensitivity="internal", operational_criticality="medium", access_level="delegated", processes_personal_data=True, owner_id=lena.id, risk_ids=[r3.id])
    tpl = tprm.templates(session)[0]
    q = tprm.send_questionnaire(session, mia, fab.id, tpl.id)
    answers = {qq["id"]: {"answer": "yes"} for qq in tpl.questions if qq["type"] != "text"}
    answers["ops1"] = {"answer": "partial", "comment": "30 days for critical"}
    answers["gov2"] = {"answer": "yes", "comment": "ISO 27001 certificate valid to 2027"}
    tprm.record_responses(session, mia, q.id, answers, complete=True)
    tprm.send_questionnaire(session, mia, nw.id, tpl.id, due_date=date.today() - timedelta(days=4))
    va = tprm.save_assessment(session, mia, fab.id, title="Fabrikam Backup annual assessment", scenario="Compromise of Fabrikam's platform used to read or delete our Microsoft 365 data.", integration_depth="Tenant-wide application access", tef=[0.05, 0.2, 1], tcap=[0.5, 0.7, 0.95], control_strength=[0.5, 0.7, 0.85], plm=[100_000, 400_000, 2_000_000], slef=[0.2, 0.4, 0.7], slm=[50_000, 250_000, 1_500_000])
    tprm.run_assessment(session, mia, va.id, iterations=3000, seed=2)
    tprm.submit_assessment(session, mia, va.id)
    # Entra exposure: the demo org has a main tenant (two snapshots) and a subsidiary tenant.
    import json

    from keystone.core.settings import PROJECT_ROOT
    from keystone.tprm.exposure import fair_mapping, importer, vendor_matching

    fx = PROJECT_ROOT / "tests" / "fixtures"
    for name, label in (("collected_tenant_a.json", "Alpine Ski House (main)"), ("collected_tenant_a_later.json", None), ("collected_tenant_b_no_p1.json", "Tailspin Toys (subsidiary)")):
        importer.import_document(session, mia, json.loads((fx / name).read_text(encoding="utf-8")), create_tenant_name=label)
    vendor_matching.refresh_suggestions(session, mia)
    from keystone.tprm.exposure.inventory import mappings
    for oid, m in mappings(session).items():
        if m.vendor_id in (fab.id, nw.id) and m.match_signals.get("strength") == "strong":
            vendor_matching.confirm(session, mia, oid, m.vendor_id)
    main = importer.tenants(session)[0]
    nva = tprm.save_assessment(session, mia, nw.id, title="Northwind Signatures exposure review", integration_depth=None, entra_tenant_id=main.id, tef=[0.05, 0.3, 1], tcap=[0.4, 0.6, 0.9], control_strength=[0.4, 0.5, 0.7])
    fair_mapping.generate(session, mia, nva.id)
    return {"people": people, "assets": [booking, guestdb, m365], "risks": [r1, r2, r3]}
