"""Fictional demo organisation used by scripts/seed_demo.py and the UI tests.

Everything is invented (".example" domains, made-up people). Never put real data here.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.assets import service as assets
from keystone.audits import review as reviews
from keystone.audits import service as audits
from keystone.controls import service as controls
from keystone.core import auth
from keystone.core.rbac import Role
from keystone.frameworks import loader
from keystone.frameworks.models import CommonControl
from keystone.frameworks.service import control_by_code
from keystone.improvement import service as improvement
from keystone.incidents import service as incidents
from keystone.core.db import utcnow
from keystone.org import service as org
from keystone.policies import service as pol
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


def _control(session: Session, code: str) -> CommonControl:
    c = control_by_code(session, code)
    if c is None:
        raise LookupError(f"Control {code} is missing from the content pack")
    return c


def seed(session: Session, admin) -> dict:
    """Populate an empty database (after the first admin exists). Returns handles for tests."""
    people = {"admin": admin}
    for username, name, role in PEOPLE:
        expiry = datetime.now() + timedelta(days=90) if role == Role.AUDITOR else None  # auditor accounts must expire
        people[username] = auth.create_user(session, admin, username=username, display_name=name, password=DEMO_PASSWORD, role=role, email=f"{username}@alpineskihouse.example", must_change_password=False, expires_at=expiry)
    loader.seed_content(session, admin)
    from keystone.frameworks.models import Framework

    for fw in session.scalars(select(Framework)):  # the demo company: an ISMS on ISO 27001 plus GDPR for guest data
        fw.enabled = fw.code in ("ISO27001_2022", "NIST_CSF_2_0", "SOC2_TSC_2017", "CIS_V8_1", "GDPR")

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

    c_backup, c_mfa, c_vuln, c_supplier = (_control(session, c) for c in ("KC-TEC-13", "KC-TEC-05", "KC-TEC-08", "KC-ORG-19"))
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
        ctl = _control(session, code)
        ctl.status = status
        if status == "not_applicable":
            ctl.na_justification = "No cabling under our control: all sites use the landlord's managed network."
    session.flush()
    controls.add_evidence(session, lena, _control(session, "KC-TEC-13").id, title="Backup job report, October", kind="file", filename="backup-report.pdf", data=b"%PDF-1.4 demo backup report", valid_until=date.today() + timedelta(days=20))
    controls.add_evidence(session, admin, _control(session, "KC-ORG-01").id, title="Board approval of policy set v3", kind="note", description="Approved at the board meeting; minutes item 4.")
    controls.add_evidence(session, lena, _control(session, "KC-TEC-05").id, title="Conditional Access policy export", kind="link", url="https://intranet.alpineskihouse.example/it/ca-policies", collected_on=date.today() - timedelta(days=200), valid_until=date.today() - timedelta(days=2))
    from keystone.frameworks.service import framework_by_code
    iso = framework_by_code(session, "ISO27001_2022")
    if iso is None:
        raise LookupError("ISO27001_2022 is missing from the content pack")
    controls.approve_soa(session, admin, iso.id, "Initial SoA")
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
    c_pol = _control(session, "KC-ORG-01")
    isp = pol.save_document(session, mia, code="POL-001", title="Information Security Policy", requires_acknowledgement=True, owner_id=mia.id, control_ids=[c_pol.id])
    v = pol.start_version(session, mia, isp.id, body="# Information Security Policy\n\n## Purpose\nProtect guest, staff and company information.\n\n## Scope\nAll staff, contractors and systems in the ISMS scope.\n\n## Rules\n1. Use MFA for every account.\n2. Report suspected incidents to security@alpineskihouse.example at once.\n3. Handle guest data only for the purpose it was collected.", change_summary="First issue")
    pol.submit_version(session, mia, v.id)
    pol.approve_version(session, admin, v.id, "Approved by the board")
    pol.acknowledge(session, raj, v.id)
    aup = pol.save_document(session, mia, code="POL-002", title="Acceptable Use Policy", requires_acknowledgement=True, owner_id=lena.id)
    v2 = pol.start_version(session, mia, aup.id, body="# Acceptable Use\n\nCompany devices are for business use...", change_summary="First issue")
    pol.submit_version(session, mia, v2.id)
    pol.save_document(session, mia, code="PRC-010", title="Incident Response Procedure", doc_type="procedure", owner_id=mia.id)

    phish = incidents.report_incident(session, lena, title="Phishing email led to one compromised mailbox", category="account_compromise", severity="high", personal_data_involved=False, detected_at=utcnow() - timedelta(days=12), reported_by="Front desk, Hotel Edelweiss", owner_id=lena.id, asset_ids=[m365.id])
    for stt in ("triage", "contained", "eradicated", "recovered"):
        incidents.move(session, lena, phish.id, stt)
    incidents.update_incident(session, lena, phish.id, root_cause="Legacy MFA (SMS) phished through an adversary-in-the-middle page.", lessons_learned="Move all staff to phishing-resistant MFA; block legacy authentication.")
    incidents.move(session, lena, phish.id, "closed")
    leak = incidents.report_incident(session, raj, title="Guest list emailed to wrong recipient", category="data_breach", severity="medium", personal_data_involved=True, notification_required=True, detected_at=utcnow() - timedelta(hours=30), owner_id=mia.id)
    incidents.move(session, raj, leak.id, "triage")
    incidents.add_note(session, raj, leak.id, "Recipient confirmed deletion by email.")
    nc = improvement.raise_nc(session, mia, title="Phishing-resistant MFA not enforced for hotel staff", source="incident", severity="major", incident_id=phish.id, common_control_id=c_mfa.id, owner_id=lena.id, root_cause="MFA rollout plan excluded seasonal accounts.", due_date=date.today() + timedelta(days=60))
    a = improvement.add_action(session, mia, nc.id, "Enforce FIDO2 for all hotel accounts via Conditional Access", owner_id=lena.id, due_date=date.today() + timedelta(days=30))
    improvement.plan(session, mia, nc.id)
    improvement.raise_nc(session, people["omar.audit"], title="Access reviews for the booking platform not evidenced", source="internal_audit", severity="minor")

    omar = people["omar.audit"]
    au = audits.save_audit(session, mia, title="Internal audit: identity and access management", audit_type="internal", lead_auditor_id=omar.id, planned_start=date.today() - timedelta(days=20), planned_end=date.today() - timedelta(days=15), scope="Joiner/mover/leaver process, MFA, privileged access", criteria="ISO/IEC 27001:2022 A.5.15-A.5.18, A.8.2, A.8.5; sample of 20 leavers", control_ids=[_control(session, c).id for c in ("KC-ORG-15", "KC-ORG-16", "KC-ORG-18", "KC-TEC-02", "KC-TEC-05")])
    audits.advance(session, mia, au.id)
    audits.add_finding(session, omar, au.id, finding_type="minor_nc", title="Two leavers kept access for over a week", evidence="2 of 20 sampled leavers", common_control_id=_control(session, "KC-ORG-18").id)
    audits.add_finding(session, omar, au.id, finding_type="opportunity", title="Automate access reviews in Entra ID Governance")
    audits.advance(session, mia, au.id)
    audits.save_audit(session, mia, au.id, summary="Sampled 20 leavers and 10 admin accounts.", conclusion="Controls partially effective; one minor nonconformity.")
    audits.advance(session, mia, au.id)
    audits.save_audit(session, mia, title="Internal audit: backup and recovery", audit_type="internal", lead_auditor_id=omar.id, planned_start=date.today() + timedelta(days=30), control_ids=[_control(session, "KC-TEC-13").id, _control(session, "KC-ORG-30").id])

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
        if m.vendor_id in (fab.id, nw.id) and (m.match_signals or {}).get("strength") == "strong":
            vendor_matching.confirm(session, mia, oid, m.vendor_id)
    main = importer.tenants(session)[0]
    nva = tprm.save_assessment(session, mia, nw.id, title="Northwind Signatures exposure review", integration_depth=None, entra_tenant_id=main.id, tef=[0.05, 0.3, 1], tcap=[0.4, 0.6, 0.9], control_strength=[0.4, 0.5, 0.7])
    fair_mapping.generate(session, mia, nva.id)
    rv = reviews.create_review(session, mia, title="Management review Q4", held_on=date.today(), attendees="CEO, CFO, ISO (Mia Novak)")
    reviews.update_review(session, mia, rv.id, discussion="Phishing incident and MFA gap discussed.", decisions="Approve budget for phishing-resistant MFA.", actions="Lena Fischer: FIDO2 for all staff by end of Q1.")
    _seed_workflows(session, people, fab, nw)
    _seed_trend_history(session)
    _seed_attack_surface(session, admin)
    _seed_configuration(session, admin)
    _seed_security(session, admin, people)
    _seed_operations(session, admin, people)
    seed_external(session)
    seed_privacy_continuity(session, people)
    _seed_outreach(session, admin, people)
    return {"people": people, "assets": [booking, guestdb, m365], "risks": [r1, r2, r3]}


def _seed_attack_surface(session: Session, admin) -> None:
    """Fictional devices, accounts and settings so the attack surface screens have something to show."""
    from keystone.asm import baselines as asm_baselines
    from keystone.asm.ingest import ingest
    from keystone.asm.vocabulary import DeviceObs, IdentityObs, Inventory, SettingObs, VulnObs

    now = datetime.now()
    d = lambda ext, name, cat, os_, kind, owner, days, props: DeviceObs(external_id=ext, name=name, category=cat, hostname=name.lower(), serial=f"ASH{ext[-3:].upper()}",
                                                                       os=os_, device_type=kind, owner_email=owner, last_seen=now - timedelta(days=days), props=props)
    rmm = [
        d("rmm-001", "ASH-LT-001", "rmm", "Windows 11", "workstation", "mia.isms@alpineskihouse.example", 0, {"disk_encrypted": True, "av_up_to_date": True, "patches_pending": 0}),
        d("rmm-002", "ASH-LT-002", "rmm", "Windows 11", "workstation", "raj.risk@alpineskihouse.example", 1, {"disk_encrypted": False, "av_up_to_date": True, "patches_pending": 3}),
        d("rmm-003", "ASH-LT-003", "rmm", "Windows 10", "workstation", "lena.ctl@alpineskihouse.example", 0, {"disk_encrypted": True, "av_up_to_date": False, "patches_pending": 1}),
        d("rmm-004", "ASH-MB-004", "rmm", "macOS 15", "workstation", "sam.view@alpineskihouse.example", 2, {"disk_encrypted": True}),
        d("rmm-005", "ASH-SRV-BOOK", "rmm", "Windows Server 2022", "server", None, 0, {"av_up_to_date": True, "patches_pending": 0}),
        d("rmm-006", "ASH-SRV-FILE", "rmm", "Windows Server 2016", "server", None, 0, {"av_up_to_date": True, "patches_pending": 7}),
        d("rmm-007", "ASH-KIOSK-01", "rmm", "Windows 10", "workstation", None, 23, {"disk_encrypted": False}),
    ]
    ingest(session, None, "Demo data", "demo", Inventory(devices=rmm), recompute_after=False)
    edr = [d(f"edr-{n[-3:]}", n, "edr", None, k, None, 0, {"edr_active": ok}) for n, k, ok in
           (("ASH-LT-001", "workstation", True), ("ASH-LT-002", "workstation", True), ("ASH-LT-003", "workstation", False), ("ASH-MB-004", "workstation", True), ("ASH-SRV-BOOK", "server", True))]
    edr.append(d("edr-web", "ASH-WEB-01", "edr", "Ubuntu 22.04", "server", None, 0, {"edr_active": True}))
    ingest(session, None, "Demo data", "demo", Inventory(devices=edr), recompute_after=False)
    scan = [d("vuln-book", "ASH-SRV-BOOK", "vuln", "Windows Server 2022", "server", None, 1, {}), d("vuln-web", "ASH-WEB-01", "vuln", "Ubuntu 22.04", "server", None, 1, {}),
            d("vuln-file", "ASH-SRV-FILE", "vuln", "Windows Server 2016", "server", None, 1, {})]
    vulns = [VulnObs("vuln-web", "openssl-2026-01", "OpenSSL remote code execution", "critical", cve="CVE-2026-0001", cvss=9.8, exploitable=True, first_seen=(now - timedelta(days=12)).date()),
             VulnObs("vuln-file", "smb-signing", "SMB signing not required", "medium", first_seen=(now - timedelta(days=90)).date()),
             VulnObs("vuln-file", "ms-2026-10", "Windows cumulative update missing (October 2026)", "high", cve="CVE-2026-2002", cvss=8.1, first_seen=(now - timedelta(days=41)).date()),
             VulnObs("vuln-book", "tls10", "TLS 1.0 enabled", "medium", first_seen=(now - timedelta(days=5)).date()),
             VulnObs("vuln-book", "log4j-2021", "Apache Log4j2 remote code execution (Log4Shell)", "critical", cve="CVE-2021-44228", cvss=10.0, exploitable=True, first_seen=(now - timedelta(days=3)).date())]
    # A snapshot of the two public feeds for the demo (real, public entries), so priorities show without a download.
    from keystone.asm.models import EpssScore, KevEntry

    session.add(KevEntry(cve="CVE-2021-44228", vendor="Apache", product="Log4j2", name="Apache Log4j2 Remote Code Execution Vulnerability", date_added=date(2021, 12, 10), due_date=date(2021, 12, 24), ransomware=True))
    session.add(EpssScore(cve="CVE-2026-0001", score=0.31, percentile=0.97, score_date=now.date()))
    ingest(session, None, "Demo data", "demo", Inventory(devices=scan, vulns=vulns), recompute_after=False)
    ids = [IdentityObs(f"{u}@alpineskihouse.example", n, {"mfa_registered": mfa, "is_admin": adm, "account_enabled": True, "is_guest": False, "last_sign_in_days": days})
           for u, n, mfa, adm, days in (("mia.isms", "Mia Novak", True, True, 0), ("raj.risk", "Raj Patel", True, False, 1), ("lena.ctl", "Lena Fischer", True, True, 0),
                                       ("sam.view", "Sam Jones", False, False, 4), ("svc.backup", "Backup service", False, True, 140))]
    ids.append(IdentityObs("contractor_partner.example#ext#@alpineskihouse.example", "Contractor (guest)", {"mfa_registered": False, "is_admin": False, "account_enabled": True, "is_guest": True, "last_sign_in_days": 200}))
    settings = [SettingObs("demo:mfa-admins", "Require MFA for administrative roles", True, "Identity", "Score 10 of 10"),
                SettingObs("demo:legacy-auth", "Block legacy authentication", False, "Identity", "Score 0 of 8"),
                SettingObs("demo:user-consent", "Do not allow users to grant consent to unreliable applications", False, "Apps", "Score 0 of 4"),
                SettingObs("demo:audit-log", "Turn on audit log search", True, "Data", "Score 1 of 1")]
    ingest(session, None, "Demo data", "demo", Inventory(identities=ids, settings=settings))
    asm_baselines.add_recommended(session, admin)
    asm_baselines.evaluate(session)


# A fictional FortiGate export (documentation addresses, no secrets) with some common weaknesses.
_DEMO_FORTIGATE = """#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0:user=admin
config system global
    set admintimeout 30
    set hostname "ASH-FW-HQ"
    set strong-crypto enable
    set admin-lockout-threshold 3
end
config system interface
    edit "wan1"
        set ip 192.0.2.1 255.255.255.0
        set allowaccess ping https
    next
    edit "internal"
        set ip 198.51.100.1 255.255.255.0
        set allowaccess ping https ssh
    next
end
config system ntp
    set ntpsync enable
end
config log syslogd setting
    set status disable
end
config firewall policy
    edit 1
        set name "guest-wifi-out"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set logtraffic disable
    next
    edit 2
        set name "booking-web"
        set srcintf "wan1"
        set dstintf "internal"
        set action accept
        set srcaddr "all"
        set dstaddr "booking-web"
        set service "HTTPS"
        set logtraffic all
    next
end
"""


def _passing_facts(platform: str) -> dict:
    """Values that meet Keystone's recommended rule for every setting of a platform."""
    from keystone.configcheck import catalogue as cat

    out: dict = {}
    for st in cat.settings_for(platform):
        if st.recommended is None:
            continue
        op, expected = st.recommended[0], st.recommended[1]
        if op == "in" and isinstance(expected, (list, tuple)):
            out[st.key] = expected[0]
        else:
            out[st.key] = {"is_true": True, "is_false": False, "empty": []}.get(op, expected)
    return out


def _seed_configuration(session: Session, admin) -> None:
    """Fictional hosts and a firewall checked against configuration baselines, so the configuration screens have
    something to show. The hosts are recorded as if their agents had reported; they have no device token."""
    from keystone.configcheck import service as cfg
    from keystone.configcheck.models import ConfigTarget

    base = {platform: cfg.create_baseline(session, admin, name=name, platform=platform)
            for platform, name in (("windows", "Windows workstations"), ("linux", "Linux servers"), ("fortigate", "FortiGate firewalls"))}
    for key in ("ssh_login_grace_time", "ssh_tcp_forwarding_off", "tls10_server_disabled", "admin_lockout_threshold"):
        cfg.add_from_library(session, admin, key)
    cfg.save_rule(session, admin, baseline_id=base["windows"].id, key="custom.tls10_server_disabled", operator="eq", expected=0, severity="high", reevaluate=False)
    cfg.save_rule(session, admin, baseline_id=base["fortigate"].id, key="custom.admin_lockout_threshold", operator="lte", expected=5, severity="medium", reevaluate=False)
    dmz = cfg.create_baseline(session, admin, name="Internet-facing Linux", platform="linux", recommended=False, is_default=False,
                              description="Stricter SSH for servers reachable from the internet.", scope={"tags": ["dmz"]})
    cfg.save_rule(session, admin, baseline_id=dmz.id, key="custom.ssh_login_grace_time", operator="lte", expected=60, severity="medium", reevaluate=False)
    cfg.save_rule(session, admin, baseline_id=dmz.id, key="custom.ssh_tcp_forwarding_off", operator="eq", expected="no", severity="medium", reevaluate=False)

    now = datetime.now()
    hosts = (
        ("windows", "ASH-LT-001", "Microsoft Windows 11 Pro", "10.0.26100", None, {"rdp_enabled": False, "custom.tls10_server_disabled": 0}),
        ("windows", "ASH-SRV-FILE", "Microsoft Windows Server 2016 Standard", "10.0.14393", ["server"],
         {"rdp_enabled": True, "smb1_enabled": True, "smb_signing_required": False, "last_update_installed_days": 64, "lm_compatibility_level": 3, "custom.tls10_server_disabled": 1}),
        ("linux", "ash-web-01", "Ubuntu 22.04.5 LTS", "5.15.0-125-generic", ["dmz"],
         {"ssh_password_authentication": True, "security_updates_pending": 4, "custom.ssh_login_grace_time": 120, "custom.ssh_tcp_forwarding_off": "yes"}),
        ("linux", "ash-db-01", "Debian GNU/Linux 12", "6.1.0-28-amd64", None, {"custom.ssh_login_grace_time": 30, "custom.ssh_tcp_forwarding_off": "no"}),
    )
    for platform, name, os_name, os_version, tags, overrides in hosts:
        t = ConfigTarget(kind="agent", platform=platform, name=name, hostname=name, os_name=os_name, os_version=os_version, agent_version="1.1.0",
                         enrolled_at=now - timedelta(days=20), last_ip="198.51.100.20", facts={}, created_at=now - timedelta(days=20), tags=tags)
        session.add(t)
        session.flush()
        cfg.report(session, t, facts={**_passing_facts(platform), "ssh_server_installed": platform == "linux", **overrides}, hostname=name,
                   os_name=os_name, os_version=os_version, agent_version="1.1.0", ip="198.51.100.20")
    cfg.upload_firewall(session, admin, platform="fortigate", filename="ASH-FW-HQ_backup.conf", data=_DEMO_FORTIGATE.encode())


def _seed_security(session: Session, admin, people: dict) -> None:
    """Fictional registers (obligations, changes, exceptions, sites and checks, people security) and two reports from
    the employee portal, so the security screens have something to show."""
    from sqlalchemy import select

    from keystone.core.auth import User
    from keystone.incidents import reports
    from keystone.people.models import Person
    from keystone.registers import service as reg

    mia, lena, raj = people["mia.isms"], people["lena.ctl"], people["raj.risk"]
    on = date.today()
    reg.save(session, admin, "obligations", title="GDPR Article 32: security of processing", owner_id=mia.id, kind="law", source="GDPR Art. 32", jurisdiction="EU",
             requirement="Appropriate technical and organisational measures for personal data, including the ability to restore it in time.",
             how_met="Access control, encryption, backups tested twice a year.", review_on=(on + timedelta(days=120)).isoformat())
    reg.save(session, admin, "obligations", title="PCI DSS for card payments at the shops", owner_id=raj.id, kind="standard", source="PCI DSS 4.0.1 (SAQ B-IP)",
             jurisdiction="Card brands via the acquirer", requirement="Card terminals segmented and maintained; annual self-assessment.", review_on=(on + timedelta(days=40)).isoformat())
    reg.save(session, admin, "obligations", title="Contoso Travel contract: security schedule", owner_id=mia.id, kind="contract", source="Agency agreement, schedule 4",
             jurisdiction="Contoso Travel", requirement="Notify security incidents affecting their bookings within 24 hours.", review_on=(on + timedelta(days=200)).isoformat())

    def raised_by(e, user):
        e.created_by_id = user.id
        session.flush()
        return e

    up = raised_by(reg.save(session, admin, "changes", title="Upgrade the booking database to PostgreSQL 17", owner_id=lena.id, change_type="normal", risk_level="medium",
                            description="Major version upgrade for continued security support.", security_review="No change to exposure; access unchanged; backups verified first.",
                            rollback="Restore last night's snapshot (tested).", planned_on=(on - timedelta(days=6)).isoformat()), lena)
    reg.move(session, mia, up.id, "approved")
    reg.move(session, lena, up.id, "implemented")
    raised_by(reg.save(session, admin, "changes", title="Open the Wi-Fi guest network in the new ski school hut", owner_id=lena.id, change_type="normal", risk_level="high",
                       description="Guest Wi-Fi for the hut, on its own network.", planned_on=(on + timedelta(days=10)).isoformat()), lena)
    raised_by(reg.save(session, admin, "policy-exceptions", title="Front desk kiosks stay signed in", owner_id=lena.id, policy="POL-003 Access Control Policy, section 4.2",
                       scope="Two reception kiosks", justification="The booking kiosk software can't re-authenticate during check-in.",
                       compensating="Kiosks on their own network, locked-down profile, no email.", expires_on=(on + timedelta(days=90)).isoformat()), lena)

    office = reg.save(session, admin, "sites", title="Head office, Zermatt", owner_id=raj.id, kind="office", zone="internal", address="Bahnhofstrasse 1 (fictional)",
                      controls_text="Badge entry, reception during office hours, alarm out of hours.", review_on=(on + timedelta(days=150)).isoformat())
    room = reg.save(session, admin, "sites", title="Server room, head office", owner_id=lena.id, kind="server_room", zone="restricted",
                    controls_text="Badge plus PIN, CCTV, temperature alarm. Visitors escorted and logged.", review_on=(on + timedelta(days=90)).isoformat())
    reg.save(session, admin, "physical-checks", title="CCTV recording and coverage", owner_id=raj.id, equipment="cctv", site=office.id, every_months=3,
             last_done_on=(on - timedelta(days=70)).isoformat())
    reg.save(session, admin, "physical-checks", title="Who holds server room badges", owner_id=lena.id, equipment="badge_review", site=room.id, every_months=6,
             last_done_on=(on - timedelta(days=200)).isoformat())
    reg.save(session, admin, "visitors", title="Jordan Field", organisation="Fabrikam Backup (fictional)", site=room.id, host=lena.id, purpose="Replace a backup appliance",
             arrived_on=on.isoformat(), badge_returned=False)

    nina = session.scalar(select(Person).where(Person.email == "nina.weber@alpineskihouse.example"))
    if nina is not None:
        chk = reg.save(session, admin, "screening", title="Right to work", person=nina.id, check_type="right_to_work", provider="HR")
        reg.move(session, admin, chk.id, "clear")
        reg.save(session, admin, "screening", title="References", person=nina.id, check_type="references", provider="HR")
        reg.save(session, admin, "confidentiality", title="Employment contract, confidentiality clause", person=nina.id, agreement="employment_contract",
                 signed_on=(on - timedelta(days=12)).isoformat(), location="HR system")
    nina_user = session.scalar(select(User).where(User.username == "nina.weber@alpineskihouse.example"))
    if nina_user is not None:
        old = reports.submit(session, nina_user, kind="physical", description="The server room door was propped open with a chair at lunchtime.", where="Head office, first floor")
        reports.close(session, mia, old.id, outcome="not_a_threat", reply="Thanks Nina: the door was closed and the alarm checked. We've reminded the cleaning team.")
        reports.submit(session, nina_user, kind="phishing", description="An email says my booking-system password expires today and asks me to sign in through a link.",
                       sender="it-support@alpineski-house.example", subject="Password expires today")


def _seed_operations(session: Session, admin, people: dict) -> None:
    """Fictional alerts, pentest findings, application security, certificates, backups, indicators and a maturity
    assessment, so the security operations screens have something to show."""
    from keystone.alerts import service as alerts
    from keystone.indicators import service as kri
    from keystone.maturity import service as mat
    from keystone.registers import service as reg

    mia, lena, raj, omar = people["mia.isms"], people["lena.ctl"], people["raj.risk"], people["omar.audit"]
    on = date.today()
    src, _token = alerts.create_source(session, admin, "Contoso EDR (fictional)", "edr")  # the token isn't kept: the demo sends nothing
    mail, _token2 = alerts.create_source(session, admin, "Email security (fictional)", "email")
    alerts.receive(session, src, title="Credential dumping tool blocked", severity="high", category="malware", host="ASH-LT-002", external_id="edr-4411",
                   description="LSASS access by an unsigned binary; blocked and quarantined.", link="https://edr.contoso.example/alerts/4411")
    alerts.receive(session, src, title="Outdated agent version", severity="low", category="misconfiguration", host="ASH-KIOSK-01", external_id="edr-4398")
    alerts.receive(session, mail, title="Phishing campaign blocked: invoice lure", severity="medium", category="phishing", account="frontdesk@alpineskihouse.example")
    for _ in range(3):
        alerts.receive(session, mail, title="Phishing campaign blocked: invoice lure", severity="medium", category="phishing", account="frontdesk@alpineskihouse.example")

    def raised_by(e, user):
        e.created_by_id = user.id
        session.flush()
        return e

    pen = reg.save(session, admin, "pentests", title="External penetration test 2026", owner_id=mia.id, kind="pentest", provider="Fabrikam Security (fictional)",
                   scope="Booking platform, public website and VPN.", report_location="ISMS SharePoint, restricted folder", retest_on=(on + timedelta(days=30)).isoformat())
    reg.move(session, mia, pen.id, "in_progress")
    reg.move(session, mia, pen.id, "reported")
    f1 = raised_by(reg.save(session, admin, "findings", title="Stored XSS in booking notes", owner_id=lena.id, test=pen.id, severity="high",
                            description="Guest notes are shown unescaped to front desk staff.", recommendation="Encode output; add a content security policy."), mia)
    reg.move(session, lena, f1.id, "fixed", note="Output encoded and CSP added in release 4.2.")
    reg.move(session, omar, f1.id, "verified")
    reg.save(session, admin, "findings", title="TLS 1.0 still enabled on the VPN", owner_id=lena.id, test=pen.id, severity="medium",
             description="The VPN gateway accepts TLS 1.0.", recommendation="Allow TLS 1.2 and later only.")
    reg.save(session, admin, "findings", title="Verbose server banner", owner_id=lena.id, test=pen.id, severity="low", description="The web server shows its version.")

    app = reg.save(session, admin, "applications", title="Booking platform", owner_id=lena.id, criticality="critical", data="restricted", personal_data=True,
                   description="Online booking for hotels, lifts and rentals.", repository="alpine/booking (fictional)", hosting="Cloud (EU)",
                   practices="Code review on every change, dependency and secret scanning, yearly pentest.")
    tm = raised_by(reg.save(session, admin, "threat-models", title="Booking platform: STRIDE", owner_id=lena.id, application=app.id, method="stride",
                            scope="Web app, booking API, payment redirect.", threats="Account takeover; card-data exposure; booking tampering; denial of service at peak season.",
                            mitigations="MFA for staff, payment page hosted by the processor, rate limits, CDN.", residual="medium",
                            review_on=(on + timedelta(days=300)).isoformat()), lena)
    reg.move(session, mia, tm.id, "approved")
    raised_by(reg.save(session, admin, "release-signoffs", title="Booking platform 4.3", application=app.id, version="4.3", changes="Gift vouchers; new login page.",
                       tests="Dependency and secret scanning clean; SAST: 2 low; login page retested.", release_on=(on + timedelta(days=5)).isoformat()), lena)

    reg.save(session, admin, "crypto", title="Booking platform signing key", owner_id=lena.id, kind="signing_key", location="Booking API (tokens)",
             storage="Cloud key vault", algorithm="ECDSA P-256", rotate_every_months=12, last_rotated_on=(on - timedelta(days=340)).isoformat())
    reg.save(session, admin, "crypto", title="Code signing certificate", owner_id=lena.id, kind="code_signing", location="Kiosk app builds",
             storage="Hardware token in the safe", expires_on=(on + timedelta(days=21)).isoformat())

    reg.save(session, admin, "backups", title="Booking database", owner_id=lena.id, tool="Cloud snapshots", frequency="hourly", retention="35 days", offsite=True,
             last_success_on=on.isoformat(), last_restore_test_on=(on - timedelta(days=40)).isoformat(), restore_test_every_months=6)
    files = reg.save(session, admin, "backups", title="Hotel file servers", owner_id=raj.id, tool="Veeam (fictional)", frequency="daily", retention="90 days", offsite=False,
                     last_success_on=(on - timedelta(days=3)).isoformat(), last_restore_test_on=(on - timedelta(days=220)).isoformat(), restore_test_every_months=6)
    reg.move(session, raj, files.id, "failure", note="Repository full since Saturday.")

    kri.add_recommended(session, admin)
    a = mat.save(session, admin, title="2026 self-assessment", assessed_on=on - timedelta(days=20))
    scores = {}
    for f in mat.categories():
        base = {"GV": 2, "ID": 2, "PR": 3, "DE": 1, "RS": 2, "RC": 1}.get(f["ref"], 2)
        for n, c in enumerate(f["categories"]):
            cur = max(0, min(4, base + (-1, 0, 1, 0)[n % 4]))  # a fixed spread: the same demo every time
            scores[c["ref"]] = {"current": cur, "target": min(4, max(cur, 3))}
    mat.save(session, admin, a.id, scores=scores)
    mat.finalise(session, admin, a.id)


DEMO_DMARC = """<?xml version="1.0"?>
<feedback><report_metadata><org_name>Mail provider (fictional)</org_name><report_id>demo-{day}</report_id>
<date_range><begin>{begin}</begin><end>{end}</end></date_range></report_metadata>
<policy_published><domain>alpineskihouse.example</domain><p>quarantine</p></policy_published>
<record><row><source_ip>192.0.2.10</source_ip><count>1840</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
<identifiers><header_from>alpineskihouse.example</header_from></identifiers></record>
<record><row><source_ip>198.51.100.7</source_ip><count>212</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row>
<identifiers><header_from>alpineskihouse.example</header_from></identifiers></record>
<record><row><source_ip>203.0.113.66</source_ip><count>37</count><policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
<identifiers><header_from>alpineskihouse.example</header_from></identifiers></record>
</feedback>"""


def _seed_outreach(session: Session, admin, people: dict) -> None:
    """A finished phishing simulation, look-alike domains, a supplier breach, an on-call rota and a DMARC report. All
    fictional and made locally: the demo never sends an email or calls crt.sh or Have I Been Pwned."""
    from keystone.asm.models import ExternalDomain
    from keystone.dmarc import service as dm
    from keystone.oncall import service as oc
    from keystone.phishing import service as ph
    from keystone.phishing.models import PhishingTarget
    from keystone.threatintel import service as ti

    mia, raj, lena = people["mia.isms"], people["raj.risk"], people["lena.ctl"]
    now = datetime.now().replace(microsecond=0)

    c = ph.create(session, mia, name="Autumn practice: shared document", template="shared-document", audience=None)
    c.status, c.launched_by_id, c.launched_at, c.completed_at = "completed", admin.id, now - timedelta(days=20), now - timedelta(days=6)
    rows = [(admin, "IT", 2, None), (mia, "IT", None, 3), (raj, "Digital", 1, None), (lena, "IT", None, 5), (people["omar.audit"], "Audit", None, None), (people["sam.view"], "Front desk", 4, 9)]
    for u, dept, clicked, reported in rows:  # fixed results: the same demo every time
        session.add(PhishingTarget(campaign_id=c.id, user_id=u.id, department=dept, sent_at=c.launched_at,
                                   clicked_at=c.launched_at + timedelta(hours=clicked) if clicked else None, clicks=1 if clicked else 0,
                                   reported_at=c.launched_at + timedelta(hours=reported) if reported else None))
    ph.create(session, mia, name="Winter practice: parcel delivery", template="parcel", audience={"departments": ["Front desk"], "employment_types": []})

    def ct(pattern: str) -> set[str]:
        return {"alpineskihouse-login.example", "alpineskihuose.example", "alpineskihouse.example", "mail.alpineskihouse.example"} if "alpine" in pattern else set()

    if session.scalar(select(ExternalDomain)) is not None:
        ti.scan_lookalikes(session, fetch=ct)
        for x in ti.lookalikes(session, admin):
            if x.name.startswith("alpineskihuose"):
                ti.decide_lookalike(session, admin, x.id, "threat", "Blocked in email and web filters; takedown requested from the registrar.")

    def hibp() -> list[dict]:
        return [{"Name": "FabrikamBackup2026", "Title": "Fabrikam Backup (fictional)", "Domain": "fabrikambackup.example", "BreachDate": (date.today() - timedelta(days=45)).isoformat(),
                 "AddedDate": (date.today() - timedelta(days=4)).isoformat(), "PwnCount": 182000, "DataClasses": ["Email addresses", "Names", "Passwords"]}]

    ti.scan_breaches(session, fetch=hibp)
    oc.save(session, admin, name="Security on-call", member_ids=[mia.id, lena.id, raj.id], start_on=date.today() - timedelta(days=3), rotation_days=7, escalate_after_minutes=15)
    end = int(now.timestamp())
    dm.upload(session, admin, "demo.xml", DEMO_DMARC.format(day=date.today().isoformat(), begin=end - 86400, end=end).encode())


def _seed_trend_history(session: Session, weeks: int = 11) -> None:
    """Fictional weekly snapshots so the demo dashboard has trends: earlier weeks had more open work."""
    from keystone.reporting import dashboard
    from keystone.reporting.models import MetricSnapshot

    now = dashboard.metrics(session)
    today = date.today()
    sunday = today - timedelta(days=today.weekday() + 1)
    for w in range(weeks, 0, -1):
        day = sunday - timedelta(weeks=w - 1)
        f = (w + 1) / (weeks + 1)  # near 1.0 for the oldest week, falling towards last week
        v = dict(now)
        v["readiness_pct"] = round(max(0.0, now["readiness_pct"] * (1 - 0.6 * f)), 1)
        v["controls_implemented"] = round(now["controls_implemented"] * (1 - 0.6 * f))
        v["controls_audited"] = round(now["controls_audited"] * (1 - f))
        v["open_risks"] = now["open_risks"] + round(3 * f)
        v["high_risks"] = now["high_risks"] + round(2 * f)
        v["tasks_overdue"] = now["tasks_overdue"] + round(6 * f)
        v["open_incidents"] = now["open_incidents"] + (1 if w in (4, 5) else 0)
        v["open_ncs"] = max(0, now["open_ncs"] - (1 if w > 6 else 0))
        v["vendors"] = max(1, now["vendors"] - (1 if w > 8 else 0))
        session.add(MetricSnapshot(day=day, values=v, taken_at=datetime.combine(day, datetime.min.time())))
    session.flush()


def _seed_workflows(session: Session, people: dict, fab, nw) -> None:
    """Onboarding, tasks, people and portal, Trust Center, integrations and questionnaires."""
    from keystone.answers import service as answers
    from keystone.integrations import service as integ
    from keystone.onboarding import service as onboarding
    from keystone.people import service as ppl
    from keystone.policies.models import PolicyDocument
    from keystone.tasks import service as tasks
    from keystone.trust import service as trust
    from sqlalchemy import select

    admin, mia, lena = people["admin"], people["mia.isms"], people["lena.ctl"]
    onboarding.complete(session, admin, {
        "company_name": "Alpine Ski House", "legal_name": "Alpine Ski House AG", "industry": "Leisure and hospitality", "size": "201-1000",
        "hosting": ["m365", "cloud_azure"], "data_types": ["customer_personal", "payment_cards", "employee"], "develops_software": True, "offices": True,
        "locations": "the Geneva head office and three resort sites", "frameworks": ["ISO27001_2022", "NIST_CSF_2_0", "SOC2_TSC_2017", "CIS_V8_1"], "isms_owner_id": mia.id, "review_months": 12,
    })
    # Approve a core set of the generated policies (written by admin, approved by the ISMS manager).
    for code in ("POL-003", "POL-006", "POL-007", "POL-008", "POL-012", "POL-015"):
        d = session.scalar(select(PolicyDocument).where(PolicyDocument.code == code))
        v = d and pol.open_version(d)
        if v is not None:
            pol.submit_version(session, admin, v.id)
            pol.approve_version(session, mia, v.id, "Reviewed for Alpine Ski House")

    # Tasks: a few done (evidence filed on their controls), one in review, one not relevant.
    open_tasks = [t for t in tasks.list_tasks(session, include_closed=False) if t.status == "todo"]
    for t in open_tasks[:3]:
        tasks.start(session, mia, t.id)
        tasks.submit(session, mia, t.id, f"Completed for the {date.today():%B %Y} cycle; records kept on the IT share.")
        tasks.approve(session, admin, t.id, "Checked")
    if len(open_tasks) > 4:
        tasks.submit(session, mia, open_tasks[3].id, "Draft register attached in the IT share; please review.")
        tasks.mark_not_relevant(session, mia, open_tasks[4].id, "Covered by the landlord's building management at all sites.")

    # People: staff with sign-ins, an employee who joined through the portal, and a leaver.
    for user, title, dept in ((mia, "Information Security Officer", "IT"), (people["raj.risk"], "Head of Digital", "Digital"), (lena, "IT Operations Lead", "IT")):
        p = ppl.save_person(session, admin, full_name=user.display_name, email=user.email, job_title=title, department=dept, start_date=date.today() - timedelta(days=700))
        ppl.link_user(session, admin, p.id, user.id)
        ppl.set_status(session, admin, p.id, "active")
    nina = ppl.save_person(session, admin, full_name="Nina Weber", email="nina.weber@alpineskihouse.example", job_title="Front desk supervisor", department="Hotels", start_date=date.today() - timedelta(days=10))
    token = ppl.invite(session, admin, nina.id)
    nina_user = ppl.accept_invite(session, token, DEMO_PASSWORD)
    for m in ppl.modules(session)[:3]:
        ppl.submit_quiz(session, nina_user, m["key"], [q["answer"] for q in m["quiz"]])
    ppl.attest_device(session, nina_user, device_name="Front desk laptop 3", os="windows", checks={k: True for k in ("disk_encryption", "screen_lock", "antivirus", "auto_updates", "firewall")})
    ppl.save_person(session, admin, full_name="Tomás García", email="tomas.garcia@alpineskihouse.example", job_title="Seasonal ski instructor", department="Ski school", employment_type="contractor", start_date=date.today() + timedelta(days=14))
    leaver = ppl.save_person(session, admin, full_name="Olivia Brown", email="olivia.brown@alpineskihouse.example", job_title="Marketing coordinator", department="Marketing", start_date=date.today() - timedelta(days=400), end_date=date.today() - timedelta(days=2))
    ppl.set_status(session, admin, leaver.id, "active")
    ppl.set_status(session, admin, leaver.id, "offboarding")
    ppl.tick_offboarding(session, admin, leaver.id, "accounts_disabled")

    # Trust Center (published).
    trust.update_settings(session, admin, published=True, slug="alpine-ski-house", headline="Security at Alpine Ski House",
                          overview="We protect guest, payment and staff data with an ISO/IEC 27001-aligned security programme.\n\n- Encryption in transit and at rest\n- Phishing-resistant MFA rollout\n- Independent penetration testing every year",
                          contact_email="security@alpineskihouse.example")
    trust.save_faq(session, admin, question="Where is guest data stored?", answer="In EU data centres operated by our cloud provider.")
    trust.save_faq(session, admin, question="How do I report a security issue?", answer="Email security@alpineskihouse.example. We reply within one working day.")
    trust.set_subprocessor(session, admin, fab.id, "Microsoft 365 backup", "EU")
    trust.add_document(session, admin, title="Penetration test summary 2026", kind="report", access="nda", filename="pentest-summary.pdf", data=b"%PDF-1.4 demo penetration test summary")

    # Integrations: the Entra checks read the imported exposure snapshots (no network).
    entra = integ.save_integration(session, admin, provider_key="entra", name="Microsoft Entra ID (Alpine Ski House)")
    integ.run(session, admin, entra.id)

    # Security questionnaires: an approved knowledge base and a partly answered questionnaire.
    kb = [("Do you encrypt customer data at rest?", "Yes. Guest and payment data is encrypted at rest with AES-256 in our cloud platform."),
          ("Do you require multi-factor authentication?", "Yes. MFA is required for all staff accounts, and we are moving all staff to phishing-resistant methods."),
          ("Do you have an incident response plan?", "Yes. Our Incident Response Policy and procedure are tested once a year.")]
    for q, a in kb:
        e = answers.save_entry(session, lena, question=q, answer=a, tags="standard answers")
        answers.approve_entry(session, mia, e.id)
    sq = answers.create(session, lena, title="Contoso Travel vendor security review", requester="Contoso Travel", due_date=date.today() + timedelta(days=12),
                        pasted="Do you encrypt customer data at rest?\nDo you require multi-factor authentication?\nDo you have an incident response plan?\nHow often do you test restores from backup?\nDo you hold an ISO 27001 certificate?")
    answers.fill_from_knowledge_base(session, lena, sq.id)
    answers.approve_item(session, mia, sq.items[0].id)


def seed_external(session: Session) -> None:
    """A fictional verified domain with example results (no lookups are made for demo data)."""
    from keystone.asm.external import RECORD_PREFIX, _issue, _worst
    from keystone.asm.models import ExternalDomain, ExternalHost

    now = utcnow()
    d = ExternalDomain(name="alpineskihouse.example", verification_token=RECORD_PREFIX + "demo", verified_at=now, last_scan_at=now,
                       email={"spf": "v=spf1 include:spf.protection.outlook.com -all", "dmarc": "v=DMARC1; p=none", "dmarc_policy": "none", "caa": []},
                       issues=[_issue("dmarc_monitor_only", "medium", "DMARC policy is p=none (monitoring only)"),
                               _issue("caa_missing", "low", "No CAA record limiting which certificate authorities may issue for this domain")])
    session.add(d)
    session.flush()
    hosts = [
        ("alpineskihouse.example", "dns", {"web": "https", "tls_version": "TLSv1.3", "cert_expires": (now + timedelta(days=70)).date().isoformat(), "https_redirect": True}, []),
        ("www.alpineskihouse.example", "dns", {"web": "https", "tls_version": "TLSv1.3", "cert_expires": (now + timedelta(days=70)).date().isoformat(), "https_redirect": True}, []),
        ("booking.alpineskihouse.example", "ct", {"web": "https", "tls_version": "TLSv1.2", "cert_expires": (now + timedelta(days=9)).date().isoformat(), "https_redirect": True},
         [_issue("cert_expiring", "high", "Certificate expires soon"), _issue("hsts_missing", "low", "No Strict-Transport-Security header")]),
        ("shop.alpineskihouse.example", "ct", {"cname": "alpine-shop-2019.azurewebsites.example", "addresses": []},
         [_issue("dangling_cname", "high", "Points (CNAME) to alpine-shop-2019.azurewebsites.example, which doesn't exist: someone could claim it and serve content on this name")]),
        ("vpn.alpineskihouse.example", "ct", {"web": "https", "tls_version": "TLSv1.0", "https_redirect": None}, [_issue("tls_old", "high", "Old TLS version (TLSv1.0)")]),
        ("intranet.alpineskihouse.example", "ct", {"addresses": ["10.20.0.15"], "web": "not checked"},
         [_issue("internal_address", "low", "Public DNS gives an internal address for this name (reveals internal naming)")]),
    ]
    for name, src, facts, issues in hosts:
        session.add(ExternalHost(domain_id=d.id, host=name, source=src, first_seen=now - timedelta(days=30), last_seen=now, checked_at=now, facts=facts, issues=issues, worst=_worst(issues)))
    session.flush()


def seed_privacy_continuity(session: Session, people: dict) -> None:
    """Fictional privacy records and continuity data for the demo organisation."""
    from keystone.assets.models import Asset
    from keystone.continuity import service as bc
    from keystone.privacy import service as pv
    from keystone.tprm.models import Vendor

    mia, raj = people["mia.isms"], people["raj.risk"]
    vendors = {v.name: v.id for v in session.scalars(select(Vendor))}
    assets = {a.name: a.id for a in session.scalars(select(Asset))}
    book = pv.save_activity(session, mia, name="Guest bookings", purpose="Take, change and fulfil hotel and ski-school bookings", lawful_basis="contract",
                            data_subjects="Guests and their party members", data_categories="Names, contact details, stay dates, payment references",
                            recipients="Hotels, payment provider", retention="7 years after the stay (tax law)", owner_id=raj.id,
                            asset_ids=[i for n, i in assets.items() if n in ("Online booking platform", "Guest database")],
                            vendor_ids=[i for n, i in vendors.items() if n.startswith("Fabrikam")], security_measures="Encryption at rest, MFA for staff, daily backups")
    pv.save_activity(session, mia, name="Marketing newsletter", purpose="Send season offers to people who signed up", lawful_basis="consent",
                     data_subjects="Subscribers", data_categories="Email address, language", retention="Until consent is withdrawn", owner_id=mia.id,
                     transfers="United States", transfer_safeguard="scc")
    pv.save_activity(session, mia, name="Staff medical certificates", purpose="Record sick leave", lawful_basis="legal_obligation", special_category=True,
                     special_condition="Art. 9(2)(b) employment law", data_subjects="Employees", retention="3 years", owner_id=mia.id, dpia_required=False)
    d = pv.save_dpia(session, mia, title="Lift-pass face recognition pilot", activity_id=book.id, description="Pilot of face matching at two lift gates to stop pass sharing",
                     necessity="Pass sharing costs revenue; a photo check by staff is the less intrusive alternative",
                     risks=[{"risk": "Biometric data of guests processed at scale", "likelihood": 3, "severity": 3, "measures": "Opt-in only; templates deleted at end of stay", "residual": 2},
                            {"risk": "False matches deny access", "likelihood": 2, "severity": 2, "measures": "Staff override at every gate", "residual": 1}],
                     outcome="proceed_with_measures", dpo_advice="Only with explicit opt-in and a non-biometric alternative")
    pv.submit_dpia(session, mia, d.id)
    on = today_ = date.today()
    r = pv.save_request(session, mia, request_type="access", received_on=today_ - timedelta(days=24), channel="Email", requester_name="A. Guest",
                        requester_contact="guest@example.com", details="Copy of all booking data", assignee_id=mia.id, identity_verified=True)
    pv.move_request(session, mia, r.id, "in_progress")
    pv.save_request(session, mia, request_type="erasure", received_on=today_ - timedelta(days=3), channel="Web form", requester_name="B. Visitor", details="Delete my newsletter data")

    pb = bc.save_process(session, raj, name="Online bookings", criticality="critical", owner_id=raj.id, mtpd_hours=24, rto_hours=8, rpo_hours=1,
                         impact={"financial": 5, "operational": 4, "legal": 2, "reputational": 4}, asset_ids=[assets.get("Online booking platform")] if assets.get("Online booking platform") else [],
                         workarounds="Phone bookings on paper forms at each hotel desk", minimum_staff=4)
    pl = bc.save_process(session, raj, name="Lift operations", criticality="critical", owner_id=raj.id, mtpd_hours=4, rto_hours=2, rpo_hours=24,
                         impact={"financial": 5, "operational": 5, "legal": 3, "reputational": 5})
    bc.save_process(session, raj, name="Payroll", criticality="high", owner_id=mia.id, mtpd_hours=120, rto_hours=72, rpo_hours=24)
    bc.save_process(session, raj, name="Hotel housekeeping scheduling", criticality="low", mtpd_hours=168, rto_hours=72)
    plan = bc.save_plan(session, raj, title="Booking platform recovery", process_ids=[pb.id], owner_id=raj.id, strategy="Restore from immutable backup to the secondary region",
                        activation="Head of IT or duty manager, when bookings are down for 30 minutes")
    bc.save_plan(session, raj, title="Lift operations continuity", process_ids=[pl.id], owner_id=raj.id, strategy="Manual gate operation; paper pass checks")
    t = bc.plan_test(session, raj, plan_id=plan.id, title="Restore booking database from backup", test_type="backup_restore", planned_on=on - timedelta(days=40))
    bc.complete_test(session, raj, t.id, performed_on=on - timedelta(days=38), outcome="passed_with_issues", findings="Restore took 11 hours: the runbook missed the DNS change",
                     results=[{"process_id": pb.id, "recovered_hours": 11, "data_loss_hours": 0.5}], raise_nc=True)
    bc.plan_test(session, raj, plan_id=plan.id, title="Tabletop: ransomware during peak week", test_type="tabletop", planned_on=on + timedelta(days=21))
