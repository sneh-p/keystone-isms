"""Phase 6: vendor matching, FAIR suggestions, snapshot diff, remediation exports."""

import io

import pytest
from openpyxl import load_workbook
from sqlalchemy import select

from keystone.core.rbac import PermissionDenied
from keystone.tprm import service as tprm
from keystone.tprm.exposure import diff, exports, fair_mapping, importer, inventory, vendor_matching as vm
from keystone.tprm.exposure.models import FairSuggestion, TenantApp


@pytest.fixture
def loaded(users, session, tenant_a, tenant_a_later, tenant_b):
    mgr = users["isms_manager"]
    a = importer.import_document(session, mgr, tenant_a, create_tenant_name="Alpine Ski House")
    importer.import_document(session, mgr, tenant_a_later)
    b = importer.import_document(session, mgr, tenant_b, create_tenant_name="Tailspin Toys")
    v = {
        "fab": tprm.save_vendor(session, mgr, name="Fabrikam Backup", website="https://fabrikambackup.example", status="active", data_sensitivity="restricted", operational_criticality="high", access_level="tenant_wide"),
        "nw": tprm.save_vendor(session, mgr, name="Northwind Signatures", website="northwindsignatures.example", status="active"),
        "lit": tprm.save_vendor(session, mgr, name="Litware", website="litware.example", status="active"),
        "other": tprm.save_vendor(session, mgr, name="Completely Different Co", website="different.example", status="active"),
    }
    return {"tenant_a": a.tenant_id, "tenant_b": b.tenant_id, "vendors": v}


def owner_of(session, name):
    return session.scalar(select(TenantApp.owner_org_id).where(TenantApp.display_name == name).limit(1))


@pytest.mark.parametrize("host,dom", [("app.northwindsignatures.example", "northwindsignatures.example"), ("portal.example.co.uk", "example.co.uk"), ("localhost", None), (None, None)])
def test_registrable_domain(host, dom):
    assert vm.registrable_domain(host) == dom


def test_owner_orgs_use_latest_snapshot(loaded, session):
    orgs = inventory.owner_orgs(session)
    names = {o.label for o in orgs.values()}
    assert "Adatum Survey" not in " ".join(n for o in orgs.values() for n in o.names)  # removed in later snapshot
    assert any("Margie" in n for o in orgs.values() for n in o.names)
    fab = orgs[owner_of(session, "Fabrikam Backup for Microsoft 365")]
    assert set(fab.level_by_tenant) == {loaded["tenant_a"], loaded["tenant_b"]}  # same owner org in both tenants


def test_candidates_strong_and_weak(loaded, session):
    orgs = inventory.owner_orgs(session)
    vendors = list(loaded["vendors"].values())
    fab = vm.candidates(orgs[owner_of(session, "Fabrikam Backup for Microsoft 365")], vendors)
    assert fab[0].vendor_name == "Fabrikam Backup" and fab[0].domain_match and fab[0].strength == "strong"
    lit = vm.candidates(orgs[owner_of(session, "Litware Scheduler")], vendors)
    assert lit[0].vendor_name == "Litware" and not lit[0].domain_match and lit[0].strength == "weak"
    wing = vm.candidates(orgs[owner_of(session, "Wingtip HR Sync")], vendors)
    assert all(c.vendor_name != "Completely Different Co" for c in wing)


def test_suggest_confirm_ignore_flow(loaded, session, users):
    mgr = users["isms_manager"]
    assert vm.refresh_suggestions(session, mgr) >= 3
    maps = inventory.mappings(session)
    fab_owner = owner_of(session, "Fabrikam Backup for Microsoft 365")
    assert maps[fab_owner].status == "suggested" and maps[fab_owner].vendor_id == loaded["vendors"]["fab"].id
    # Nothing is applied until confirmed
    assert inventory.vendor_presence(session, loaded["vendors"]["fab"].id) == {}
    with pytest.raises(PermissionDenied):
        vm.confirm(session, users["viewer"], fab_owner, loaded["vendors"]["fab"].id)
    vm.confirm(session, mgr, fab_owner, loaded["vendors"]["fab"].id)
    # One confirmed mapping applies across all tenants via owner_org_id
    assert inventory.vendor_presence(session, loaded["vendors"]["fab"].id) == {"Alpine Ski House": "Critical", "Tailspin Toys": "Critical"}
    wing = owner_of(session, "Wingtip HR Sync")
    vm.ignore(session, mgr, wing)
    vm.refresh_suggestions(session, mgr)  # does not touch confirmed/ignored
    maps = inventory.mappings(session)
    assert maps[fab_owner].status == "confirmed" and maps[wing].status == "ignored" and maps[wing].vendor_id is None
    queued = {o.owner_org_id for o, _ in vm.queue(session)}
    assert fab_owner not in queued and wing not in queued
    vm.reset(session, mgr, wing)
    assert wing in {o.owner_org_id for o, _ in vm.queue(session)}


def test_one_vendor_many_owner_orgs(loaded, session, users):
    mgr = users["isms_manager"]
    vm.confirm(session, mgr, owner_of(session, "Northwind Signatures"), loaded["vendors"]["nw"].id)
    vm.confirm(session, mgr, owner_of(session, "Relecloud Wiki (SAML)"), loaded["vendors"]["nw"].id)
    assert inventory.vendor_presence(session, loaded["vendors"]["nw"].id)["Alpine Ski House"] == "Critical"  # later snapshot: Mail.Send app-only


# ---- FAIR suggestions ------------------------------------------------------------------------

def _assessment(session, users, loaded, vendor="fab", tenant="tenant_a", **kw):
    v = loaded["vendors"][vendor]
    vm.confirm(session, users["isms_manager"], owner_of(session, {"fab": "Fabrikam Backup for Microsoft 365", "nw": "Northwind Signatures", "lit": "Litware Scheduler"}[vendor]), v.id)
    return tprm.save_assessment(session, users["isms_manager"], v.id, title="Exposure-informed", entra_tenant_id=loaded[tenant], **kw)


def test_suggestions_for_tenant_wide_vendor(loaded, session, users):
    a = _assessment(session, users, loaded, tef=[0.1, 0.5, 2], control_strength=[0.5, 0.6, 0.7])
    sugg = {s.field: s for s in fair_mapping.generate(session, users["isms_manager"], a.id)}
    assert set(sugg) == {"integration_depth", "plm", "slm", "control_strength"}  # never tef
    assert sugg["integration_depth"].suggested_value == "Tenant-wide application access" and sugg["integration_depth"].rule_ids == ["ID1"]
    assert sugg["plm"].suggested_value == {"min": 250000.0, "ml": 1000000.0, "max": 5000000.0}
    # Alpine later snapshot: users cannot consent (no shift), workflow enabled +0.05, verified +0.05
    cs = sugg["control_strength"]
    assert cs.suggested_value == {"min": 0.6, "ml": 0.7, "max": 0.8} and set(cs.rule_ids) == {"CS2", "CS3"}
    assert all(s.reasons for s in sugg.values())
    # Suggest, never overwrite
    session.refresh(a)
    assert a.plm is None and a.integration_depth is None and a.control_strength == {"min": 0.5, "ml": 0.6, "max": 0.7}


def test_control_strength_unknown_and_negative_shifts(loaded, session, users):
    a = _assessment(session, users, loaded, tenant="tenant_b", control_strength=[0.05, 0.1, 0.2])
    cs = next(s for s in fair_mapping.generate(session, users["isms_manager"], a.id) if s.field == "control_strength")
    # Tailspin: users can consent (-0.10), workflow disabled (0), verified (+0.05), credentials unknown (no adj)
    assert cs.suggested_value == {"min": 0.0, "ml": 0.05, "max": 0.15}  # clamped at 0
    assert any("Unknown" in r["text"] for r in cs.reasons if r["rule_id"] == "CS4")


def test_accept_reject_and_locking(loaded, session, users):
    mgr = users["isms_manager"]
    a = _assessment(session, users, loaded)
    sugg = {s.field: s for s in fair_mapping.generate(session, mgr, a.id)}
    fair_mapping.reject(session, mgr, sugg["slm"].id)
    fair_mapping.accept(session, mgr, sugg["plm"].id)
    assert a.plm == sugg["plm"].suggested_value and a.slm is None
    with pytest.raises(ValueError, match="already been decided"):
        fair_mapping.accept(session, mgr, sugg["plm"].id)
    assert fair_mapping.accept_all(session, mgr, a.id) == 2
    assert a.integration_depth == "Tenant-wide application access"
    decided = session.scalars(select(FairSuggestion).where(FairSuggestion.assessment_id == a.id)).all()
    assert {s.status for s in decided} == {"accepted", "rejected"} and all(s.decided_by == "ismsmanager" for s in decided)
    # Regenerating replaces only pending suggestions
    new = fair_mapping.generate(session, mgr, a.id)
    assert all(s.status == "pending" for s in new)


def test_cannot_apply_to_non_draft(loaded, session, users):
    mgr = users["isms_manager"]
    a = _assessment(session, users, loaded, tef=[0.1, 0.5, 2], tcap=[0.3, 0.5, 0.8], control_strength=[0.4, 0.5, 0.6], plm=[1, 2, 3])
    s = next(x for x in fair_mapping.generate(session, mgr, a.id) if x.field == "slm")
    tprm.run_assessment(session, mgr, a.id, iterations=500, seed=1)
    tprm.submit_assessment(session, mgr, a.id)
    with pytest.raises(ValueError, match="draft"):
        fair_mapping.accept(session, mgr, s.id)


def test_generate_requires_scope_and_mapping(loaded, session, users):
    v = loaded["vendors"]["other"]
    a = tprm.save_assessment(session, users["admin"], v.id, title="x")
    with pytest.raises(ValueError, match="Scope"):
        fair_mapping.generate(session, users["admin"], a.id)
    tprm.save_assessment(session, users["admin"], v.id, a.id, entra_tenant_id=loaded["tenant_a"])
    with pytest.raises(ValueError, match="No confirmed apps"):
        fair_mapping.generate(session, users["admin"], a.id)


def test_integration_depth_variants(loaded, session, users):
    mgr = users["isms_manager"]
    lit = loaded["vendors"]["lit"]
    vm.confirm(session, mgr, owner_of(session, "Litware Scheduler"), lit.id)
    ex = fair_mapping.summarize(session, lit.id, loaded["tenant_b"])
    assert ex.integration_depth == "User-delegated API access" and ex.depth_reason["rule_id"] == "ID2"
    vm.confirm(session, mgr, owner_of(session, "Relecloud Wiki (SAML)"), loaded["vendors"]["other"].id)
    ex2 = fair_mapping.summarize(session, loaded["vendors"]["other"].id, loaded["tenant_a"])
    assert ex2.integration_depth == "SSO only" and ex2.worst_level == "Low"


# ---- diff ---------------------------------------------------------------------------------------

def test_snapshot_diff(loaded, session):
    d = diff.latest_diff(session, loaded["tenant_a"])
    assert d.new_apps == ["Margie's Travel Expense"] and d.removed_apps == ["Adatum Survey"]
    first = d.new_permissions[0]
    assert first.app_only_high and first.tier == "critical"
    head = [(c.app, c.value) for c in d.new_permissions if c.app_only_high]
    assert set(head) == {("Margie's Travel Expense", "Directory.ReadWrite.All"), ("Northwind Signatures", "Mail.Send")}
    assert d.new_permissions[len(head)].value == "Calendars.Read"  # medium, after the app-only critical ones
    assert ("Users can consent to apps", True, False) in d.consent_changes
    assert ("Admin consent workflow enabled", False, True) in d.consent_changes
    assert d.new_credentials == [("ASH Internal Reporting", "password", "reporting-secret-2026b")]
    assert d.not_comparable == []


def test_diff_marks_failed_datasets_not_comparable(users, session, tenant_b, clone):
    later = clone(tenant_b)
    later["metadata"]["collected_at_utc"] = "2026-11-12T10:00:00Z"
    importer.import_document(session, users["admin"], tenant_b, create_tenant_name="Tailspin Toys")
    importer.import_document(session, users["admin"], later)
    t = importer.tenants(session)[0]
    d = diff.latest_diff(session, t.id)
    assert "credentials" in d.not_comparable and d.new_credentials == []
    assert diff.latest_diff(session, 999) is None


# ---- remediation ------------------------------------------------------------------------------

def test_remediation_candidates(loaded, session):
    r = exports.remediation_candidates(session)
    assert {x["App"] for x in r["dormant_high_risk"]} == {"Litware Scheduler"}  # Litware absent from later report
    assert "Litware Scheduler" in {x["App"] for x in r["unverified_user_consented"]}
    assert {x["App"] for x in r["expired_credentials"]} == {"ASH Internal Reporting"}
    assert {x["App"] for x in r["sp_credentials_on_vendor_apps"]} == {"Northwind Signatures"}
    assert [x["Tenant"] for x in r["users_can_consent"]] == ["Tailspin Toys"]
    wb = load_workbook(io.BytesIO(exports.remediation_xlsx(session)))
    assert set(wb.sheetnames) == set(exports.SHEET_TITLES.values())
