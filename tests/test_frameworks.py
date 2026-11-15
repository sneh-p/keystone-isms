"""Phase 2: framework packs, common controls, crosswalk, licensing guard, coverage."""

import copy
import re

import pytest
from sqlalchemy import func, select

from keystone.core.rbac import PermissionDenied
from keystone.frameworks import loader, service
from keystone.frameworks.models import CommonControl, ControlMapping, Framework, Requirement

EXPECTED_LEAVES = {"NIST_CSF_2_0": 106, "ISO27001_2022": 93 + 30, "SOC2_TSC_2017": 61, "CIS_V8_1": 153}


def _leaf_count(s, code):
    fw = service.framework_by_code(s, code)
    return s.scalar(select(func.count()).select_from(Requirement).where(Requirement.framework_id == fw.id, Requirement.is_leaf.is_(True)))


def test_pack_sizes(content, session):
    for code, n in EXPECTED_LEAVES.items():
        assert _leaf_count(session, code) == n, code
    fw = service.framework_by_code(session, "ISO27001_2022")
    annex = [r for r in fw.requirements if r.kind == "annex_control"]
    assert len(annex) == 93
    assert {r.ref.split(".")[1] for r in annex} == {"5", "6", "7", "8"}
    assert session.scalar(select(func.count(CommonControl.id))) == 107


@pytest.mark.parametrize("code", list(EXPECTED_LEAVES))
def test_every_leaf_requirement_is_mapped(content, session, code):
    rows = service.coverage(session, service.framework_by_code(session, code).id)
    unmapped = [r.requirement.ref for r in rows if not r.controls]
    assert unmapped == []


def test_every_control_maps_to_iso_and_something_else(content, session):
    for c in service.controls(session):
        fws = service.requirements_for_control(c)
        assert "ISO27001_2022" in fws, c.code
    # Most controls should also satisfy at least one other framework.
    multi = [c for c in service.controls(session) if len(service.requirements_for_control(c)) > 1]
    assert len(multi) >= 90


def test_reload_is_idempotent(content, db, users):
    with db.session_scope(users["admin"]) as s:
        before = s.scalar(select(func.count(ControlMapping.id)))
        loader.seed_content(s, users["admin"])
        assert s.scalar(select(func.count(ControlMapping.id))) == before
        assert s.scalar(select(func.count(Framework.id))) == 4


def test_seed_requires_permission(db, users):
    with db.session_scope() as s:
        with pytest.raises(PermissionDenied):
            loader.seed_content(s, users["viewer"])


# ---- licensing guard ---------------------------------------------------------------

@pytest.mark.parametrize("name", loader.PACK_FILES)
def test_bundled_packs_pass_licence_check(name):
    doc = loader.read_yaml(loader.CONTENT_DIR / name)
    loader.check_pack(doc, name)
    fw = doc["framework"]
    if fw["license"] != "public_domain":
        assert fw["text_level"] == "summary"
        assert all(len(r["title"]) <= 80 for r in doc["requirements"]), "restricted titles should be short"
        assert all(not r.get("description") for r in doc["requirements"])


def test_restricted_pack_with_long_text_rejected():
    doc = copy.deepcopy(loader.read_yaml(loader.CONTENT_DIR / "iso27001_2022.yaml"))
    doc["requirements"][5]["description"] = "x" * 200
    with pytest.raises(loader.ContentError, match="longer than"):
        loader.check_pack(doc)
    doc = copy.deepcopy(loader.read_yaml(loader.CONTENT_DIR / "cis_v8_1.yaml"))
    doc["framework"]["text_level"] = "full"
    with pytest.raises(loader.ContentError, match="summary"):
        loader.check_pack(doc)


def test_licensed_text_key_never_allowed_in_files():
    doc = copy.deepcopy(loader.read_yaml(loader.CONTENT_DIR / "nist_csf_2_0.yaml"))
    doc["requirements"][1]["licensed_text"] = "x"
    with pytest.raises(loader.ContentError, match="never be stored"):
        loader.check_pack(doc)


def test_crosswalk_refs_exist_and_are_well_formed():
    cw = loader.read_yaml(loader.CONTENT_DIR / "crosswalk.yaml")
    ctl_codes = {c["code"] for c in loader.read_yaml(loader.CONTENT_DIR / "common_controls.yaml")["controls"]}
    for fw, mapping in cw.items():
        for ref, codes in mapping.items():
            assert codes and set(codes) <= ctl_codes, (fw, ref)
            assert len(codes) == len(set(codes)), (fw, ref)
    assert all(re.fullmatch(r"KC-(GOV|ORG|PPL|PHY|TEC)-\d{2}", c) for c in ctl_codes)


def test_unknown_crosswalk_ref_rejected(content, db, users):
    with db.session_scope(users["admin"]) as s:
        with pytest.raises(loader.ContentError, match="unknown requirement"):
            loader.load_controls(s, users["admin"], {"controls": []}, {"CIS_V8_1": {"99.9": ["KC-TEC-01"]}})


# ---- licensed text import --------------------------------------------------------------

def test_import_licensed_text(content, session, users):
    rows = loader.parse_licensed_file("iso.csv", b"ref,text\nA.5.1,Official wording here\nZ.9,nope\n")
    res = loader.import_licensed_text(session, users["admin"], "ISO27001_2022", rows)
    assert res == {"updated": 1, "unknown_refs": ["Z.9"]}
    req = session.scalar(select(Requirement).where(Requirement.ref == "A.5.1"))
    assert req.licensed_text == "Official wording here"


# ---- coverage --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "statuses,expected",
    [
        ([], "unmapped"),
        (["not_applicable"], "not_applicable"),
        (["implemented", "not_applicable"], "implemented"),
        (["implemented", "planned"], "partial"),
        (["partial"], "partial"),
        (["planned", "not_started"], "not_implemented"),
    ],
)
def test_derive_status(statuses, expected):
    assert service.derive_status(statuses) == expected


def test_coverage_moves_with_control_status(content, session):
    fw = service.framework_by_code(session, "CIS_V8_1")
    before = service.coverage_summary(service.coverage(session, fw.id))
    assert before["implemented_pct"] == 0.0
    service.control_by_code(session, "KC-TEC-08").status = "implemented"  # vulnerability mgmt
    session.flush()
    after = service.coverage_summary(service.coverage(session, fw.id))
    assert after["implemented_pct"] > 0
    rows = {r.requirement.ref: r.status for r in service.coverage(session, fw.id)}
    assert rows["7.1"] == "implemented" and rows["2.2"] == "partial"


def test_user_mapping(content, session, users):
    ctl = service.control_by_code(session, "KC-TEC-01")
    group = session.scalar(select(Requirement).where(Requirement.ref == "PR.AA"))
    with pytest.raises(ValueError, match="groupings"):
        service.add_user_mapping(session, users["admin"], ctl.id, group.id)
    leaf = session.scalar(select(Requirement).where(Requirement.ref == "PR.AA-03"))
    m = service.add_user_mapping(session, users["admin"], ctl.id, leaf.id)
    assert m.source == "user"
    with pytest.raises(PermissionDenied):
        service.add_user_mapping(session, users["viewer"], ctl.id, leaf.id)
