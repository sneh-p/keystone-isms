"""Phase 1: fixtures validate, and the schema rejects data that must never appear."""

import json
import re
from pathlib import Path

import pytest
import yaml

from keystone.tprm.exposure.schema import validation_errors

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_FILES = sorted((ROOT / "tests" / "fixtures").glob("collected_*.json"))


def test_three_fixtures_exist():
    assert {p.name for p in FIXTURE_FILES} == {
        "collected_tenant_a.json",
        "collected_tenant_a_later.json",
        "collected_tenant_b_no_p1.json",
    }


@pytest.mark.parametrize("path", FIXTURE_FILES, ids=lambda p: p.name)
def test_fixture_validates(path):
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert validation_errors(doc) == []


@pytest.mark.parametrize("path", FIXTURE_FILES, ids=lambda p: p.name)
def test_fixture_contains_no_forbidden_keys(path):
    text = path.read_text(encoding="utf-8")
    for forbidden in ('"hint"', '"principalId"', '"secretText"', '"key"', '"accessToken"'):
        assert forbidden not in text
    assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}", text), "looks like a JWT"


def test_fixtures_only_use_fictional_domains():
    for path in FIXTURE_FILES:
        domains = re.findall(r"https?://([^/\"]+)", path.read_text(encoding="utf-8"))
        assert all(d.endswith(".example") for d in domains), domains


def test_tenant_b_distinguishes_null_from_empty(tenant_b):
    assert tenant_b["signin_activity"] is None
    assert tenant_b["credentials"] is None
    es = tenant_b["metadata"]["endpoint_status"]
    assert es["signin_activity"]["status"] == "unavailable_license"
    assert es["credentials.applications"]["status"] == "forbidden"
    assert tenant_b["metadata"]["entra_p1_available"] is False


# ---- negative cases -------------------------------------------------------------

def test_rejects_password_hint(tenant_a):
    tenant_a["credentials"][0]["hint"] = "abc"
    assert any("hint" in e for e in validation_errors(tenant_a))


def test_rejects_user_principal_id_in_grants(tenant_a):
    tenant_a["delegated_grants"][0]["principalId"] = "11111111-1111-1111-1111-111111111111"
    assert validation_errors(tenant_a)


def test_rejects_unknown_endpoint_status(tenant_a):
    tenant_a["metadata"]["endpoint_status"]["tenant"]["status"] = "maybe"
    assert validation_errors(tenant_a)


def test_rejects_missing_dataset_key(tenant_a):
    del tenant_a["signin_activity"]
    assert validation_errors(tenant_a)


def test_accepts_null_and_empty_datasets(tenant_a):
    tenant_a["delegated_grants"] = []
    tenant_a["app_role_assignments"] = None
    assert validation_errors(tenant_a) == []


# ---- config files ----------------------------------------------------------------

def test_config_files_parse():
    cfg = ROOT / "config"
    owners = json.loads((cfg / "microsoft_owner_tenants.json").read_text())
    ids = {t["id"] for t in owners["tenant_ids"]}
    assert {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"} <= ids

    tiers = yaml.safe_load((cfg / "permission_tiers.yaml").read_text())
    assert tiers["default_unlisted"] == "medium"
    all_values = [v.lower() for t in ("critical", "high", "medium", "low") for v in tiers[t]]
    assert len(all_values) == len(set(all_values)), "a permission is listed in two tiers"

    rules = yaml.safe_load((cfg / "exposure_rules.yaml").read_text())
    assert [r["id"] for r in rules["rules"]] == ["R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8"]
    assert rules["dormant_days"] == 90

    fair = yaml.safe_load((cfg / "fair_suggestions.yaml").read_text())
    assert set(fair["loss_magnitude"]) == {"Critical", "High", "Medium", "Low"}
    for level in fair["loss_magnitude"].values():
        for rng in level.values():
            assert rng["min"] <= rng["ml"] <= rng["max"]
