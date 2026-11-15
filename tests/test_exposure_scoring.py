"""Phase 6: permission catalog and deterministic exposure scoring."""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from keystone.tprm.exposure import importer, permission_catalog as cat, scoring
from keystone.tprm.exposure.models import TenantApp
from keystone.tprm.exposure.scoring import AppFacts, Cred, Perm

REF = datetime(2026, 10, 1, 12, 0)


@pytest.mark.parametrize(
    "value,tier",
    [("Directory.ReadWrite.All", "critical"), ("directory.readwrite.all", "critical"), ("full_access_as_app", "critical"), ("Mail.Read", "high"), ("Mail.ReadBasic.All", "high"), ("User.Read.All", "medium"), ("openid", "low"), ("Some.Unknown.Permission", "medium"), (None, "medium")],
)
def test_tier_for(value, tier):
    assert cat.tier_for(value) == tier


def test_max_tier_and_at_least():
    assert cat.max_tier(["low", "critical", "medium"]) == "critical"
    assert cat.max_tier([]) is None
    assert cat.at_least("high", "medium") and not cat.at_least("medium", "high")


def facts(perms, verified=False, creds=(), sign_in=True, last=REF - timedelta(days=1), owner="third_party", missing=()):
    return AppFacts(owner, verified, list(perms), None if creds is None else list(creds), sign_in, last, REF, list(missing))


APP_CRIT = Perm("application", "Files.ReadWrite.All", "critical", resource_name="Microsoft Graph")
APP_HIGH = Perm("application", "Mail.Read", "high")
APP_MED = Perm("application", "User.Read.All", "medium")
DEL_CRIT_ADMIN = Perm("delegated", "Mail.Send", "critical", "AllPrincipals")
DEL_CRIT_USER = Perm("delegated", "Mail.Send", "critical", "Principal", user_count=3)
DEL_HIGH_USER = Perm("delegated", "Calendars.ReadWrite", "high", "Principal", user_count=9)
DEL_LOW = Perm("delegated", "openid", "low", "Principal", user_count=2)


@pytest.mark.parametrize(
    "perms,verified,level,rule",
    [
        ([APP_CRIT], True, "Critical", "R1"),
        ([DEL_CRIT_ADMIN], False, "Critical", "R2"),
        ([APP_HIGH], False, "High", "R3"),
        ([DEL_CRIT_ADMIN], True, "High", "R4"),
        ([DEL_HIGH_USER], False, "High", "R5"),
        ([APP_MED], False, "Medium", "R6"),
        ([DEL_HIGH_USER], True, "Medium", "R6"),
        ([DEL_CRIT_USER], True, "Medium", "R6"),  # delegated critical, user consent, verified: "high or above"
        ([DEL_LOW], False, "Low", "R7"),
        ([], False, "Low", "R8"),
        ([Perm("delegated", "Calendars.Read", "medium", "Principal")], False, "Low", "R8"),
        ([APP_HIGH, APP_CRIT, DEL_LOW], False, "Critical", "R1"),  # first match wins
    ],
)
def test_rules(perms, verified, level, rule):
    ex = scoring.score(facts(perms, verified))
    assert ex.level == level
    assert ex.reasons[0]["rule_id"] == rule
    assert ex.reasons[0]["text"].endswith(f"→ {level}.")


def test_all_matching_rules_are_recorded():
    ex = scoring.score(facts([APP_CRIT, DEL_HIGH_USER]))
    ids = [r["rule_id"] for r in ex.reasons]
    assert ids[:4] == ["R1", "R3", "R5", "R6"]
    assert "Files.ReadWrite.All on Microsoft Graph" in ex.reasons[0]["text"]


def test_dormancy_tristate():
    assert scoring.score(facts([], sign_in=False, last=None)).dormant is None
    assert scoring.score(facts([], sign_in=True, last=None)).dormant is True
    assert scoring.score(facts([], last=REF - timedelta(days=91))).dormant is True
    assert scoring.score(facts([], last=REF - timedelta(days=90))).dormant is False
    reasons = {r["rule_id"] for r in scoring.score(facts([], sign_in=False, last=None)).reasons}
    assert "D0" in reasons


def test_credential_flags():
    creds = [Cred("application", REF - timedelta(days=800), REF - timedelta(days=1)), Cred("application", REF, REF + timedelta(days=10)), Cred("servicePrincipal", REF - timedelta(days=10), REF + timedelta(days=900))]
    f = scoring.score(facts([], creds=creds)).credential_flags
    assert f == {"expired_present": True, "expiring_30d": True, "long_lived": True, "sp_credential_on_third_party": True}
    assert scoring.score(facts([], creds=[])).credential_flags == {"expired_present": False, "expiring_30d": False, "long_lived": False, "sp_credential_on_third_party": False}
    assert scoring.score(facts([], creds=None)).credential_flags is None
    internal = scoring.score(facts([], creds=[Cred("servicePrincipal", REF, REF + timedelta(days=5))], owner="internal")).credential_flags
    assert internal["sp_credential_on_third_party"] is False


def test_incomplete_data_modifier_does_not_change_level():
    ex = scoring.score(facts([APP_HIGH], missing=["credentials"]))
    assert ex.level == "High" and ex.incomplete_data
    r0 = next(r for r in ex.reasons if r["rule_id"] == "R0")
    assert "credentials" in r0["text"]


def test_aggregates():
    ex = scoring.score(facts([APP_MED, DEL_CRIT_ADMIN, DEL_HIGH_USER, DEL_LOW], verified=True))
    assert ex.has_app_only and ex.admin_consented and ex.user_consent_count == 9 and ex.max_permission_tier == "critical"


def test_unknown_condition_rejected():
    with pytest.raises(ValueError, match="unknown rule condition"):
        scoring.evaluate({"magic": True}, facts([]))


def test_fixture_levels(users, session, tenant_a):
    res = importer.import_document(session, users["admin"], tenant_a, create_tenant_name="Alpine Ski House")
    apps = {a.display_name: a.exposure for a in session.scalars(select(TenantApp).where(TenantApp.snapshot_id == res.snapshot_id))}
    expected = {
        "Fabrikam Backup for Microsoft 365": ("Critical", "R1"),
        "Proseware PDF Tools": ("Critical", "R2"),
        "Northwind Signatures": ("High", "R3"),
        "Wingtip HR Sync": ("High", "R4"),
        "Litware Scheduler": ("High", "R5"),
        "Legacy Print Connector": ("Medium", "R6"),
        "ASH Internal Reporting": ("Medium", "R6"),
        "Adatum Survey": ("Low", "R7"),
        "Relecloud Wiki (SAML)": ("Low", "R8"),
    }
    for name, (level, rule) in expected.items():
        assert (apps[name].exposure_level, apps[name].reasons[0]["rule_id"]) == (level, rule), name
    assert apps["Litware Scheduler"].dormant is True       # last sign-in 153 days before collection
    assert apps["Adatum Survey"].dormant is True            # absent from a successful report
    assert apps["Fabrikam Backup for Microsoft 365"].dormant is False
    assert apps["Northwind Signatures"].credential_flags["sp_credential_on_third_party"] is True
    assert apps["ASH Internal Reporting"].credential_flags == {"expired_present": True, "expiring_30d": True, "long_lived": True, "sp_credential_on_third_party": False}
    assert all(r["text"] for e in apps.values() for r in e.reasons)
