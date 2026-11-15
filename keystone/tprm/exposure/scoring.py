"""Deterministic exposure scoring (no LLM). Rules come from config/exposure_rules.yaml."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache

import yaml

from .paths import CONFIG_DIR
from .permission_catalog import TIER_RANK, at_least, max_tier

LEVEL_ORDER = ["Low", "Medium", "High", "Critical"]
SIGN_IN_SCOPES = {"openid", "profile", "email", "offline_access", "user.read"}


@dataclass(frozen=True)
class Perm:
    permission_type: str  # application | delegated
    value: str
    tier: str
    consent_type: str = "n/a"  # AllPrincipals | Principal | n/a
    resource_name: str | None = None
    user_count: int | None = None


@dataclass(frozen=True)
class Cred:
    owner_type: str
    start: datetime | None
    end: datetime | None


@dataclass
class AppFacts:
    owner_class: str
    publisher_verified: bool
    permissions: list[Perm]
    credentials: list[Cred] | None  # None = credential data unavailable
    sign_in_available: bool
    last_sign_in: datetime | None
    reference_time: datetime
    missing_datasets: list[str] = field(default_factory=list)


@dataclass
class Exposure:
    level: str
    has_app_only: bool
    max_permission_tier: str | None
    admin_consented: bool
    user_consent_count: int
    dormant: bool | None
    credential_flags: dict | None
    incomplete_data: bool
    reasons: list[dict]


@dataclass(frozen=True)
class RuleSet:
    rules: list[dict]
    modifiers: list[dict]
    dormant_days: int
    long_lived_months: int
    expiring_soon_days: int


@lru_cache(maxsize=4)
def load_rules(path: str | None = None) -> RuleSet:
    d = yaml.safe_load(open(path or CONFIG_DIR / "exposure_rules.yaml", encoding="utf-8"))
    rules = d["rules"]
    if not any(r["when"].get("always") for r in rules):
        raise ValueError("exposure rules need a final 'always' fallback rule")
    for r in rules:
        if r["level"] not in LEVEL_ORDER:
            raise ValueError(f"rule {r['id']}: unknown level {r['level']}")
    return RuleSet(rules, d.get("modifiers", []), int(d["dormant_days"]), int(d["long_lived_credential_months"]), int(d["expiring_soon_days"]))


# ---- condition evaluation ------------------------------------------------------------

def _perm_matches(p: Perm, cond: dict) -> bool:
    if "permission_type" in cond and p.permission_type != cond["permission_type"]:
        return False
    if "min_tier" in cond and not at_least(p.tier, cond["min_tier"]):
        return False
    if "max_tier" in cond and TIER_RANK[p.tier] > TIER_RANK[cond["max_tier"]]:
        return False
    if "consent" in cond:
        want = {"admin": "AllPrincipals", "user": "Principal"}[cond["consent"]]
        if p.consent_type != want:
            return False
    return True


def evaluate(cond: dict, facts: AppFacts) -> tuple[bool, list[Perm]]:
    """Return (matched, permissions that satisfied it). Keys at one level are AND-ed."""
    evidence: list[Perm] = []
    for key, val in cond.items():
        if key == "always":
            ok = bool(val)
        elif key == "publisher_verified":
            ok = facts.publisher_verified is bool(val)
        elif key == "any_permission":
            hits = [p for p in facts.permissions if _perm_matches(p, val)]
            ok = bool(hits)
            evidence += hits
        elif key == "all_permissions":
            ok = bool(facts.permissions) and all(_perm_matches(p, val) for p in facts.permissions)
            evidence += facts.permissions if ok else []
        elif key == "any_of":
            results = [evaluate(c, facts) for c in val]
            ok = any(r[0] for r in results)
            for matched, ev in results:
                if matched:
                    evidence += ev
        else:
            raise ValueError(f"unknown rule condition {key!r}")
        if not ok:
            return False, []
    return True, evidence


def _describe(perms: list[Perm]) -> str:
    seen = []
    for p in perms:
        label = f"{p.value}" + (f" on {p.resource_name}" if p.resource_name else "")
        if label not in seen:
            seen.append(label)
    return ", ".join(seen[:6]) + (f" and {len(seen) - 6} more" if len(seen) > 6 else "")


# ---- scoring ---------------------------------------------------------------------------------

def credential_flags(creds: list[Cred] | None, ref: datetime, rules: RuleSet, owner_class: str) -> dict | None:
    if creds is None:
        return None
    soon = ref + timedelta(days=rules.expiring_soon_days)
    long_days = rules.long_lived_months * 30.44
    flags = {
        "expired_present": any(c.end and c.end < ref for c in creds),
        "expiring_30d": any(c.end and ref <= c.end <= soon for c in creds),
        "long_lived": any(c.start and c.end and (c.end - c.start).days > long_days for c in creds),
        "sp_credential_on_third_party": owner_class in ("third_party", "unknown") and any(c.owner_type == "servicePrincipal" for c in creds),
    }
    return flags


def score(facts: AppFacts, rules: RuleSet | None = None) -> Exposure:
    rules = rules or load_rules()
    reasons: list[dict] = []
    level = None
    for rule in rules.rules:
        matched, evidence = evaluate(rule["when"], facts)
        if not matched:
            continue
        text = rule["text"] + (f" ({_describe(evidence)})" if evidence else "")
        if level is None:
            level = rule["level"]
            reasons.append({"rule_id": rule["id"], "text": f"{text} → {level}."})
        elif not rule["when"].get("always"):
            reasons.append({"rule_id": rule["id"], "text": f"Also matches: {text}"})

    app_only = [p for p in facts.permissions if p.permission_type == "application"]
    admin = any(p.consent_type == "AllPrincipals" for p in facts.permissions)
    user_count = max((p.user_count or 0 for p in facts.permissions if p.consent_type == "Principal"), default=0)

    # Dormancy: unknown (None) whenever sign-in data is unavailable. Never treat unknown as dormant.
    if not facts.sign_in_available:
        dormant = None
        reasons.append({"rule_id": "D0", "text": "Sign-in activity was not available for this tenant, so dormancy is unknown."})
    elif facts.last_sign_in is None:
        dormant = True
        reasons.append({"rule_id": "D1", "text": "No sign-in recorded in the activity report: likely unused."})
    else:
        idle = (facts.reference_time - facts.last_sign_in).days
        dormant = idle > rules.dormant_days
        if dormant:
            reasons.append({"rule_id": "D2", "text": f"Last sign-in {idle} days before collection (threshold {rules.dormant_days})."})

    flags = credential_flags(facts.credentials, facts.reference_time, rules, facts.owner_class)
    if flags:
        if flags["expired_present"]:
            reasons.append({"rule_id": "C1", "text": "Expired credentials are still attached; remove them."})
        if flags["expiring_30d"]:
            reasons.append({"rule_id": "C2", "text": f"A credential expires within {rules.expiring_soon_days} days."})
        if flags["long_lived"]:
            reasons.append({"rule_id": "C3", "text": f"A credential is valid for longer than {rules.long_lived_months} months."})
        if flags["sp_credential_on_third_party"]:
            reasons.append({"rule_id": "C4", "text": "A secret or certificate was added to this third-party app's service principal in your tenant; confirm who added it (a known persistence technique)."})
    if not facts.publisher_verified and facts.owner_class in ("third_party", "unknown"):
        reasons.append({"rule_id": "P1", "text": "Publisher is not verified by Microsoft."})

    incomplete = bool(facts.missing_datasets)
    if incomplete:
        for m in rules.modifiers:
            if m.get("flag") == "incomplete_data":
                reasons.append({"rule_id": m["id"], "text": m["text"].format(datasets=", ".join(facts.missing_datasets))})

    return Exposure(
        level=level or "Low",
        has_app_only=bool(app_only),
        max_permission_tier=max_tier(p.tier for p in facts.permissions),
        admin_consented=admin,
        user_consent_count=user_count,
        dormant=dormant,
        credential_flags=flags,
        incomplete_data=incomplete,
        reasons=reasons,
    )


def only_sign_in_scopes(perms: list[Perm]) -> bool:
    return all(p.permission_type == "delegated" and p.value.lower() in SIGN_IN_SCOPES for p in perms)
