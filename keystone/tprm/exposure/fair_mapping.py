"""Turn a vendor's Entra exposure into FAIR input SUGGESTIONS for a vendor assessment.

Suggestions never change an assessment until a person accepts them. TEF is never inferred.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.db import utcnow
from keystone.core.services import authorize, get_or_404
from keystone.tprm.models import VendorAssessment

from .inventory import latest_apps, latest_snapshot_ids, mappings, worst
from .models import ConsentPosture, FairSuggestion
from .paths import CONFIG_DIR
from .permission_catalog import at_least


@lru_cache(maxsize=2)
def load_config(path: str | None = None) -> dict:
    return yaml.safe_load(open(path or CONFIG_DIR / "fair_suggestions.yaml", encoding="utf-8"))


@dataclass
class VendorExposure:
    tenant_id: int
    snapshot_id: int
    app_names: list[str]
    worst_level: str | None
    integration_depth: str
    depth_reason: dict
    publisher_all_verified: bool | None
    risky_credentials: bool | None
    users_can_consent: bool | None
    admin_consent_workflow_enabled: bool | None
    app_reasons: dict[str, list[dict]] = field(default_factory=dict)


def summarize(session: Session, vendor_id: int, tenant_id: int) -> VendorExposure | None:
    cfg = load_config()
    snaps = latest_snapshot_ids(session)
    if tenant_id not in snaps:
        return None
    owners = {oid for oid, m in mappings(session).items() if m.status == "confirmed" and m.vendor_id == vendor_id}
    apps = [a for a in latest_apps(session, ("third_party",), tenant_id) if a.owner_org_id in owners]
    if not apps:
        return None
    perms = [p for a in apps for p in a.permissions]
    sign_in = {s.lower() for s in cfg["sign_in_scopes"]}
    app_only = [p for p in perms if p.permission_type == "application"]
    beyond_sign_in = [p for p in perms if p.permission_type == "delegated" and p.value.lower() not in sign_in]
    depth = cfg["integration_depth"]
    if any(at_least(p.tier, "high") for p in app_only):
        d, r = depth["tenant_wide"], {"rule_id": "ID1", "text": "Holds app-only (application) permissions at high or critical tier: " + ", ".join(sorted({p.value for p in app_only if at_least(p.tier, 'high')}))}
    elif app_only:
        d, r = depth["tenant_wide"], {"rule_id": "ID1b", "text": "Holds app-only permissions (tenant-wide by nature, lower tier): " + ", ".join(sorted({p.value for p in app_only}))}
    elif beyond_sign_in:
        d, r = depth["delegated"], {"rule_id": "ID2", "text": "Only delegated permissions, beyond sign-in scopes: " + ", ".join(sorted({p.value for p in beyond_sign_in})[:8])}
    else:
        d, r = depth["sso_only"], {"rule_id": "ID3", "text": "Only sign-in scopes (or no API permissions)."}
    flags = [a.exposure.credential_flags for a in apps if a.exposure]
    if any(f and (f["expired_present"] or f["long_lived"]) for f in flags):
        risky = True
    elif any(f is None for f in flags):
        risky = None
    else:
        risky = False
    cp = session.scalar(select(ConsentPosture).where(ConsentPosture.snapshot_id == snaps[tenant_id]))
    return VendorExposure(
        tenant_id=tenant_id,
        snapshot_id=snaps[tenant_id],
        app_names=sorted(a.display_name or a.app_id for a in apps),
        worst_level=worst(a.exposure.exposure_level for a in apps if a.exposure),
        integration_depth=d,
        depth_reason=r,
        publisher_all_verified=all(a.publisher_verified for a in apps),
        risky_credentials=risky,
        users_can_consent=cp.users_can_consent if cp else None,
        admin_consent_workflow_enabled=cp.admin_consent_workflow_enabled if cp else None,
        app_reasons={a.display_name or a.app_id: (a.exposure.reasons if a.exposure else []) for a in apps},
    )


def _clamp(x: float) -> float:
    return round(min(1.0, max(0.0, x)), 4)


def compute(assessment: VendorAssessment, ex: VendorExposure) -> list[dict]:
    """Suggested values for integration_depth, plm, slm and control_strength (never tef)."""
    cfg = load_config()
    out = []
    out.append({"field": "integration_depth", "current": assessment.integration_depth, "suggested": ex.integration_depth, "rule_ids": [ex.depth_reason["rule_id"]], "reasons": [ex.depth_reason]})
    if ex.worst_level:
        lm = cfg["loss_magnitude"][ex.worst_level]
        why = {"rule_id": f"LM-{ex.worst_level}", "text": f"Worst exposure of this vendor's apps in the tenant is {ex.worst_level}; range from fair_suggestions.yaml (calibration starting point)."}
        out.append({"field": "plm", "current": assessment.plm, "suggested": {k: float(v) for k, v in lm["plm"].items()}, "rule_ids": [why["rule_id"]], "reasons": [why]})
        out.append({"field": "slm", "current": assessment.slm, "suggested": {k: float(v) for k, v in lm["slm"].items()}, "rule_ids": [why["rule_id"]], "reasons": [why]})
    base = assessment.control_strength or cfg["control_strength_default"]
    shift, rule_ids, reasons = 0.0, [], []
    inputs = {
        "users_can_consent": ex.users_can_consent,
        "admin_consent_workflow_enabled": ex.admin_consent_workflow_enabled,
        "publisher_verified": ex.publisher_all_verified,
        "risky_credentials_present": ex.risky_credentials,
    }
    for key, adj in cfg["control_strength_adjustments"].items():
        value = inputs[key]
        if value is None:
            reasons.append({"rule_id": adj["rule_id"], "text": f"{adj['text']} Unknown for this tenant: no adjustment."})
        elif value == adj["when"]:
            shift += adj["shift"]
            rule_ids.append(adj["rule_id"])
            reasons.append({"rule_id": adj["rule_id"], "text": f"{adj['text']} Shift {adj['shift']:+.2f}."})
    if rule_ids:
        suggested = {k: _clamp(float(base[k]) + shift) for k in ("min", "ml", "max")}
        out.append({"field": "control_strength", "current": assessment.control_strength, "suggested": suggested, "rule_ids": rule_ids, "reasons": reasons})
    return [s for s in out if s["suggested"] != s["current"]]


def generate(session: Session, actor, assessment_id: int) -> list[FairSuggestion]:
    authorize(session, actor, "vendor.write")
    a = get_or_404(session, VendorAssessment, assessment_id)
    if a.entra_tenant_id is None:
        raise ValueError("Scope the assessment to an Entra tenant to get exposure-based suggestions.")
    ex = summarize(session, a.vendor_id, a.entra_tenant_id)
    if ex is None:
        raise ValueError("No confirmed apps for this vendor in the tenant's latest snapshot.")
    for old in session.scalars(select(FairSuggestion).where(FairSuggestion.assessment_id == a.id, FairSuggestion.status == "pending")):
        session.delete(old)
    created = []
    for s in compute(a, ex):
        fs = FairSuggestion(assessment_id=a.id, snapshot_id=ex.snapshot_id, field=s["field"], current_value=s["current"], suggested_value=s["suggested"], rule_ids=s["rule_ids"], reasons=s["reasons"], status="pending")
        session.add(fs)
        created.append(fs)
    session.flush()
    return created


def _decide(session: Session, actor, suggestion_id: int, accept: bool) -> FairSuggestion:
    authorize(session, actor, "vendor.write")
    s = get_or_404(session, FairSuggestion, suggestion_id)
    if s.status != "pending":
        raise ValueError("This suggestion has already been decided.")
    a = get_or_404(session, VendorAssessment, s.assessment_id)
    if accept:
        if a.status != "draft":
            raise ValueError("Suggestions can only be applied to draft assessments.")
        setattr(a, s.field, s.suggested_value)
    s.status = "accepted" if accept else "rejected"
    s.decided_by, s.decided_at = actor.username, utcnow()
    session.flush()
    return s


def accept(session: Session, actor, suggestion_id: int) -> FairSuggestion:
    return _decide(session, actor, suggestion_id, True)


def reject(session: Session, actor, suggestion_id: int) -> FairSuggestion:
    return _decide(session, actor, suggestion_id, False)


def accept_all(session: Session, actor, assessment_id: int) -> int:
    pending = list(session.scalars(select(FairSuggestion).where(FairSuggestion.assessment_id == assessment_id, FairSuggestion.status == "pending")))
    for s in pending:
        accept(session, actor, s.id)
    return len(pending)


def suggestions_for(session: Session, assessment_id: int) -> list[FairSuggestion]:
    return list(session.scalars(select(FairSuggestion).where(FairSuggestion.assessment_id == assessment_id).order_by(FairSuggestion.id.desc())))
