"""Remediation candidates and exposure exports (XLSX)."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from sqlalchemy.orm import Session

from keystone.reporting.exports import xlsx

from .importer import tenants
from .inventory import latest_apps, latest_snapshot_ids
from .models import ConsentPosture, ExposureSnapshot


def remediation_candidates(session: Session) -> dict[str, list[dict]]:
    names = {t.id: t.name for t in tenants(session)}
    apps = latest_apps(session, ("third_party", "unknown", "internal"))
    out: dict[str, list[dict]] = {"dormant_high_risk": [], "unverified_user_consented": [], "expired_credentials": [], "users_can_consent": [], "sp_credentials_on_vendor_apps": []}
    for a in apps:
        ex = a.exposure
        if ex is None:
            continue
        row = {"Tenant": names[a.snapshot.tenant_id], "App": a.display_name, "Owner class": a.owner_class, "Exposure": ex.exposure_level, "App ID": a.app_id}
        if a.owner_class != "internal" and ex.dormant is True and ex.exposure_level in ("High", "Critical"):
            out["dormant_high_risk"].append({**row, "Last sign-in": a.last_sign_in_utc.strftime("%Y-%m-%d") if a.last_sign_in_utc else "none recorded"})
        if a.owner_class != "internal" and not a.publisher_verified and ex.user_consent_count > 0:
            out["unverified_user_consented"].append({**row, "Users consented (max per resource)": ex.user_consent_count})
        if ex.credential_flags and ex.credential_flags.get("expired_present"):
            out["expired_credentials"].append({**row, "Expired": ", ".join(c.display_name or c.key_id for c in a.credentials if c.status == "expired")})
        if ex.credential_flags and ex.credential_flags.get("sp_credential_on_third_party"):
            out["sp_credentials_on_vendor_apps"].append({**row, "Credentials": ", ".join(c.display_name or c.key_id for c in a.credentials if c.owner_type == "servicePrincipal")})
    for tid, sid in latest_snapshot_ids(session).items():
        snap = session.get(ExposureSnapshot, sid)
        cp: ConsentPosture | None = snap.consent if snap else None
        if cp and cp.users_can_consent:
            out["users_can_consent"].append({"Tenant": names[tid], "Policies": ", ".join(cp.permission_grant_policies_raw or []), "Admin consent workflow": {True: "enabled", False: "disabled", None: "unknown"}[cp.admin_consent_workflow_enabled]})
    return out


SHEET_TITLES = {
    "dormant_high_risk": "Dormant High-Critical",
    "unverified_user_consented": "Unverified user-consented",
    "expired_credentials": "Expired credentials",
    "sp_credentials_on_vendor_apps": "Creds on vendor apps",
    "users_can_consent": "Users can consent",
}


def remediation_xlsx(session: Session) -> bytes:
    data = remediation_candidates(session)
    sheets: dict[str, tuple[Sequence[str], Iterable[Sequence[Any]]]] = {}
    for key, title in SHEET_TITLES.items():
        rows = data[key]
        headers = list(rows[0]) if rows else ["(none found)"]
        sheets[title] = (headers, [list(r.values()) for r in rows])
    return xlsx(sheets)
