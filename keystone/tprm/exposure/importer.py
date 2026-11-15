"""Import collected.json into Keystone. The Streamlit app never talks to Microsoft Graph."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.audit import log_event
from keystone.core.db import utcnow
from keystone.core.services import authorize

from . import classification, scoring
from .models import AppCredential, AppExposure, AppPermission, ConsentPosture, EntraTenant, ExposureSnapshot, TenantApp
from .permission_catalog import tier_for
from .schema import CollectedFileInvalid, validate_collected

MAX_FILE_BYTES = 50 * 1024 * 1024
DATASETS = ("tenant", "licensing", "consent_posture", "service_principals", "app_role_assignments", "delegated_grants", "credentials", "signin_activity")
BAD_STATUSES = ("forbidden", "error")


class DuplicateSnapshot(ValueError):
    pass


class UnknownTenant(LookupError):
    pass


def parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def load_document(data: bytes) -> dict:
    if len(data) > MAX_FILE_BYTES:
        raise CollectedFileInvalid([f"file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB"])
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise CollectedFileInvalid([f"not valid JSON: {e}"]) from None
    validate_collected(doc)
    return doc


def status_ok(endpoint_status: dict, key: str) -> bool:
    """Was this dataset collected successfully? Composite datasets need all their endpoints."""
    if key == "credentials":
        return all(endpoint_status.get(k, {}).get("status") == "ok" for k in ("credentials.applications", "credentials.service_principals"))
    if key == "consent_posture":
        return all(endpoint_status.get(k, {}).get("status") == "ok" for k in ("consent_posture.authorization_policy", "consent_posture.admin_consent_request_policy"))
    return endpoint_status.get(key, {}).get("status") == "ok"


@dataclass
class Preview:
    tenant_id: str
    tenant_name: str
    default_domain: str | None
    collected_at: datetime
    operator: str
    write_scopes_present: bool
    entra_p1_available: bool | None
    counts: dict[str, int | None]
    endpoint_status: dict
    problems: list[tuple[str, str, str]] = field(default_factory=list)  # (severity, dataset, message)
    existing_tenant: str | None = None
    duplicate: bool = False


def preview(session: Session, doc: dict) -> Preview:
    md = doc["metadata"]
    counts = {k: (None if doc[k] is None else (len(doc[k]) if isinstance(doc[k], list) else 1)) for k in DATASETS}
    problems = []
    for key, st in md["endpoint_status"].items():
        if st["status"] in BAD_STATUSES:
            problems.append(("error", key, f"{st['status']} (HTTP {st['http_status']}): {st['message']}"))
        elif st["status"] == "unavailable_license":
            problems.append(("warning", key, "Not available: the tenant has no Entra ID P1/P2 licence. Dormancy will be shown as unknown."))
        elif st["status"] == "skipped":
            problems.append(("warning", key, f"Skipped: {st['message']}"))
    tenant = session.scalar(select(EntraTenant).where(EntraTenant.entra_tenant_id == md["tenant_id"].lower()))
    collected = parse_dt(md["collected_at_utc"])
    dup = bool(tenant and session.scalar(select(ExposureSnapshot).where(ExposureSnapshot.tenant_id == tenant.id, ExposureSnapshot.collected_at_utc == collected)))
    return Preview(md["tenant_id"].lower(), md["tenant_name"], md.get("default_domain"), collected, md["operator_upn"], md["write_scopes_present"], md["entra_p1_available"], counts, md["endpoint_status"], problems, tenant.name if tenant else None, dup)


def _domain(url: str) -> str | None:
    try:
        host = urlparse(url if "://" in url else f"https://{url}").hostname
    except ValueError:
        return None
    return host.lower() if host else None


def users_can_consent(policies: list[str] | None) -> bool | None:
    if policies is None:
        return None
    return any(p.startswith("ManagePermissionGrantsForSelf.") for p in policies)


@dataclass
class ImportResult:
    snapshot_id: int
    tenant_id: int
    apps: int
    by_class: dict[str, int]
    by_level: dict[str, int]


def import_document(session: Session, actor, doc: dict, create_tenant_name: str | None = None) -> ImportResult:
    """Validate and store a collected.json document, then classify and score every app.

    If the Entra tenant is not known yet, pass create_tenant_name to create it, else UnknownTenant is raised.
    """
    authorize(session, actor, "exposure.import")
    validate_collected(doc)
    md = doc["metadata"]
    es = md["endpoint_status"]
    entra_id = md["tenant_id"].lower()
    tenant = session.scalar(select(EntraTenant).where(EntraTenant.entra_tenant_id == entra_id))
    if tenant is None:
        if not create_tenant_name:
            raise UnknownTenant(f"Entra tenant {entra_id} is not registered in Keystone yet.")
        tenant = EntraTenant(name=create_tenant_name.strip() or md["tenant_name"], entra_tenant_id=entra_id, default_domain=md.get("default_domain"))
        session.add(tenant)
        session.flush()
    collected = parse_dt(md["collected_at_utc"])
    if session.scalar(select(ExposureSnapshot).where(ExposureSnapshot.tenant_id == tenant.id, ExposureSnapshot.collected_at_utc == collected)):
        raise DuplicateSnapshot(f"A snapshot of {tenant.name} collected at {collected:%Y-%m-%d %H:%M} UTC is already imported.")

    snap = ExposureSnapshot(
        tenant_id=tenant.id, collected_at_utc=collected, collector_version=doc["collector_version"], schema_version=doc["schema_version"],
        operator_upn=md["operator_upn"], ticket_number=md.get("ticket_number"), entra_p1_available=md["entra_p1_available"],
        write_scopes_present=md["write_scopes_present"], granted_scopes=md["granted_scopes"], microsoft_owned_skipped_count=md["microsoft_owned_skipped_count"],
        endpoint_status=es, imported_at=utcnow(), imported_by=actor.username,
    )
    session.add(snap)
    session.flush()

    cp = doc["consent_posture"]
    authz = cp["authorization_policy"] if cp else None
    acr = cp["admin_consent_request_policy"] if cp else None
    session.add(ConsentPosture(
        snapshot_id=snap.id,
        users_can_consent=users_can_consent(authz["permissionGrantPoliciesAssigned"] if authz else None),
        permission_grant_policies_raw=authz["permissionGrantPoliciesAssigned"] if authz else None,
        admin_consent_workflow_enabled=acr["isEnabled"] if acr else None,
    ))

    sps = doc["service_principals"] or []
    sp_by_id = {sp["id"]: sp for sp in sps}
    signin = None if doc["signin_activity"] is None else {s["appId"]: s for s in doc["signin_activity"]}
    assignments = doc["app_role_assignments"]
    grants = doc["delegated_grants"]
    creds = doc["credentials"]
    ms_ids = classification.microsoft_owner_ids()
    rules = scoring.load_rules()

    by_class: dict[str, int] = {}
    by_level: dict[str, int] = {}
    for sp in sps:
        owner_class, needs_review = classification.classify(sp["appOwnerOrganizationId"], entra_id, sp["servicePrincipalType"], ms_ids)
        vp = sp.get("verifiedPublisher") or {}
        last = None
        if signin is not None and sp["appId"] in signin:
            row = signin[sp["appId"]]
            stamps = [parse_dt((row.get(k) or {}).get("lastSignInDateTime")) for k in row if k != "appId"]
            stamps = [s for s in stamps if s]
            last = max(stamps) if stamps else None
        domains = sorted({d for d in (_domain(u) for u in [sp.get("homepage") or "", *sp.get("replyUrls", [])] if u) if d})
        app = TenantApp(
            snapshot_id=snap.id, sp_object_id=sp["id"], app_id=sp["appId"], display_name=sp["displayName"], service_principal_type=sp["servicePrincipalType"],
            owner_org_id=(sp["appOwnerOrganizationId"] or None) and sp["appOwnerOrganizationId"].lower(), owner_class=owner_class, needs_review=needs_review,
            publisher_name=sp["publisherName"], verified_publisher_name=vp.get("displayName"), publisher_verified=bool(vp.get("verifiedPublisherId")),
            account_enabled=sp["accountEnabled"], last_sign_in_utc=last, sign_in_data_available=signin is not None, homepage=sp.get("homepage"), reply_url_domains=domains,
        )
        session.add(app)
        session.flush()

        perms: list[scoring.Perm] = []
        for a in assignments or []:
            if a["servicePrincipalId"] != sp["id"]:
                continue
            res = sp_by_id.get(a["resourceId"], {})
            value = a["appRoleValue"] or f"appRole:{a['appRoleId']}"
            p = AppPermission(tenant_app_id=app.id, permission_type="application", resource_app_id=res.get("appId"), resource_name=a["resourceDisplayName"] or res.get("displayName"), value=value, consent_type="n/a", user_count=None, tier=tier_for(a["appRoleValue"]))
            session.add(p)
            perms.append(scoring.Perm("application", value, p.tier, "n/a", p.resource_name))
        for g in grants or []:
            if g["clientId"] != sp["id"]:
                continue
            res = sp_by_id.get(g["resourceId"], {})
            for scope in g["scopes"]:
                count = g["principalCount"] if g["consentType"] == "Principal" else None
                p = AppPermission(tenant_app_id=app.id, permission_type="delegated", resource_app_id=res.get("appId"), resource_name=res.get("displayName"), value=scope, consent_type=g["consentType"], user_count=count, tier=tier_for(scope))
                session.add(p)
                perms.append(scoring.Perm("delegated", scope, p.tier, g["consentType"], p.resource_name, count))

        cred_facts = None
        if creds is not None:
            cred_facts = []
            for c in creds:
                if c["ownerAppId"] != sp["appId"]:
                    continue
                start, end = parse_dt(c["startDateTime"]), parse_dt(c["endDateTime"])
                state = "valid"
                if end and end < collected:
                    state = "expired"
                elif end and (end - collected).days <= rules.expiring_soon_days:
                    state = "expiring_30d"
                session.add(AppCredential(tenant_app_id=app.id, owner_type=c["ownerType"], key_id=c["keyId"], display_name=c["displayName"], credential_type=c["credentialType"], start_utc=start, end_utc=end, lifetime_days=(end - start).days if start and end else None, status=state))
                cred_facts.append(scoring.Cred(c["ownerType"], start, end))

        missing = []
        if assignments is None and owner_class != "microsoft":
            missing.append("app permissions")
        if grants is None:
            missing.append("delegated grants")
        if creds is None:
            missing.append("credentials")
        facts = scoring.AppFacts(owner_class, app.publisher_verified, perms, cred_facts, signin is not None, last, collected, missing)
        ex = scoring.score(facts, rules)
        session.add(AppExposure(
            tenant_app_id=app.id, exposure_level=ex.level, has_app_only=ex.has_app_only, max_permission_tier=ex.max_permission_tier,
            admin_consented=ex.admin_consented, user_consent_count=ex.user_consent_count, dormant=ex.dormant,
            credential_flags=ex.credential_flags, incomplete_data=ex.incomplete_data, reasons=ex.reasons,
        ))
        by_class[owner_class] = by_class.get(owner_class, 0) + 1
        if owner_class != "microsoft":
            by_level[ex.level] = by_level.get(ex.level, 0) + 1
    session.flush()
    log_event(session, actor, "import", "ExposureSnapshot", snap.id, f"Imported exposure snapshot of {tenant.name} collected {collected:%Y-%m-%d %H:%M} UTC ({len(sps)} apps)")
    return ImportResult(snap.id, tenant.id, len(sps), by_class, by_level)


def latest_snapshots(session: Session, tenant_id: int, n: int = 2) -> list[ExposureSnapshot]:
    return list(session.scalars(select(ExposureSnapshot).where(ExposureSnapshot.tenant_id == tenant_id).order_by(ExposureSnapshot.collected_at_utc.desc()).limit(n)))


def tenants(session: Session) -> list[EntraTenant]:
    return list(session.scalars(select(EntraTenant).order_by(EntraTenant.name)))
