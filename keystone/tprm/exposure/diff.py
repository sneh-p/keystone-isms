"""Compare the two latest snapshots of a tenant. Only datasets that succeeded in both are compared."""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from .importer import latest_snapshots, status_ok
from .inventory import VENDOR_CLASSES
from .models import ExposureSnapshot
from .permission_catalog import TIER_RANK


@dataclass
class PermissionChange:
    app: str
    owner_class: str
    permission_type: str
    value: str
    resource: str | None
    tier: str
    consent_type: str

    @property
    def app_only_high(self) -> bool:
        return self.permission_type == "application" and TIER_RANK[self.tier] >= TIER_RANK["high"]


@dataclass
class SnapshotDiff:
    old_id: int
    new_id: int
    new_apps: list[str] = field(default_factory=list)
    removed_apps: list[str] = field(default_factory=list)
    new_permissions: list[PermissionChange] = field(default_factory=list)
    consent_changes: list[tuple[str, object, object]] = field(default_factory=list)
    new_credentials: list[tuple[str, str, str | None]] = field(default_factory=list)  # (app, type, name)
    not_comparable: list[str] = field(default_factory=list)


def _apps(snap: ExposureSnapshot) -> dict:
    return {a.app_id: a for a in snap.apps}


def diff_snapshots(old: ExposureSnapshot, new: ExposureSnapshot) -> SnapshotDiff:
    d = SnapshotDiff(old.id, new.id)
    ok = {k: status_ok(old.endpoint_status, k) and status_ok(new.endpoint_status, k) for k in ("service_principals", "app_role_assignments", "delegated_grants", "credentials", "consent_posture.authorization_policy", "consent_posture.admin_consent_request_policy")}
    d.not_comparable = [k for k, v in ok.items() if not v]
    a_old, a_new = _apps(old), _apps(new)

    if ok["service_principals"]:
        d.new_apps = sorted(a.display_name or k for k, a in a_new.items() if k not in a_old and a.owner_class in VENDOR_CLASSES)
        d.removed_apps = sorted(a.display_name or k for k, a in a_old.items() if k not in a_new and a.owner_class in VENDOR_CLASSES)

    compare_types = {t for t, key in (("application", "app_role_assignments"), ("delegated", "delegated_grants")) if ok[key]}
    for app_id, app in a_new.items():
        if app.owner_class == "microsoft":
            continue
        before = {(p.permission_type, p.resource_app_id, p.value, p.consent_type) for p in (a_old[app_id].permissions if app_id in a_old else [])}
        for p in app.permissions:
            if p.permission_type in compare_types and (p.permission_type, p.resource_app_id, p.value, p.consent_type) not in before:
                d.new_permissions.append(PermissionChange(app.display_name or app_id, app.owner_class, p.permission_type, p.value, p.resource_name, p.tier, p.consent_type))
    # Newly added app-only critical/high permissions first, then by tier.
    d.new_permissions.sort(key=lambda c: (not c.app_only_high, -TIER_RANK[c.tier], c.permission_type != "application", c.app, c.value))

    for label, key, attr in (("Users can consent to apps", "consent_posture.authorization_policy", "users_can_consent"), ("Admin consent workflow enabled", "consent_posture.admin_consent_request_policy", "admin_consent_workflow_enabled")):
        if ok[key]:
            before, after = getattr(old.consent, attr), getattr(new.consent, attr)
            if before != after:
                d.consent_changes.append((label, before, after))

    if ok["credentials"]:
        old_keys = {c.key_id for a in a_old.values() for c in a.credentials}
        for app in a_new.values():
            for c in app.credentials:
                if c.key_id not in old_keys:
                    d.new_credentials.append((app.display_name or app.app_id, c.credential_type, c.display_name))
    return d


def latest_diff(session: Session, tenant_id: int) -> SnapshotDiff | None:
    snaps = latest_snapshots(session, tenant_id, 2)
    if len(snaps) < 2:
        return None
    return diff_snapshots(snaps[1], snaps[0])
