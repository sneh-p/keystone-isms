"""Role-based access control. Every service function that writes calls require()."""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"
    ISMS_MANAGER = "isms_manager"
    RISK_OWNER = "risk_owner"
    CONTROL_OWNER = "control_owner"
    AUDITOR = "auditor"
    VIEWER = "viewer"


ROLE_LABELS = {
    Role.ADMIN: "Administrator",
    Role.ISMS_MANAGER: "ISMS manager",
    Role.RISK_OWNER: "Risk owner",
    Role.CONTROL_OWNER: "Control owner",
    Role.AUDITOR: "Auditor",
    Role.VIEWER: "Viewer",
}

ALL_PERMISSIONS = frozenset(
    {
        "read",
        "users.manage",
        "audit_log.view",
        "org.write",
        "framework.write",
        "asset.write",
        "risk.write",
        "risk.accept",
        "control.write",
        "soa.write",
        "evidence.write",
        "vendor.write",
        "vendor.approve",
        "exposure.import",
        "exposure.confirm",
        "policy.write",
        "policy.approve",
        "policy.acknowledge",
        "incident.write",
        "nc.write",
        "nc.verify",
        "audit.manage",
        "audit.findings",
        "review.write",
        "task.write",
        "task.approve",
    }
)

_BASE = {"read", "policy.acknowledge"}

ROLE_PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.ADMIN: ALL_PERMISSIONS,
    Role.ISMS_MANAGER: ALL_PERMISSIONS - {"users.manage"},
    Role.RISK_OWNER: frozenset(_BASE | {"asset.write", "risk.write", "evidence.write", "incident.write", "nc.write", "task.write"}),
    Role.CONTROL_OWNER: frozenset(_BASE | {"control.write", "evidence.write", "incident.write", "nc.write", "task.write"}),
    Role.AUDITOR: frozenset(_BASE | {"audit.findings", "audit_log.view"}),
    Role.VIEWER: frozenset(_BASE),
}


class PermissionDenied(PermissionError):
    pass


def has_permission(user, permission: str) -> bool:
    if permission not in ALL_PERMISSIONS:
        raise ValueError(f"unknown permission {permission!r}")
    if user is None or not getattr(user, "active", False):
        return False
    return permission in ROLE_PERMISSIONS.get(Role(user.role), frozenset())


def require(user, permission: str) -> None:
    if not has_permission(user, permission):
        who = getattr(user, "username", "anonymous")
        raise PermissionDenied(f"{who} lacks permission {permission!r}")
