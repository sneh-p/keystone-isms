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
    EMPLOYEE = "employee"


ROLE_LABELS = {
    Role.ADMIN: "Administrator",
    Role.ISMS_MANAGER: "ISMS manager",
    Role.RISK_OWNER: "Risk owner",
    Role.CONTROL_OWNER: "Control owner",
    Role.AUDITOR: "Auditor",
    Role.VIEWER: "Viewer",
    Role.EMPLOYEE: "Employee (portal only)",
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
        "people.write",
        "portal",
        "trust.manage",
        "integration.manage",
        "questionnaire.write",
        "questionnaire.approve",
        "ai.manage",
        "privacy.write",  # round 3: records of processing, DPIAs, data subject requests, breach assessments
        "continuity.write",  # round 3: business impact analysis, continuity plans and tests
        "access_review.manage",  # round 3: run access review campaigns (reviewers decide their own items with "read")
    }
)

_BASE = {"read", "policy.acknowledge", "portal"}

ROLE_PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.ADMIN: ALL_PERMISSIONS,
    Role.ISMS_MANAGER: ALL_PERMISSIONS - {"users.manage", "ai.manage"},
    Role.RISK_OWNER: frozenset(_BASE | {"asset.write", "risk.write", "evidence.write", "incident.write", "nc.write", "task.write", "continuity.write"}),
    Role.CONTROL_OWNER: frozenset(_BASE | {"control.write", "evidence.write", "incident.write", "nc.write", "task.write", "questionnaire.write"}),
    Role.AUDITOR: frozenset(_BASE | {"audit.findings", "audit_log.view"}),
    Role.VIEWER: frozenset(_BASE),
    # Employees use only their own portal: no access to ISMS records.
    Role.EMPLOYEE: frozenset({"portal", "policy.acknowledge"}),
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
