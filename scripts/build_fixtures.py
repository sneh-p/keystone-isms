"""Generate the synthetic collected.json test fixtures.

Everything here is fictional: tenant names, vendors, domains (.example TLD, reserved
by RFC 2606) and GUIDs (uuid5 from a fixed project namespace). The only real
identifiers are Microsoft's public first-party appIds for Microsoft Graph, Exchange
Online and SharePoint Online, plus the Microsoft owner tenant IDs from the spec,
which are needed so resource resolution and Microsoft classification are realistic.

Run:  python scripts/build_fixtures.py   (rewrites tests/fixtures/*.json)
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

NS = uuid.UUID("5d1a6c0e-7b7e-4a3f-9a51-000000000000")  # project-local namespace
OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures"

MS_OWNER = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
GRAPH_APP = "00000003-0000-0000-c000-000000000000"
EXO_APP = "00000002-0000-0ff1-ce00-000000000000"
SPO_APP = "00000003-0000-0ff1-ce00-000000000000"


def g(*parts: str) -> str:
    return str(uuid.uuid5(NS, "/".join(parts)))


# Vendor owner orgs are the same in every tenant (multi-tenant apps).
OWNERS = {
    "northwind": g("owner", "northwind"),
    "fabrikam": g("owner", "fabrikam"),
    "litware": g("owner", "litware"),
    "wingtip": g("owner", "wingtip"),
    "proseware": g("owner", "proseware"),
    "adatum": g("owner", "adatum"),
    "relecloud": g("owner", "relecloud"),
    "margies": g("owner", "margies"),
}

# appId per app is also global (one app registration in the vendor's tenant).
APPS = {
    "northwind": {
        "appId": g("app", "northwind"),
        "displayName": "Northwind Signatures",
        "owner": OWNERS["northwind"],
        "publisherName": "Northwind Signatures Ltd",
        "verified": "Northwind Signatures Ltd",
        "homepage": "https://www.northwindsignatures.example/",
        "replyUrls": ["https://app.northwindsignatures.example/auth/callback"],
    },
    "fabrikam": {
        "appId": g("app", "fabrikam"),
        "displayName": "Fabrikam Backup for Microsoft 365",
        "owner": OWNERS["fabrikam"],
        "publisherName": "Fabrikam Backup Inc",
        "verified": "Fabrikam Backup Inc",
        "homepage": "https://fabrikambackup.example",
        "replyUrls": ["https://portal.fabrikambackup.example/oauth"],
    },
    "litware": {
        "appId": g("app", "litware"),
        "displayName": "Litware Scheduler",
        "owner": OWNERS["litware"],
        "publisherName": "Litware",
        "verified": None,
        "homepage": "https://litware-scheduler.example",
        "replyUrls": ["https://litware-scheduler.example/signin-oidc"],
    },
    "wingtip": {
        "appId": g("app", "wingtip"),
        "displayName": "Wingtip HR Sync",
        "owner": OWNERS["wingtip"],
        "publisherName": "Wingtip Toys HR Software",
        "verified": "Wingtip HR Software",
        "homepage": "https://wingtiphr.example",
        "replyUrls": ["https://sync.wingtiphr.example/callback"],
    },
    "proseware": {
        "appId": g("app", "proseware"),
        "displayName": "Proseware PDF Tools",
        "owner": OWNERS["proseware"],
        "publisherName": "Proseware",
        "verified": None,
        "homepage": None,
        "replyUrls": ["https://pdf.proseware.example/auth"],
    },
    "adatum": {
        "appId": g("app", "adatum"),
        "displayName": "Adatum Survey",
        "owner": OWNERS["adatum"],
        "publisherName": "Adatum Corporation",
        "verified": "Adatum Corporation",
        "homepage": "https://survey.adatum.example",
        "replyUrls": ["https://survey.adatum.example/login"],
    },
    "relecloud": {
        "appId": g("app", "relecloud"),
        "displayName": "Relecloud Wiki (SAML)",
        "owner": OWNERS["relecloud"],
        "publisherName": "Relecloud",
        "verified": None,
        "homepage": "https://wiki.relecloud.example",
        "replyUrls": ["https://wiki.relecloud.example/saml/acs"],
    },
    "margies": {
        "appId": g("app", "margies"),
        "displayName": "Margie's Travel Expense",
        "owner": OWNERS["margies"],
        "publisherName": "Margie's Travel",
        "verified": None,
        "homepage": "https://margiestravel.example",
        "replyUrls": [],
    },
}


def sp(tenant: str, key: str, app: dict, sp_type: str = "Application") -> dict:
    verified = app.get("verified")
    return {
        "id": g(tenant, "sp", key),
        "appId": app["appId"],
        "displayName": app["displayName"],
        "servicePrincipalType": sp_type,
        "appOwnerOrganizationId": app["owner"],
        "publisherName": app.get("publisherName"),
        "verifiedPublisher": {
            "displayName": verified,
            "verifiedPublisherId": g("mpn", key)[:7] if verified else None,
            "addedDateTime": "2024-02-01T00:00:00Z" if verified else None,
        },
        "accountEnabled": True,
        "appRoleAssignmentRequired": False,
        "tags": ["WindowsAzureActiveDirectoryIntegratedApp"],
        "homepage": app.get("homepage"),
        "replyUrls": app.get("replyUrls", []),
    }


def ms_resources(tenant: str) -> dict:
    """Microsoft first-party SPs present in every tenant."""
    base = {"owner": MS_OWNER, "publisherName": "Microsoft Services", "verified": None, "homepage": None}
    return {
        "graph": sp(tenant, "graph", {**base, "appId": GRAPH_APP, "displayName": "Microsoft Graph"}),
        "exo": sp(tenant, "exo", {**base, "appId": EXO_APP, "displayName": "Office 365 Exchange Online"}),
        "spo": sp(tenant, "spo", {**base, "appId": SPO_APP, "displayName": "Office 365 SharePoint Online"}),
        "teams": sp(tenant, "teams", {**base, "appId": g("app", "teams"), "displayName": "Microsoft Teams"}),
    }


def ara(tenant: str, client_sp: dict, resource_sp: dict, value: str, created: str) -> dict:
    return {
        "servicePrincipalId": client_sp["id"],
        "resourceId": resource_sp["id"],
        "resourceDisplayName": resource_sp["displayName"],
        "appRoleId": g("approle", resource_sp["appId"], value),
        "appRoleValue": value,
        "createdDateTime": created,
    }


def grant(client_sp: dict, resource_sp: dict, consent: str, scopes: list[str], count: int) -> dict:
    return {
        "clientId": client_sp["id"],
        "resourceId": resource_sp["id"],
        "consentType": consent,
        "scopes": scopes,
        "principalCount": count,
    }


def cred(owner_type: str, owner: dict, ctype: str, name: str, start: str, end: str, tenant: str) -> dict:
    return {
        "ownerType": owner_type,
        "ownerObjectId": owner["id"],
        "ownerAppId": owner["appId"],
        "credentialType": ctype,
        "keyId": g(tenant, "key", owner["appId"], name),
        "displayName": name,
        "startDateTime": start,
        "endDateTime": end,
    }


def signin(app_id: str, last: str | None, app_only: str | None = None, delegated: str | None = None) -> dict:
    return {
        "appId": app_id,
        "lastSignInActivity": {"lastSignInDateTime": last},
        "delegatedClientSignInActivity": {"lastSignInDateTime": delegated},
        "delegatedResourceSignInActivity": {"lastSignInDateTime": None},
        "applicationAuthenticationClientSignInActivity": {"lastSignInDateTime": app_only},
        "applicationAuthenticationResourceSignInActivity": {"lastSignInDateTime": None},
    }


def status(count: int | None, state: str = "ok", http: int | None = 200, msg: str = "", api: str = "v1.0") -> dict:
    return {"status": state, "http_status": http, "message": msg, "record_count": count, "api_version": api}


P1_PLANS = [
    {"servicePlanName": "AAD_PREMIUM", "provisioningStatus": "Success", "skuPartNumber": "SPB", "capabilityStatus": "Enabled"},
    {"servicePlanName": "EXCHANGE_S_STANDARD", "provisioningStatus": "Success", "skuPartNumber": "SPB", "capabilityStatus": "Enabled"},
    {"servicePlanName": "SHAREPOINTSTANDARD", "provisioningStatus": "Success", "skuPartNumber": "SPB", "capabilityStatus": "Enabled"},
]
NO_P1_PLANS = [
    {"servicePlanName": "EXCHANGE_S_STANDARD", "provisioningStatus": "Success", "skuPartNumber": "O365_BUSINESS_PREMIUM", "capabilityStatus": "Enabled"},
    {"servicePlanName": "SHAREPOINTSTANDARD", "provisioningStatus": "Success", "skuPartNumber": "O365_BUSINESS_PREMIUM", "capabilityStatus": "Enabled"},
    {"servicePlanName": "TEAMS1", "provisioningStatus": "Success", "skuPartNumber": "O365_BUSINESS_PREMIUM", "capabilityStatus": "Enabled"},
]

READ_SCOPES = ["Application.Read.All", "AuditLog.Read.All", "Directory.Read.All", "Policy.Read.All", "openid", "profile", "offline_access"]


def finish(doc: dict) -> dict:
    """Fill endpoint_status record counts from the datasets."""
    es = doc["metadata"]["endpoint_status"]
    for key in ("service_principals", "app_role_assignments", "delegated_grants", "signin_activity"):
        if es[key]["status"] == "ok":
            es[key]["record_count"] = len(doc[key])
    if doc["credentials"] is not None:
        apps = sum(1 for c in doc["credentials"] if c["ownerType"] == "application")
        sps = sum(1 for c in doc["credentials"] if c["ownerType"] == "servicePrincipal")
        es["credentials.applications"]["record_count"] = apps
        es["credentials.service_principals"]["record_count"] = sps
    if doc["licensing"] is not None:
        es["licensing"]["record_count"] = len(doc["licensing"]["service_plans"])
    return doc


# --------------------------------------------------------------------------- Tenant A
def tenant_a(later: bool) -> dict:
    t = "tenant-a"
    tid = g("tenant", "alpine-ski-house")
    ms = ms_resources(t)
    internal_app = {"id": g(t, "app-object", "reporting"), "appId": g(t, "app", "reporting")}
    sps = {k: sp(t, k, APPS[k]) for k in ("northwind", "fabrikam", "litware", "wingtip", "proseware", "relecloud")}
    if not later:
        sps["adatum"] = sp(t, "adatum", APPS["adatum"])
    else:
        sps["margies"] = sp(t, "margies", APPS["margies"])
    sps["internal_reporting"] = sp(
        t,
        "internal_reporting",
        {
            "appId": internal_app["appId"],
            "displayName": "ASH Internal Reporting",
            "owner": tid,
            "publisherName": "Alpine Ski House",
            "verified": None,
            "homepage": None,
        },
    )
    sps["legacy_print"] = sp(
        t,
        "legacy_print",
        {
            "appId": g("app", "legacy-print"),
            "displayName": "Legacy Print Connector",
            "owner": None,
            "publisherName": None,
            "verified": None,
            "homepage": None,
        },
        sp_type="Legacy",
    )
    sps["managed_identity"] = sp(
        t,
        "managed_identity",
        {
            "appId": g(t, "app", "mi"),
            "displayName": "ash-automation-mi",
            "owner": None,
            "publisherName": None,
            "verified": None,
            "homepage": None,
        },
        sp_type="ManagedIdentity",
    )

    graph, exo, spo = ms["graph"], ms["exo"], ms["spo"]
    assignments = [
        ara(t, sps["northwind"], graph, "User.Read.All", "2025-03-10T09:00:00Z"),
        ara(t, sps["northwind"], graph, "MailboxSettings.ReadWrite", "2025-03-10T09:00:00Z"),
        ara(t, sps["fabrikam"], graph, "Files.ReadWrite.All", "2024-11-02T12:00:00Z"),
        ara(t, sps["fabrikam"], spo, "Sites.FullControl.All", "2024-11-02T12:00:00Z"),
        ara(t, sps["fabrikam"], exo, "full_access_as_app", "2024-11-02T12:00:00Z"),
        ara(t, sps["legacy_print"], graph, "Printer.Read.All", "2023-06-01T08:00:00Z"),
        ara(t, sps["internal_reporting"], graph, "Reports.Read.All", "2024-01-15T08:00:00Z"),
        ara(t, sps["managed_identity"], graph, "Group.Read.All", "2025-05-01T08:00:00Z"),
    ]
    if later:
        assignments += [
            ara(t, sps["northwind"], graph, "Calendars.Read", "2026-10-20T10:00:00Z"),
            ara(t, sps["northwind"], graph, "Mail.Send", "2026-10-20T10:00:00Z"),
            ara(t, sps["margies"], graph, "Directory.ReadWrite.All", "2026-10-28T15:30:00Z"),
        ]

    grants = [
        grant(sps["litware"], graph, "Principal", ["Calendars.ReadWrite", "offline_access", "openid"], 14),
        grant(sps["wingtip"], graph, "AllPrincipals", ["Directory.ReadWrite.All", "User.Read"], 0),
        grant(sps["proseware"], graph, "AllPrincipals", ["Files.ReadWrite.All", "Mail.Send", "User.Read"], 0),
    ]
    if not later:
        grants.append(grant(sps["adatum"], graph, "Principal", ["User.Read", "openid", "profile"], 3))

    creds = [
        cred("application", internal_app, "password", "reporting-secret-2024", "2024-01-15T08:00:00Z", "2025-01-15T08:00:00Z", t),
        cred("application", internal_app, "certificate", "reporting-cert", "2024-06-01T00:00:00Z", "2027-06-01T00:00:00Z", t),
        cred("application", internal_app, "password", "reporting-secret-2026", "2026-01-10T08:00:00Z", "2026-10-20T08:00:00Z", t),
        cred("servicePrincipal", sps["northwind"], "password", "added-by-helpdesk", "2026-02-01T00:00:00Z", "2028-02-01T00:00:00Z", t),
    ]
    if later:
        creds.append(cred("application", internal_app, "password", "reporting-secret-2026b", "2026-11-01T08:00:00Z", "2027-05-01T08:00:00Z", t))

    signins = [
        signin(APPS["northwind"]["appId"], "2026-09-30T22:10:00Z", app_only="2026-09-30T22:10:00Z"),
        signin(APPS["fabrikam"]["appId"], "2026-09-30T23:00:00Z", app_only="2026-09-30T23:00:00Z"),
        signin(APPS["litware"]["appId"], "2026-05-01T14:00:00Z", delegated="2026-05-01T14:00:00Z"),
        signin(APPS["wingtip"]["appId"], "2026-09-20T06:00:00Z", delegated="2026-09-20T06:00:00Z"),
        signin(APPS["proseware"]["appId"], "2026-09-29T11:00:00Z", delegated="2026-09-29T11:00:00Z"),
        signin(APPS["relecloud"]["appId"], "2026-09-01T09:00:00Z", delegated="2026-09-01T09:00:00Z"),
        signin(g("app", "legacy-print"), "2025-12-01T09:00:00Z", app_only="2025-12-01T09:00:00Z"),
        signin(internal_app["appId"], "2026-09-30T05:00:00Z", app_only="2026-09-30T05:00:00Z"),
        # Adatum Survey deliberately absent: report succeeded but no activity recorded.
    ]
    if later:
        signins = [s for s in signins if s["appId"] != APPS["litware"]["appId"]]
        signins.append(signin(APPS["margies"]["appId"], "2026-11-09T18:00:00Z", app_only="2026-11-09T18:00:00Z"))

    collected = "2026-11-10T16:45:00Z" if later else "2026-10-01T14:05:00Z"
    policies = [] if later else ["ManagePermissionGrantsForSelf.microsoft-user-default-low"]
    sp_list = list(ms.values()) + list(sps.values())

    doc = {
        "schema_version": "1.0",
        "collector_version": "0.1.0",
        "metadata": {
            "tenant_id": tid,
            "tenant_name": "Alpine Ski House",
            "default_domain": "alpineskihouse.example",
            "collected_at_utc": collected,
            "operator_upn": "tech01@msp-partner.example",
            "ticket_number": "T20261110.0107" if later else "T20261001.0042",
            "granted_scopes": READ_SCOPES,
            "write_scopes_present": False,
            "entra_p1_available": True,
            "microsoft_owned_skipped_count": len(ms),
            "endpoint_status": {
                "tenant": status(1),
                "licensing": status(None),
                "consent_posture.authorization_policy": status(1),
                "consent_posture.admin_consent_request_policy": status(1),
                "service_principals": status(None),
                "app_role_assignments": status(None),
                "delegated_grants": status(None),
                "credentials.applications": status(None),
                "credentials.service_principals": status(None),
                "signin_activity": status(None, api="beta"),
            },
        },
        "tenant": {"id": tid, "displayName": "Alpine Ski House", "defaultDomain": "alpineskihouse.example"},
        "licensing": {"service_plans": P1_PLANS},
        "consent_posture": {
            "authorization_policy": {"permissionGrantPoliciesAssigned": policies},
            "admin_consent_request_policy": {"isEnabled": later},
        },
        "service_principals": sp_list,
        "app_role_assignments": assignments,
        "delegated_grants": grants,
        "credentials": creds,
        "signin_activity": signins,
    }
    return finish(doc)


# --------------------------------------------------------------------------- Tenant B
def tenant_b() -> dict:
    t = "tenant-b"
    tid = g("tenant", "tailspin-toys")
    ms = ms_resources(t)
    sps = {k: sp(t, k, APPS[k]) for k in ("northwind", "fabrikam", "litware")}
    sps["unknown_sync"] = sp(
        t,
        "unknown_sync",
        {
            "appId": g("app", "unknown-sync"),
            "displayName": "Contact Sync Helper",
            "owner": None,
            "publisherName": None,
            "verified": None,
            "homepage": "https://contactsync.example",
        },
    )
    graph = ms["graph"]
    assignments = [
        ara(t, sps["fabrikam"], graph, "Files.ReadWrite.All", "2025-08-14T10:00:00Z"),
        ara(t, sps["northwind"], graph, "User.Read.All", "2025-09-01T10:00:00Z"),
    ]
    grants = [
        grant(sps["litware"], graph, "Principal", ["Calendars.Read", "openid"], 6),
        grant(sps["unknown_sync"], graph, "Principal", ["Contacts.ReadWrite", "offline_access"], 2),
    ]
    doc = {
        "schema_version": "1.0",
        "collector_version": "0.1.0",
        "metadata": {
            "tenant_id": tid,
            "tenant_name": "Tailspin Toys",
            "default_domain": "tailspintoys.example",
            "collected_at_utc": "2026-11-05T10:20:00Z",
            "operator_upn": "tech02@msp-partner.example",
            "ticket_number": "T20261105.0019",
            "granted_scopes": READ_SCOPES + ["User.ReadWrite.All"],
            "write_scopes_present": True,
            "entra_p1_available": False,
            "microsoft_owned_skipped_count": len(ms),
            "endpoint_status": {
                "tenant": status(1),
                "licensing": status(None),
                "consent_posture.authorization_policy": status(1),
                "consent_posture.admin_consent_request_policy": status(1),
                "service_principals": status(None),
                "app_role_assignments": status(None),
                "delegated_grants": status(None),
                "credentials.applications": status(
                    None, "forbidden", 403, "Authorization_RequestDenied: Insufficient privileges to complete the operation."
                ),
                "credentials.service_principals": status(None),
                "signin_activity": status(
                    None,
                    "unavailable_license",
                    403,
                    "Tenant does not have a Microsoft Entra ID P1 or P2 license.",
                    api="beta",
                ),
            },
        },
        "tenant": {"id": tid, "displayName": "Tailspin Toys", "defaultDomain": "tailspintoys.example"},
        "licensing": {"service_plans": NO_P1_PLANS},
        "consent_posture": {
            "authorization_policy": {
                "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]
            },
            "admin_consent_request_policy": {"isEnabled": False},
        },
        "service_principals": list(ms.values()) + list(sps.values()),
        "app_role_assignments": assignments,
        "delegated_grants": grants,
        "credentials": None,  # one credential endpoint was forbidden -> whole dataset unknown
        "signin_activity": None,
    }
    return finish(doc)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, doc in (
        ("collected_tenant_a.json", tenant_a(later=False)),
        ("collected_tenant_a_later.json", tenant_a(later=True)),
        ("collected_tenant_b_no_p1.json", tenant_b()),
    ):
        (OUT / name).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {OUT / name}")


if __name__ == "__main__":
    main()
