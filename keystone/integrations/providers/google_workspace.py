"""Google Workspace (read-only): 2-step verification, super administrators, inactive users and external Drive sharing.

Approved with the round 9 request (human:sneh, 2026-11-21). A service account with domain-wide delegation for
read-only scopes, acting as an administrator; fixed hosts: oauth2.googleapis.com, admin.googleapis.com and
cloudidentity.googleapis.com.
"""

from __future__ import annotations

import json
import re
import time
from datetime import timedelta
from urllib.parse import quote

from keystone.asm.vocabulary import parse_time
from keystone.core.db import utcnow

from ..http import Api, ConnectorError, HostPolicy
from .base import CheckDef, ConfigField, Outcome, Provider, SetupStep

OAUTH_URL = "https://oauth2.googleapis.com/token"
ADMIN, CLOUD_IDENTITY = "https://admin.googleapis.com", "https://cloudidentity.googleapis.com"
POLICY = HostPolicy(hosts=frozenset({"oauth2.googleapis.com", "admin.googleapis.com", "cloudidentity.googleapis.com"}))
SCOPES = "https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/cloud-identity.policies.readonly"
EMAIL = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}$")
INACTIVE_DAYS = 90
MAX_SUPER_ADMINS = 3


def assertion(sa: dict, subject: str, now: int) -> str:
    from joserfc import jwt
    from joserfc.jwk import RSAKey

    try:
        key = RSAKey.import_key(sa["private_key"])
    except (KeyError, ValueError, TypeError) as e:
        raise ConnectorError("The service account key couldn't be read; paste the whole JSON key file.") from e
    claims = {"iss": sa["client_email"], "sub": subject, "scope": SCOPES, "aud": OAUTH_URL, "iat": now, "exp": now + 600}
    return jwt.encode({"alg": "RS256", "typ": "JWT"}, claims, key)


class GoogleWorkspaceProvider(Provider):
    key = "google_workspace"
    name = "Google Workspace"
    description = "Checks Google Workspace for 2-step verification, super administrators, inactive users and external Drive sharing."
    fields = (
        ConfigField("admin_email", "Administrator to act as", help="An admin account the service account reads as (domain-wide delegation needs one).",
                    example="admin@yourcompany.com"),
        ConfigField("service_account_json", "Service account key (JSON)", secret=True, help="The JSON key of a service account with domain-wide delegation for the read-only scopes below."),
    )
    checks = (
        CheckDef("two_step_enrolled", "Every active user is enrolled in 2-step verification", ("KC-TEC-05", "KC-ORG-17")),
        CheckDef("two_step_enforced", "2-step verification enforced for every active user", ("KC-TEC-05",)),
        CheckDef("few_super_admins", f"At most {MAX_SUPER_ADMINS} super administrators", ("KC-TEC-02",)),
        CheckDef("inactive_users", f"No active users unused for {INACTIVE_DAYS} days", ("KC-ORG-18", "KC-ORG-16")),
        CheckDef("external_sharing", "Drive files can't be shared with anyone outside by default", ("KC-TEC-12", "KC-TEC-03")),
    )
    setup = (
        SetupStep("Create a service account", "Google Cloud console > IAM & Admin > Service accounts > Create “keystone-workspace-readonly” in any project, with no "
                  "roles. Keys > Add key > JSON."),
        SetupStep("Allow read-only scopes", "Google Admin console > Security > Access and data control > API controls > Manage domain-wide delegation > Add new: the "
                  "service account's client ID, with exactly these scopes, comma-separated: https://www.googleapis.com/auth/admin.directory.user.readonly, "
                  "https://www.googleapis.com/auth/cloud-identity.policies.readonly"),
        SetupStep("Choose the administrator", "Enter an administrator's address; Keystone reads as that account, limited to the two read-only scopes. A read-only admin "
                  "role (Users: Read) is enough."),
        SetupStep("Check", "Choose Test connection; Keystone runs the checks and saves nothing.", kind="verify"),
    )

    def run(self, config: dict, secrets: dict, session=None) -> list[Outcome]:
        subject = (config.get("admin_email") or "").strip()
        if not EMAIL.match(subject):
            raise ConnectorError("Enter the administrator's email address.")
        try:
            sa = json.loads(secrets.get("service_account_json") or "")
        except ValueError:
            raise ConnectorError("The service account key must be the JSON key file.") from None
        if not isinstance(sa, dict) or sa.get("type") != "service_account" or not sa.get("client_email") or not sa.get("private_key"):
            raise ConnectorError("The service account key must be a JSON key for a service account.")
        api = Api(POLICY)
        # The token endpoint is fixed: a token_uri inside the uploaded file is ignored (SC-SSRF-003).
        tok = api.json("POST", OAUTH_URL, data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion(sa, subject, int(time.time()))}).get("access_token")
        if not tok:
            raise ConnectorError("Google didn't return an access token.")
        auth = {"Authorization": f"Bearer {tok}"}
        users: list[dict] = []
        page: str | None = None
        while True:
            body = api.json("GET", f"{ADMIN}/admin/directory/v1/users?customer=my_customer&maxResults=500&projection=basic" + (f"&pageToken={quote(page, safe='')}" if page else ""),
                            headers=auth)
            users += body.get("users") or []
            page = body.get("nextPageToken")
            if not page or len(users) >= 200_000:
                break
        active = [u for u in users if not u.get("suspended") and not u.get("archived")]
        name = [u.get("primaryEmail") or u.get("id") for u in active]
        out = []
        not_enrolled = sorted(str(n) for u, n in zip(active, name, strict=True) if u.get("isEnrolledIn2Sv") is False)
        out.append(Outcome("two_step_enrolled", "fail" if not_enrolled else "pass", f"{len(not_enrolled)} of {len(active)} active users not enrolled: {', '.join(not_enrolled[:8])}"
                           if not_enrolled else f"All {len(active)} active users enrolled", {"not_enrolled": not_enrolled[:500]}))
        not_enforced = sorted(str(n) for u, n in zip(active, name, strict=True) if u.get("isEnforcedIn2Sv") is False)
        out.append(Outcome("two_step_enforced", "fail" if not_enforced else "pass", f"Not enforced for {len(not_enforced)} of {len(active)} active users"
                           if not_enforced else f"Enforced for all {len(active)} active users", {"not_enforced": not_enforced[:500]}))
        supers = sorted(str(n) for u, n in zip(active, name, strict=True) if u.get("isAdmin"))
        out.append(Outcome("few_super_admins", "pass" if len(supers) <= MAX_SUPER_ADMINS else "fail", f"{len(supers)} super administrator(s): {', '.join(supers[:8])}", {"super_admins": supers}))
        now, idle = utcnow(), []
        for u, n in zip(active, name, strict=True):
            last = parse_time(u.get("lastLoginTime")) if not str(u.get("lastLoginTime", "")).startswith("1970") else None
            seen = last or parse_time(u.get("creationTime"))
            if seen is not None and now - seen > timedelta(days=INACTIVE_DAYS):
                idle.append(str(n))
        out.append(Outcome("inactive_users", "fail" if idle else "pass", f"{len(idle)} of {len(active)} active users haven't signed in for {INACTIVE_DAYS} days: {', '.join(sorted(idle)[:8])}"
                           if idle else f"All {len(active)} active users signed in recently", {"inactive": sorted(idle)[:500]}))
        try:
            body = api.json("GET", f"{CLOUD_IDENTITY}/v1/policies?filter=" + quote("setting.type.matches('drive_and_docs.external_sharing')", safe=""), headers=auth)
            modes = [str(((p.get("setting") or {}).get("value") or {}).get("externalSharingMode") or "") for p in body.get("policies") or []]
            if not modes:
                out.append(Outcome("external_sharing", "unknown", "The sharing policy wasn't returned"))
            else:
                allowed = [m for m in modes if m.upper() == "ALLOWED"]
                out.append(Outcome("external_sharing", "fail" if allowed else "pass", f"External sharing allowed in {len(allowed)} of {len(modes)} policies" if allowed
                                   else "External sharing is off or limited to listed domains", {"modes": modes}))
        except ConnectorError as e:
            out.append(Outcome("external_sharing", "unknown", f"The sharing policy couldn't be read ({e})"))
        return out
