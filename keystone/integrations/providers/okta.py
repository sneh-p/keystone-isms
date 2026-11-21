"""Okta (read-only): checks on sign-in, MFA enrolment, administrators and the password policy.

Approved with the round 9 request (human:sneh, 2026-11-21). Host: the organisation's own Okta domain under
*.okta.com, *.oktapreview.com or *.okta-emea.com. The token is an API token created by a Read-only Administrator, so it
can't change anything.
"""

from __future__ import annotations

import re
from datetime import timedelta

from keystone.asm.vocabulary import parse_time
from keystone.core.db import utcnow

from ..http import Api, ConnectorError, HostPolicy, validate_base_url
from .base import CheckDef, ConfigField, Outcome, Provider, SetupStep

OKTA = HostPolicy(suffixes=(".okta.com", ".oktapreview.com", ".okta-emea.com"))
INACTIVE_DAYS = 90
MAX_FACTOR_LOOKUPS = 1000  # one call per user: larger organisations get "unknown" for MFA enrolment
MAX_SUPER_ADMINS = 3
MIN_PASSWORD = 12
NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')


class OktaProvider(Provider):
    key = "okta"
    name = "Okta"
    description = "Checks Okta for inactive users, MFA enrolment, the number of super administrators and the password policy's minimum length."
    fields = (
        ConfigField("domain", "Okta domain", help="e.g. https://yourcompany.okta.com", example="https://yourcompany.okta.com"),
        ConfigField("token", "API token", secret=True, help="Created while signed in as a Read-only Administrator. Note when it expires."),
    )
    checks = (
        CheckDef("inactive_users", f"No active users unused for {INACTIVE_DAYS} days", ("KC-ORG-18", "KC-ORG-16")),
        CheckDef("mfa_enrolled", "Every active user has an MFA factor", ("KC-TEC-05", "KC-ORG-17")),
        CheckDef("few_super_admins", f"At most {MAX_SUPER_ADMINS} super administrators", ("KC-TEC-02",)),
        CheckDef("password_length", f"Password policies require {MIN_PASSWORD}+ characters", ("KC-ORG-17",)),
    )
    setup = (
        SetupStep("Create a read-only admin", "Okta Admin Console > Security > Administrators > Add administrator: a dedicated user (for example keystone-readonly@…) "
                  "with only the Read-only Administrator role."),
        SetupStep("Create the token as that admin", "Sign in as that user, then Security > API > Tokens > Create token, named “Keystone”. A token can do only what its "
                  "creator can, so this one can't change anything. Okta tokens expire after 30 days unused: Keystone uses it every day."),
        SetupStep("Check", "Choose Test connection; Keystone runs the checks and saves nothing.", kind="verify"),
    )

    def _get_all(self, api: Api, url: str, limit: int = 20_000) -> list[dict]:
        out: list[dict] = []
        next_url: str | None = url
        while next_url and len(out) < limit:
            r = api.request("GET", next_url)
            try:
                page = r.json()
            except ValueError:
                raise ConnectorError("Okta didn't return JSON.") from None
            if not isinstance(page, list):
                raise ConnectorError("Okta returned an unexpected answer.")
            out += page
            m = NEXT.search(r.headers.get("link", ""))
            next_url = m.group(1) if m else None
        return out

    def run(self, config: dict, secrets: dict, session=None) -> list[Outcome]:
        base = validate_base_url(config.get("domain", ""), OKTA)
        api = Api(OKTA, headers={"Authorization": f"SSWS {secrets.get('token', '')}"})
        users = self._get_all(api, f"{base}/api/v1/users?filter=" + 'status%20eq%20%22ACTIVE%22' + "&limit=200")
        now = utcnow()
        out = []
        idle = []
        for u in users:
            last = parse_time(u.get("lastLogin")) or parse_time(u.get("activated")) or parse_time(u.get("created"))
            if last and now - last > timedelta(days=INACTIVE_DAYS):
                idle.append((u.get("profile") or {}).get("login") or u.get("id"))
        out.append(Outcome("inactive_users", "fail" if idle else "pass", f"{len(idle)} of {len(users)} active users haven't signed in for {INACTIVE_DAYS} days: {', '.join(map(str, idle[:8]))}"
                           if idle else f"All {len(users)} active users signed in recently", {"inactive": [str(x) for x in idle[:500]]}))
        if len(users) > MAX_FACTOR_LOOKUPS:
            out.append(Outcome("mfa_enrolled", "unknown", f"More than {MAX_FACTOR_LOOKUPS} active users: check MFA enrolment in Okta's reports"))
        else:
            none = []
            for u in users:
                factors = api.json("GET", f"{base}/api/v1/users/{u['id']}/factors")
                if not any(f.get("status") == "ACTIVE" for f in factors if isinstance(f, dict)):
                    none.append((u.get("profile") or {}).get("login") or u.get("id"))
            out.append(Outcome("mfa_enrolled", "fail" if none else "pass", f"{len(none)} of {len(users)} active users have no MFA factor: {', '.join(map(str, none[:8]))}"
                               if none else f"All {len(users)} active users have an MFA factor", {"without_mfa": [str(x) for x in none[:500]]}))
        try:
            admins = self._get_all(api, f"{base}/api/v1/iam/assignees/users?limit=200", limit=2000)
            supers = []
            for a in admins:
                roles = api.json("GET", f"{base}/api/v1/users/{a['id']}/roles")
                if any(r.get("type") == "SUPER_ADMIN" for r in roles if isinstance(r, dict)):
                    supers.append((a.get("profile") or {}).get("login") or a.get("id"))
            out.append(Outcome("few_super_admins", "pass" if len(supers) <= MAX_SUPER_ADMINS else "fail", f"{len(supers)} super administrator(s): {', '.join(map(str, supers[:8]))}",
                               {"super_admins": [str(x) for x in supers]}))
        except ConnectorError as e:
            out.append(Outcome("few_super_admins", "unknown", f"Administrators couldn't be read ({e})"))
        try:
            policies = [p for p in api.json("GET", f"{base}/api/v1/policies?type=PASSWORD") if isinstance(p, dict) and p.get("status") == "ACTIVE"]
            short = [f"{p.get('name')} ({(((p.get('settings') or {}).get('password') or {}).get('complexity') or {}).get('minLength')})" for p in policies
                     if int((((p.get("settings") or {}).get("password") or {}).get("complexity") or {}).get("minLength") or 0) < MIN_PASSWORD]
            out.append(Outcome("password_length", "unknown" if not policies else "fail" if short else "pass",
                               "No active password policy found" if not policies else f"Too short: {', '.join(short)}" if short else f"All {len(policies)} policies require {MIN_PASSWORD}+"))
        except ConnectorError as e:
            out.append(Outcome("password_length", "unknown", f"Password policies couldn't be read ({e})"))
        return out
