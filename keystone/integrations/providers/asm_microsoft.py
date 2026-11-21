"""Microsoft 365 (read-only): Entra ID identities and MFA, Intune devices, Defender for Endpoint devices and
vulnerabilities, Secure Score. App registration with application permissions, client-credentials flow.

Decision 2026-11-16 (human:sneh): Keystone may call Microsoft APIs directly, read-only, for attack surface
management. Hosts are fixed: login.microsoftonline.com, graph.microsoft.com, api.securitycenter.microsoft.com.
A part whose permission is missing is skipped with a note; nothing it reported before is retired.
"""

from __future__ import annotations

import base64
import json
import re

from keystone.asm.vocabulary import DeviceObs, IdentityObs, Inventory, SettingObs, VulnObs, as_bool, device_type_from, parse_time, severity_from

from ..http import Api, ConnectorError, HostPolicy, fields_of
from .base import ConfigField, InventoryProvider, PermissionReport, SetupStep

LOGIN, GRAPH, MDE = "https://login.microsoftonline.com", "https://graph.microsoft.com", "https://api.securitycenter.microsoft.com"
POLICY = HostPolicy(hosts=frozenset({"login.microsoftonline.com", "graph.microsoft.com", "api.securitycenter.microsoft.com"}))
GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def token_roles(token: str) -> list[str]:
    """The application roles in an access token's claims, to show what the app may do. Display only: the token is not
    verified here and nothing is authorised by it."""
    parts = token.split(".")
    if len(parts) != 3 or len(parts[1]) > 20_000:
        return []
    try:
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except ValueError:
        return []
    roles = claims.get("roles") if isinstance(claims, dict) else None
    return [str(r)[:100] for r in roles][:200] if isinstance(roles, list) else []


def read_only(role: str) -> bool:
    return role.endswith((".Read.All", ".Read")) and "Write" not in role


EXPLOITED = {"exploitisverified", "exploitisinkit", "exploitispublic"}


class MicrosoftProvider(InventoryProvider):
    key = "microsoft365"
    name = "Microsoft 365 (Entra, Intune, Defender)"
    description = "Read-only: Entra ID accounts and MFA registration, Intune device compliance and encryption, Defender for Endpoint device health and vulnerabilities, and Secure Score settings."
    category = "edr"
    categories = ("identity", "mdm", "edr", "vuln", "posture")
    mapping_note = "Field names from Microsoft Graph v1.0 and the Defender for Endpoint API documentation."
    fields = (
        ConfigField("tenant_id", "Directory (tenant) ID", help="A GUID from Entra ID > Overview.", example="00000000-0000-0000-0000-000000000000"),
        ConfigField("client_id", "Application (client) ID", help="From the app registration's Overview."),
        ConfigField("client_secret", "Client secret", secret=True, help="Certificates & secrets > New client secret. Note its expiry."),
    )
    setup = (
        SetupStep("Register an app", "In Entra ID > App registrations > New registration, name it “Keystone (read-only)”, single tenant, no redirect URI.",
                  link="https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade", link_label="Open App registrations"),
        SetupStep("Add read-only application permissions", "API permissions > Add a permission. Microsoft Graph, Application: User.Read.All, AuditLog.Read.All, "
                  "UserAuthenticationMethod.Read.All, DeviceManagementManagedDevices.Read.All, SecurityEvents.Read.All. WindowsDefenderATP (APIs my organization uses), "
                  "Application: Machine.Read.All, Vulnerability.Read.All. Then Grant admin consent. Leave out any you don't license; that part is skipped."),
        SetupStep("Create a client secret", "Certificates & secrets > New client secret. Copy the value into Keystone; it can't be read back. Set a reminder before it expires."),
        SetupStep("Check", "Choose Test connection. Keystone reads one page from each source and lists what it found and which parts were skipped.", kind="verify"),
    )

    def _token(self, api: Api, cfg: dict, sec: dict, scope: str) -> str:
        tid = (cfg.get("tenant_id") or "").strip()
        if not GUID.match(tid):
            raise ConnectorError("The tenant ID must be a GUID.")
        data = {"grant_type": "client_credentials", "client_id": cfg.get("client_id", "").strip(), "client_secret": sec.get("client_secret", ""), "scope": scope}
        r = api.json("POST", f"{LOGIN}/{tid}/oauth2/v2.0/token", data=data)
        if not r.get("access_token"):
            raise ConnectorError("Microsoft didn't return an access token.")
        return r["access_token"]

    def permissions(self, config: dict, secrets: dict) -> PermissionReport:
        api = Api(POLICY)
        roles = set(token_roles(self._token(api, config, secrets, f"{GRAPH}/.default")))
        try:
            roles |= set(token_roles(self._token(api, config, secrets, f"{MDE}/.default")))
        except ConnectorError:
            pass  # Defender for Endpoint not licensed or not consented: nothing granted there
        extra = sorted(r for r in roles if not read_only(r))
        if extra:
            return PermissionReport("fail", f"The app can change things: {', '.join(extra)}. Remove these permissions; Keystone only reads.", extra)
        if not roles:
            return PermissionReport("unknown", "No application permissions were granted (or admin consent is missing).")
        return PermissionReport("pass", f"{len(roles)} application permission(s), all read-only.")

    def _pages(self, api: Api, start: str, token: str, preview: bool, limit: int = 100_000) -> list[dict]:
        out: list[dict] = []
        url: str | None = start
        while url and len(out) < limit:
            body = api.json("GET", url, headers={"Authorization": f"Bearer {token}"})
            out += body.get("value", [])
            url = None if preview else body.get("@odata.nextLink")
        return out

    def collect(self, config: dict, secrets: dict, preview: bool = False) -> Inventory:
        api = Api(POLICY)
        inv = Inventory()
        graph = self._token(api, config, secrets, "https://graph.microsoft.com/.default")

        def part(name, fn):
            try:
                fn()
            except ConnectorError as e:
                if "refused access" in str(e) or "returned 403" in str(e):
                    inv.notes.append(f"{name} skipped: not permitted or not licensed")
                else:
                    raise

        def identities():
            reg = self._pages(api, f"{GRAPH}/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999", graph, preview)
            try:
                users = self._pages(api, f"{GRAPH}/v1.0/users?$select=userPrincipalName,displayName,accountEnabled,userType,signInActivity&$top=999", graph, preview)
            except ConnectorError:  # signInActivity needs Entra ID P1 and AuditLog.Read.All
                users = self._pages(api, f"{GRAPH}/v1.0/users?$select=userPrincipalName,displayName,accountEnabled,userType&$top=999", graph, preview)
                inv.notes.append("Sign-in activity unavailable (needs Entra ID P1 and AuditLog.Read.All)")
            inv.sample_fields["entra users"] = fields_of(users[0] if users else None)
            inv.sample_fields["entra registration"] = fields_of(reg[0] if reg else None)
            regs = {(r.get("userPrincipalName") or "").lower(): r for r in reg}
            from keystone.core.db import utcnow

            now = utcnow()
            for u in users:
                upn = (u.get("userPrincipalName") or "").lower()
                if not upn:
                    continue
                r = regs.get(upn, {})
                last = parse_time((u.get("signInActivity") or {}).get("lastSignInDateTime"))
                props = {"account_enabled": u.get("accountEnabled"), "is_guest": (u.get("userType") or "").lower() == "guest",
                         "mfa_registered": r.get("isMfaRegistered") if r else None, "is_admin": r.get("isAdmin") if r else None}
                if last:
                    props["last_sign_in_days"] = (now - last).days
                inv.identities.append(IdentityObs(upn, u.get("displayName"), {k: v for k, v in props.items() if v is not None}))
            if not preview:
                inv.complete.add("identities")

        def intune():
            rows = self._pages(api, f"{GRAPH}/v1.0/deviceManagement/managedDevices?$select=id,deviceName,serialNumber,operatingSystem,osVersion,complianceState,isEncrypted,lastSyncDateTime,userPrincipalName,azureADDeviceId", graph, preview)
            inv.sample_fields["intune devices"] = fields_of(rows[0] if rows else None)
            for d in rows:
                inv.devices.append(DeviceObs(external_id=f"intune:{d['id']}", name=d.get("deviceName") or d["id"], category="mdm", hostname=d.get("deviceName"),
                                             serial=d.get("serialNumber"), aad_device_id=d.get("azureADDeviceId"), os=d.get("operatingSystem"), os_version=d.get("osVersion"),
                                             device_type=device_type_from(d.get("operatingSystem")), owner_email=d.get("userPrincipalName"), last_seen=parse_time(d.get("lastSyncDateTime")),
                                             props={k: v for k, v in {"mdm_compliant": (d.get("complianceState") or "").lower() == "compliant" if d.get("complianceState") else None,
                                                                      "disk_encrypted": as_bool(d.get("isEncrypted"))}.items() if v is not None}))

        def securescore():
            profiles = {p["id"]: p for p in self._pages(api, f"{GRAPH}/v1.0/security/secureScoreControlProfiles?$top=500", graph, preview)}
            scores = api.json("GET", f"{GRAPH}/v1.0/security/secureScores?$top=1", headers={"Authorization": f"Bearer {graph}"}).get("value", [])
            if not scores:
                return
            for c in scores[0].get("controlScores", []):
                prof = profiles.get(c.get("controlName"), {})
                if prof.get("deprecated"):
                    continue
                mx, sc = prof.get("maxScore"), c.get("score")
                compliant = None if mx is None or sc is None else float(sc) >= float(mx)
                inv.settings.append(SettingObs(key=f"securescore:{c.get('controlName')}", title=prof.get("title") or c.get("controlName"), compliant=compliant,
                                               category=c.get("controlCategory") or prof.get("controlCategory"), detail=f"Score {sc} of {mx}" if mx is not None else None))
            if not preview:
                inv.complete.add("settings")

        def defender():
            tok = self._token(api, config, secrets, "https://api.securitycenter.microsoft.com/.default")
            machines = self._pages(api, f"{MDE}/api/machines", tok, preview)
            inv.sample_fields["defender machines"] = fields_of(machines[0] if machines else None)
            for m in machines:
                if (m.get("onboardingStatus") or "Onboarded") != "Onboarded":
                    continue
                inv.devices.append(DeviceObs(external_id=f"mde:{m['id']}", name=m.get("computerDnsName") or m["id"], category="edr", hostname=m.get("computerDnsName"),
                                             aad_device_id=m.get("aadDeviceId"), os=m.get("osPlatform"), os_version=m.get("osVersion"),
                                             device_type=device_type_from(m.get("osPlatform")), last_seen=parse_time(m.get("lastSeen")),
                                             props={"edr_active": (m.get("healthStatus") or "").lower() == "active"}))
            vulns = self._pages(api, f"{MDE}/api/machines/SoftwareVulnerabilitiesByMachine?pageSize=10000", tok, preview, limit=400_000)
            inv.sample_fields["defender vulnerabilities"] = fields_of(vulns[0] if vulns else None)
            for v in vulns:
                sev = severity_from(v.get("vulnerabilitySeverityLevel"))
                if sev == "low":
                    continue
                fs = parse_time(v.get("firstSeenTimestamp"))
                inv.vulns.append(VulnObs(device_external_id=f"mde:{v.get('deviceId')}", key=f"{v.get('cveId')}:{v.get('softwareName', '')}"[:120], title=f"{v.get('cveId')} in {v.get('softwareName') or 'software'}",
                                         severity=sev, cve=v.get("cveId"), exploitable=(v.get("exploitabilityLevel") or "").lower() in EXPLOITED, first_seen=fs.date() if fs else None))
            if not preview:
                inv.complete.update({"vulns"})

        part("Entra ID accounts", identities)
        part("Intune devices", intune)
        part("Secure Score", securescore)
        part("Defender for Endpoint", defender)
        if not preview and not any("Intune" in n or "Defender" in n for n in inv.notes):
            inv.complete.add("devices")  # only when every device source answered
        return inv
