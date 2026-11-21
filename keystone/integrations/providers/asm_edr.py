"""EDR connectors (read-only): CrowdStrike Falcon, SentinelOne, Sophos Central."""

from __future__ import annotations

from urllib.parse import quote

from keystone.asm.vocabulary import DeviceObs, Inventory, as_bool, device_type_from, parse_time, pick

from ..http import Api, ConnectorError, HostPolicy, fields_of, validate_base_url
from .base import ConfigField, InventoryProvider, SetupStep, alert_severity, pull_alerts_field

# ---- CrowdStrike Falcon --------------------------------------------------------------------------------

CS_CLOUDS = {"us-1": "api.crowdstrike.com", "us-2": "api.us-2.crowdstrike.com", "eu-1": "api.eu-1.crowdstrike.com", "us-gov-1": "api.laggar.gcw.crowdstrike.com"}


class CrowdStrikeProvider(InventoryProvider):
    key = "crowdstrike"
    name = "CrowdStrike Falcon"
    description = "Read-only: hosts with a Falcon sensor, their status and last check-in."
    category = "edr"
    mapping_note = "Field names from the Falcon Hosts API (devices/queries/devices/v1, devices/entities/devices/v2)."
    fields = (
        ConfigField("cloud", "Falcon cloud", help="us-1, us-2, eu-1 or us-gov-1 (from your console address).", example="us-1"),
        ConfigField("client_id", "API client ID"),
        ConfigField("client_secret", "API client secret", secret=True),
        pull_alerts_field("the Alerts: Read scope"),
    )
    pulls_alerts = True
    setup = (
        SetupStep("Create a read-only API client", "Falcon console > Support and resources > API clients and keys > Add new API client. Scope: Hosts, Read only "
                  "(and Alerts, Read only, to bring alerts into the Alert inbox). Copy the client ID and secret.",
                  link="https://falcon.crowdstrike.com/api-clients-and-keys", link_label="API clients and keys"),
        SetupStep("Check", "Choose Test connection; Keystone lists how many hosts it read.", kind="verify"),
    )

    def _connect(self, config: dict, secrets: dict) -> tuple[Api, str, dict]:
        host = CS_CLOUDS.get((config.get("cloud") or "us-1").strip().lower())
        if not host:
            raise ConnectorError(f"Falcon cloud must be one of {', '.join(CS_CLOUDS)}.")
        api = Api(HostPolicy(hosts=frozenset({host})))
        base = f"https://{host}"
        tok = api.json("POST", f"{base}/oauth2/token", data={"client_id": config.get("client_id", ""), "client_secret": secrets.get("client_secret", "")}).get("access_token")
        if not tok:
            raise ConnectorError("CrowdStrike didn't return an access token.")
        return api, base, {"Authorization": f"Bearer {tok}"}

    def fetch_alerts(self, config: dict, secrets: dict, since) -> list[dict]:
        api, base, auth = self._connect(config, secrets)
        flt = quote(f"created_timestamp:>'{since:%Y-%m-%dT%H:%M:%SZ}'", safe="")
        ids = api.json("GET", f"{base}/alerts/queries/alerts/v2?filter={flt}&limit=500", headers=auth).get("resources") or []
        if not ids:
            return []
        rows = api.json("POST", f"{base}/alerts/entities/alerts/v2", headers=auth, json={"composite_ids": ids[:500]}).get("resources") or []
        return [{"external_id": r.get("composite_id"), "title": r.get("display_name") or r.get("name") or "CrowdStrike detection",
                 "severity": alert_severity(r.get("severity_name") or r.get("severity")), "category": "malware", "host": pick(r, "device.hostname"),
                 "account": r.get("user_name"), "description": r.get("description"), "link": r.get("falcon_host_link"), "occurred_at": parse_time(r.get("created_timestamp"))}
                for r in rows]

    def collect(self, config: dict, secrets: dict, preview: bool = False) -> Inventory:
        api, base, auth = self._connect(config, secrets)
        ids: list[str] = []
        offset = 0
        while True:
            body = api.json("GET", f"{base}/devices/queries/devices/v1?limit=5000&offset={offset}", headers=auth)
            page = body.get("resources") or []
            ids += page
            total = pick(body, "meta.pagination.total", default=len(ids))
            offset += len(page)
            if preview or not page or offset >= total:
                break
        inv = Inventory()
        for i in range(0, len(ids), 1000 if not preview else 100):
            chunk = ids[i:i + 1000] if not preview else ids[:100]
            details = api.json("POST", f"{base}/devices/entities/devices/v2", headers=auth, json={"ids": chunk}).get("resources") or []
            if details and "crowdstrike hosts" not in inv.sample_fields:
                inv.sample_fields["crowdstrike hosts"] = fields_of(details[0])
            for d in details:
                rfm = (d.get("reduced_functionality_mode") or "no").lower() == "yes"
                inv.devices.append(DeviceObs(external_id=d["device_id"], name=d.get("hostname") or d["device_id"], category="edr", hostname=d.get("hostname"),
                                             serial=d.get("serial_number"), os=d.get("os_version") or d.get("platform_name"), device_type=device_type_from(d.get("product_type_desc") or d.get("platform_name")),
                                             last_seen=parse_time(d.get("last_seen")), props={"edr_active": (d.get("status") or "normal") == "normal" and not rfm}))
            if preview:
                break
        if not preview:
            inv.complete.add("devices")
        return inv


# ---- SentinelOne ----------------------------------------------------------------------------------------

S1_POLICY = HostPolicy(suffixes=(".sentinelone.net",))


class SentinelOneProvider(InventoryProvider):
    key = "sentinelone"
    host_field = "console"
    name = "SentinelOne"
    description = "Read-only: agents, their health, active threats and firewall status."
    category = "edr"
    mapping_note = "Field names from the SentinelOne Management API v2.1 (GET /web/api/v2.1/agents)."
    fields = (
        ConfigField("console", "Console address", help="Your console, e.g. https://acme.sentinelone.net", example="https://acme.sentinelone.net"),
        ConfigField("token", "API token", secret=True, help="A service user with the Viewer role."),
        pull_alerts_field("nothing more: the Viewer role can read threats"),
    )
    pulls_alerts = True
    setup = (
        SetupStep("Create a read-only service user", "Settings > Users > Service Users > Create. Role: Viewer, scope: your account or site. Copy the API token.", link="https://{host}/settings/users", link_label="Open your console"),
        SetupStep("Check", "Choose Test connection; Keystone lists how many agents it read.", kind="verify"),
    )

    def fetch_alerts(self, config: dict, secrets: dict, since) -> list[dict]:
        base = validate_base_url(config.get("console", ""), S1_POLICY)
        api = Api(S1_POLICY, headers={"Authorization": f"ApiToken {secrets.get('token', '')}"})
        rows = api.json("GET", f"{base}/web/api/v2.1/threats?createdAt__gte={quote(since.strftime('%Y-%m-%dT%H:%M:%SZ'), safe='')}&limit=200").get("data") or []
        out = []
        for t in rows:
            info = t.get("threatInfo") or {}
            cls = str(info.get("classification") or "").lower()
            out.append({"external_id": t.get("id"), "title": f"{info.get('threatName') or 'Threat'} ({info.get('classification') or 'unclassified'})",
                        "severity": "high" if info.get("confidenceLevel") == "malicious" else "medium", "category": "ransomware" if "ransom" in cls else "malware",
                        "host": pick(t, "agentRealtimeInfo.agentComputerName"), "account": info.get("processUser"),
                        "description": f"Mitigation: {info.get('mitigationStatus') or 'unknown'}", "occurred_at": parse_time(info.get("createdAt"))})
        return out

    def collect(self, config: dict, secrets: dict, preview: bool = False) -> Inventory:
        base = validate_base_url(config.get("console", ""), S1_POLICY)
        api = Api(S1_POLICY, headers={"Authorization": f"ApiToken {secrets.get('token', '')}"})
        inv, cursor = Inventory(), None
        while True:
            body = api.json("GET", f"{base}/web/api/v2.1/agents?limit={100 if preview else 1000}" + (f"&cursor={quote(cursor, safe='')}" if cursor else ""))
            rows = body.get("data") or []
            if rows and "sentinelone agents" not in inv.sample_fields:
                inv.sample_fields["sentinelone agents"] = fields_of(rows[0])
            for a in rows:
                props = {"edr_active": None if a.get("isActive") is None else bool(a.get("isActive")) and not a.get("infected"),
                         "threats_active": a.get("activeThreats"), "firewall_on": as_bool(a.get("firewallEnabled"))}
                inv.devices.append(DeviceObs(external_id=str(a["id"]), name=a.get("computerName") or str(a["id"]), category="edr", hostname=a.get("computerName"),
                                             serial=a.get("serialNumber"), os=a.get("osName"), os_version=a.get("osRevision"),
                                             device_type="server" if (a.get("machineType") or "").lower() == "server" else device_type_from(a.get("machineType") or a.get("osName")),
                                             last_seen=parse_time(a.get("lastActiveDate")), props={k: v for k, v in props.items() if v is not None}))
            cursor = pick(body, "pagination.nextCursor")
            if preview or not cursor:
                break
        if not preview:
            inv.complete.add("devices")
        return inv


# ---- Sophos Central ----------------------------------------------------------------------------------------

SOPHOS_POLICY = HostPolicy(hosts=frozenset({"id.sophos.com", "api.central.sophos.com"}), suffixes=(".central.sophos.com",))


class SophosProvider(InventoryProvider):
    key = "sophos"
    name = "Sophos Central"
    description = "Read-only: endpoints and servers, overall health, tamper protection and disk encryption."
    category = "edr"
    mapping_note = "Field names from the Sophos Central Endpoint API v1 (whoami, endpoint/v1/endpoints)."
    fields = (
        ConfigField("client_id", "Client ID"),
        ConfigField("client_secret", "Client secret", secret=True),
        pull_alerts_field("nothing more: Service Principal ReadOnly can read alerts"),
    )
    pulls_alerts = True
    setup = (
        SetupStep("Create read-only API credentials", "Sophos Central > Global settings > API Credentials Management > Add credential. Role: Service Principal ReadOnly. Use credentials for your tenant (not a partner or organisation)."),
        SetupStep("Check", "Choose Test connection; Keystone lists how many endpoints it read.", kind="verify"),
    )

    def _connect(self, config: dict, secrets: dict) -> tuple[Api, str, dict]:
        api = Api(SOPHOS_POLICY)
        tok = api.json("POST", "https://id.sophos.com/api/v2/oauth2/token", data={"grant_type": "client_credentials", "client_id": config.get("client_id", ""),
                                                                                 "client_secret": secrets.get("client_secret", ""), "scope": "token"}).get("access_token")
        if not tok:
            raise ConnectorError("Sophos didn't return an access token.")
        who = api.json("GET", "https://api.central.sophos.com/whoami/v1", headers={"Authorization": f"Bearer {tok}"})
        if who.get("idType") != "tenant":
            raise ConnectorError("Use API credentials created for a tenant; partner and organisation credentials aren't supported.")
        region = validate_base_url(pick(who, "apiHosts.dataRegion", default=""), SOPHOS_POLICY)
        return api, region, {"Authorization": f"Bearer {tok}", "X-Tenant-ID": who.get("id", "")}

    def fetch_alerts(self, config: dict, secrets: dict, since) -> list[dict]:
        api, region, hdr = self._connect(config, secrets)
        items = api.json("GET", f"{region}/common/v1/alerts?from={quote(since.strftime('%Y-%m-%dT%H:%M:%SZ'), safe='')}&pageSize=100", headers=hdr).get("items") or []
        return [{"external_id": a.get("id"), "title": a.get("description") or "Sophos alert", "severity": alert_severity(a.get("severity")),
                 "category": "malware" if "malware" in str(a.get("category") or "").lower() else "other", "host": pick(a, "managedAgent.name"),
                 "account": pick(a, "person.name"), "description": a.get("description"), "occurred_at": parse_time(a.get("raisedAt"))} for a in items]

    def collect(self, config: dict, secrets: dict, preview: bool = False) -> Inventory:
        api, region, hdr = self._connect(config, secrets)
        inv, key = Inventory(), None
        while True:
            body = api.json("GET", f"{region}/endpoint/v1/endpoints?pageSize={100 if preview else 500}&pageTotal=false" + (f"&pageFromKey={quote(key, safe='')}" if key else ""), headers=hdr)
            items = body.get("items") or []
            if items and "sophos endpoints" not in inv.sample_fields:
                inv.sample_fields["sophos endpoints"] = fields_of(items[0])
            for e in items:
                vols = pick(e, "encryption.volumes", default=None)
                encrypted = None if not vols else all((v.get("status") or "").lower() == "encrypted" for v in vols)
                props = {"edr_active": pick(e, "health.overall") == "good" if pick(e, "health.overall") else None, "tamper_protection": e.get("tamperProtectionEnabled"),
                         "disk_encrypted": encrypted, "threats_active": 0 if pick(e, "health.threats.status") == "good" else (1 if pick(e, "health.threats.status") else None)}
                inv.devices.append(DeviceObs(external_id=e["id"], name=e.get("hostname") or e["id"], category="edr", hostname=e.get("hostname"),
                                             os=pick(e, "os.name"), device_type="server" if e.get("type") == "server" else "workstation",
                                             owner_email=pick(e, "associatedPerson.viaLogin") if "@" in str(pick(e, "associatedPerson.viaLogin", default="")) else None,
                                             last_seen=parse_time(e.get("lastSeenAt")), props={k: v for k, v in props.items() if v is not None}))
            key = pick(body, "pages.nextKey")
            if preview or not key:
                break
        if not preview:
            inv.complete.add("devices")
        return inv
