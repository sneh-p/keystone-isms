"""RMM connectors (read-only): NinjaOne, Datto RMM, N-able N-central, ConnectWise Automate."""

from __future__ import annotations

import base64
from collections import Counter
from datetime import timedelta
from urllib.parse import quote

from keystone.asm.vocabulary import DeviceObs, Inventory, device_type_from, parse_time, pick
from keystone.core.db import utcnow

from ..http import Api, ConnectorError, HostPolicy, fields_of, validate_base_url
from .base import ConfigField, InventoryProvider, SetupStep

# ---- NinjaOne ------------------------------------------------------------------------------------------------

NINJA_REGIONS = {"us": "app.ninjarmm.com", "us2": "us2.ninjarmm.com", "eu": "eu.ninjarmm.com", "ca": "ca.ninjarmm.com", "oc": "oc.ninjarmm.com"}


class NinjaOneProvider(InventoryProvider):
    key = "ninjaone"
    name = "NinjaOne"
    description = "Read-only: devices, pending security patches and anti-malware status."
    category = "rmm"
    mapping_note = ("Devices from /v2/devices-detailed; patches from /v2/queries/os-patches; anti-malware from /v2/queries/antivirus-status. "
                    "Endpoint names confirmed from NinjaOne's public API listing; some field names come from community libraries, so confirm them with Test connection.")
    fields = (
        ConfigField("region", "Region", help="us, us2, eu, ca or oc (the start of your NinjaOne address).", example="us"),
        ConfigField("client_id", "Client ID"),
        ConfigField("client_secret", "Client secret", secret=True),
    )
    setup = (
        SetupStep("Create an API client", "NinjaOne > Administration > Apps > API > Client app IDs > Add. Platform: API services (machine-to-machine), scope: Monitoring only, grant type: Client credentials."),
        SetupStep("Check", "Choose Test connection; Keystone lists the devices it read and which fields it saw.", kind="verify"),
    )

    def collect(self, config: dict, secrets: dict, preview: bool = False) -> Inventory:
        host = NINJA_REGIONS.get((config.get("region") or "us").strip().lower())
        if not host:
            raise ConnectorError(f"Region must be one of {', '.join(NINJA_REGIONS)}.")
        api, base = Api(HostPolicy(hosts=frozenset({host}))), f"https://{host}"
        tok = api.json("POST", f"{base}/ws/oauth/token", data={"grant_type": "client_credentials", "client_id": config.get("client_id", ""),
                                                             "client_secret": secrets.get("client_secret", ""), "scope": "monitoring"}).get("access_token")
        if not tok:
            raise ConnectorError("NinjaOne didn't return an access token.")
        auth = {"Authorization": f"Bearer {tok}"}
        inv, after = Inventory(), 0
        devices = []
        while True:
            page = api.json("GET", f"{base}/v2/devices-detailed?pageSize={100 if preview else 1000}&after={after}", headers=auth)
            if not isinstance(page, list) or not page:
                break
            devices += page
            after = max(d.get("id", 0) for d in page)
            if preview or len(page) < 1000:
                break
        inv.sample_fields["ninjaone devices"] = fields_of(devices[0] if devices else None)
        pending: Counter = Counter()
        av: dict = {}
        try:
            cursor = None
            while True:
                body = api.json("GET", f"{base}/v2/queries/os-patches?status=APPROVED&pageSize=1000" + (f"&cursor={quote(cursor, safe='')}" if cursor else ""), headers=auth)
                for r in body.get("results") or []:
                    if (r.get("severity") or "").upper() in ("CRITICAL", "IMPORTANT"):
                        pending[r.get("deviceId")] += 1
                cursor = pick(body, "cursor.name")
                if preview or not cursor or not body.get("results"):
                    break
            for r in (api.json("GET", f"{base}/v2/queries/antivirus-status?pageSize=1000", headers=auth).get("results") or []):
                av[r.get("deviceId")] = (r.get("definitionStatus") or "").upper() in ("UP_TO_DATE", "UPTODATE")
        except ConnectorError as e:
            inv.notes.append(f"Patch or anti-malware report unavailable ({e})")
            pending, av = None, {}
        for d in devices:
            props = {"av_up_to_date": av.get(d["id"])}
            if pending is not None:
                props["patches_pending"] = pending.get(d["id"], 0)
            inv.devices.append(DeviceObs(external_id=str(d["id"]), name=d.get("systemName") or d.get("dnsName") or str(d["id"]), category="rmm",
                                         hostname=d.get("dnsName") or d.get("systemName"), serial=pick(d, "system.serialNumber"), os=pick(d, "os.name"),
                                         device_type=device_type_from(d.get("nodeClass")), last_seen=parse_time(d.get("lastContact")),
                                         props={k: v for k, v in props.items() if v is not None}))
        if not preview:
            inv.complete.add("devices")
        return inv


# ---- Datto RMM -------------------------------------------------------------------------------------------------

DATTO_PLATFORMS = ("pinotage", "merlot", "concord", "vidal", "zinfandel", "syrah")


class DattoRmmProvider(InventoryProvider):
    key = "datto_rmm"
    name = "Datto RMM"
    description = "Read-only: devices, anti-malware status and approved patches waiting to install."
    category = "rmm"
    mapping_note = "Field names from the Datto RMM API v2 (account/devices: antivirus.antivirusStatus, patchManagement.patchesApprovedPending, lastSeen)."
    fields = (
        ConfigField("platform", "Platform", help="Your Datto RMM platform: pinotage, merlot, concord, vidal, zinfandel or syrah.", example="merlot"),
        ConfigField("api_key", "API key"),
        ConfigField("api_secret", "API secret key", secret=True),
    )
    setup = (
        SetupStep("Enable API access for a read-only user", "Datto RMM > Setup > Global settings > Access control: enable API. Then Setup > Users > a user with a read-only security level > Generate API keys."),
        SetupStep("Check", "Choose Test connection; Keystone lists the devices it read.", kind="verify"),
    )

    def collect(self, config: dict, secrets: dict, preview: bool = False) -> Inventory:
        platform = (config.get("platform") or "").strip().lower()
        if platform not in DATTO_PLATFORMS:
            raise ConnectorError(f"Platform must be one of {', '.join(DATTO_PLATFORMS)}.")
        host = f"{platform}-api.centrastage.net"
        api, base = Api(HostPolicy(hosts=frozenset({host}))), f"https://{host}"
        basic = base64.b64encode(b"public-client:public").decode()  # Datto's documented public client for the password grant
        tok = api.json("POST", f"{base}/auth/oauth/token", headers={"Authorization": f"Basic {basic}"},
                       data={"grant_type": "password", "username": config.get("api_key", ""), "password": secrets.get("api_secret", "")}).get("access_token")
        if not tok:
            raise ConnectorError("Datto RMM didn't return an access token.")
        auth = {"Authorization": f"Bearer {tok}"}
        inv, url = Inventory(), f"{base}/api/v2/account/devices?max={50 if preview else 250}&page=0"
        while url:
            body = api.json("GET", url, headers=auth)
            rows = body.get("devices") or []
            if rows and "datto devices" not in inv.sample_fields:
                inv.sample_fields["datto devices"] = fields_of(rows[0])
            for d in rows:
                status = pick(d, "antivirus.antivirusStatus")
                props = {"av_up_to_date": None if status in (None, "NotDetected") else status == "RunningAndUpToDate", "patches_pending": pick(d, "patchManagement.patchesApprovedPending")}
                inv.devices.append(DeviceObs(external_id=d["uid"], name=d.get("hostname") or d["uid"], category="rmm", hostname=d.get("hostname"), os=d.get("operatingSystem"),
                                             device_type=device_type_from(pick(d, "deviceType.category") or d.get("operatingSystem")), last_seen=parse_time(d.get("lastSeen")),
                                             props={k: v for k, v in props.items() if v is not None}))
            url = None if preview else pick(body, "pageDetails.nextPageUrl")
        if not preview:
            inv.complete.add("devices")
        return inv


# ---- N-able N-central (self-hosted or N-able hosted server) ---------------------------------------------------------

SELF_HOSTED = HostPolicy(self_hosted=True)


class NCentralProvider(InventoryProvider):
    key = "ncentral"
    name = "N-able N-central"
    description = "Read-only: managed devices and when each last checked in (the REST device list has no security status)."
    category = "rmm"
    host_field = "server"
    mapping_note = "Field names from N-central's REST API reference (POST /api/auth/authenticate, GET /api/devices: deviceId, longName, deviceClass, supportedOsLabel, lastApplianceCheckinTime)."
    fields = (
        ConfigField("server", "N-central server", help="e.g. https://ncentral.example.com. Changing it requires entering the token again.", example="https://ncentral.example.com"),
        ConfigField("jwt", "API user token (JWT)", secret=True, help="Administration > User Management > Users > an API-only read-only user > API Access > Generate JSON Web Token."),
    )
    setup = (
        SetupStep("Create a read-only API user", "In N-central create a user with a read-only role and MFA off (API-only users can't use MFA), then generate its JSON Web Token under API Access."),
        SetupStep("Internal server?", "If N-central is only reachable inside your network, the server operator must add its name to KEYSTONE_INTEGRATION_PRIVATE_HOSTS."),
        SetupStep("Check", "Choose Test connection; Keystone lists the devices it read.", kind="verify"),
    )

    def collect(self, config: dict, secrets: dict, preview: bool = False) -> Inventory:
        base = validate_base_url(config.get("server", ""), SELF_HOSTED)
        api = Api(SELF_HOSTED)
        tok = pick(api.json("POST", f"{base}/api/auth/authenticate", headers={"Authorization": f"Bearer {secrets.get('jwt', '')}"}), "tokens.access.token")
        if not tok:
            raise ConnectorError("N-central didn't return an access token.")
        inv, page = Inventory(), 1
        while True:
            body = api.json("GET", f"{base}/api/devices?pageNumber={page}&pageSize={50 if preview else 1000}", headers={"Authorization": f"Bearer {tok}"})
            rows = body.get("data") or []
            if rows and "ncentral devices" not in inv.sample_fields:
                inv.sample_fields["ncentral devices"] = fields_of(rows[0])
            for d in rows:
                if d.get("isProbe"):
                    continue
                inv.devices.append(DeviceObs(external_id=str(d["deviceId"]), name=d.get("longName") or str(d["deviceId"]), category="rmm", hostname=d.get("longName"),
                                             os=d.get("supportedOsLabel"), device_type=device_type_from(d.get("deviceClass") or d.get("deviceClassLabel")),
                                             last_seen=parse_time(d.get("lastApplianceCheckinTime"))))
            if preview or page >= int(body.get("totalPages") or 1):
                break
            page += 1
        if not preview:
            inv.complete.add("devices")
        return inv


# ---- ConnectWise Automate (self-hosted server) -------------------------------------------------------------------------


class ConnectWiseAutomateProvider(InventoryProvider):
    key = "cw_automate"
    name = "ConnectWise Automate"
    description = "Read-only: computers, last contact and anti-malware definition age."
    category = "rmm"
    host_field = "server"
    mapping_note = ("POST /cwa/api/v1/apitoken and GET /cwa/api/v1/computers (paged). Field names (ComputerName, SerialNumber, OperatingSystemName, LastContact, "
                    "VirusDefinitionDate) come from community libraries; confirm them with Test connection, which lists the fields your server returns.")
    fields = (
        ConfigField("server", "Automate server", help="e.g. https://automate.example.com. Changing it requires entering the password again.", example="https://automate.example.com"),
        ConfigField("client_id", "Integrator client ID", help="The ClientID ConnectWise issued to you (required since Automate 2020.11)."),
        ConfigField("username", "API user name", help="An integrator or user account with read-only rights."),
        ConfigField("password", "Password", secret=True),
    )
    setup = (
        SetupStep("Get a ClientID and a read-only account", "Register for a ClientID on the ConnectWise developer site, then create an Automate integrator account with read-only permissions.",
                  link="https://developer.connectwise.com/ClientID", link_label="ConnectWise ClientID"),
        SetupStep("Internal server?", "If Automate is only reachable inside your network, the server operator must add its name to KEYSTONE_INTEGRATION_PRIVATE_HOSTS."),
        SetupStep("Check", "Choose Test connection; Keystone lists the computers it read and the fields your server returned.", kind="verify"),
    )

    def collect(self, config: dict, secrets: dict, preview: bool = False) -> Inventory:
        base = validate_base_url(config.get("server", ""), SELF_HOSTED)
        api = Api(SELF_HOSTED, headers={"ClientId": config.get("client_id", "")})
        tok = api.json("POST", f"{base}/cwa/api/v1/apitoken", json={"UserName": config.get("username", ""), "Password": secrets.get("password", "")}).get("AccessToken")
        if not tok:
            raise ConnectorError("Automate didn't return an access token.")
        inv, page, now = Inventory(), 1, utcnow()
        while True:
            rows = api.json("GET", f"{base}/cwa/api/v1/computers?pageSize={50 if preview else 1000}&page={page}", headers={"Authorization": f"Bearer {tok}"})
            if not isinstance(rows, list) or not rows:
                break
            if "automate computers" not in inv.sample_fields:
                inv.sample_fields["automate computers"] = fields_of(rows[0])
            for c in rows:
                defs = parse_time(pick(c, "VirusDefinitionDate", "AntivirusDefinitionDate"))
                props = {"av_up_to_date": (now - defs) <= timedelta(days=7) if defs else None}
                inv.devices.append(DeviceObs(external_id=str(c["Id"]), name=c.get("ComputerName") or str(c["Id"]), category="rmm", hostname=c.get("ComputerName"),
                                             serial=c.get("SerialNumber"), os=pick(c, "OperatingSystemName", "OS"),
                                             device_type="server" if "server" in str(pick(c, "OperatingSystemName", "OS", default="")).lower() else "workstation",
                                             last_seen=parse_time(pick(c, "LastContact", "LastHeartbeat")), props={k: v for k, v in props.items() if v is not None}))
            if preview or len(rows) < 1000:
                break
            page += 1
        if not preview:
            inv.complete.add("devices")
        return inv
