"""Device management connectors (read-only): Jamf Pro and Kandji, plus the fleet checks shared with Intune.

Approved with the round 9 request (human:sneh, 2026-11-21). Hosts: the organisation's own Jamf Pro server (Jamf Cloud
under *.jamfcloud.com, or a self-hosted server bound to its credentials), and the organisation's Kandji tenant under
*.api.kandji.io or *.api.eu.kandji.io. Only device lists are read.
"""

from __future__ import annotations

import re
from datetime import timedelta

from keystone.asm.vocabulary import DeviceObs, Inventory, device_type_from, parse_time, pick
from keystone.core.db import utcnow

from ..http import Api, ConnectorError, HostPolicy, fields_of, validate_base_url
from .base import CheckDef, ConfigField, InventoryProvider, Outcome, SetupStep

CHECKIN_DAYS = 30  # devices that haven't checked in for this long are out of management in practice
FLEET_CHECKS = (
    CheckDef("fleet_encrypted", "Every managed computer's disk is encrypted", ("KC-TEC-01", "KC-TEC-24")),
    CheckDef("fleet_checked_in", f"Every managed device checked in within {CHECKIN_DAYS} days", ("KC-TEC-01", "KC-ORG-09")),
)


def fleet_checks(inv: Inventory, source: str) -> list[Outcome]:
    """Encryption and check-in across the devices a management tool reported. Unknown values are never a pass."""
    devices = [d for d in inv.devices if d.category == "mdm"]
    if "devices" not in inv.complete or not devices:
        why = "No managed devices were read" if "devices" in inv.complete else f"{source} devices weren't fully read"
        return [Outcome("fleet_encrypted", "unknown", why), Outcome("fleet_checked_in", "unknown", why)]
    computers = [d for d in devices if d.device_type in ("workstation", "server")]  # phones and tablets encrypt by design
    plain = sorted(d.name for d in computers if d.props.get("disk_encrypted") is False)
    unknown = [d for d in computers if "disk_encrypted" not in d.props]
    if not computers:
        enc = Outcome("fleet_encrypted", "unknown", "No managed computers were read")
    elif plain:
        enc = Outcome("fleet_encrypted", "fail", f"{len(plain)} of {len(computers)} computers not encrypted: {', '.join(plain[:8])}", {"not_encrypted": plain[:500]})
    elif unknown:
        enc = Outcome("fleet_encrypted", "unknown", f"Encryption unknown for {len(unknown)} of {len(computers)} computers")
    else:
        enc = Outcome("fleet_encrypted", "pass", f"All {len(computers)} computers encrypted")
    cutoff = utcnow() - timedelta(days=CHECKIN_DAYS)
    stale = sorted(d.name for d in devices if d.last_seen is not None and d.last_seen < cutoff)
    never = [d for d in devices if d.last_seen is None]
    if stale:
        seen = Outcome("fleet_checked_in", "fail", f"{len(stale)} of {len(devices)} devices haven't checked in for {CHECKIN_DAYS} days: {', '.join(stale[:8])}", {"stale": stale[:500]})
    elif never:
        seen = Outcome("fleet_checked_in", "unknown", f"Last check-in unknown for {len(never)} devices")
    else:
        seen = Outcome("fleet_checked_in", "pass", f"All {len(devices)} devices checked in within {CHECKIN_DAYS} days")
    return [enc, seen]


# ---- Jamf Pro ----------------------------------------------------------------------------------------------------

JAMF = HostPolicy(suffixes=(".jamfcloud.com",), self_hosted=True)
SECTIONS = "section=GENERAL&section=HARDWARE&section=OPERATING_SYSTEM&section=DISK_ENCRYPTION&section=USER_AND_LOCATION"


class JamfProProvider(InventoryProvider):
    key = "jamf"
    name = "Jamf Pro"
    description = "Read-only: Macs managed by Jamf Pro, their FileVault state, macOS version and last check-in."
    category = "mdm"
    host_field = "server"
    mapping_note = ("Field names from the Jamf Pro API reference: POST /api/oauth/token, GET /api/v1/computers-inventory (general.name, general.lastContactTime, "
                    "hardware.serialNumber, operatingSystem.version, diskEncryption.bootPartitionEncryptionDetails.partitionFileVault2State, userAndLocation.email). "
                    "Confirm them with Test connection.")
    checks = FLEET_CHECKS
    fields = (
        ConfigField("server", "Jamf Pro server", help="e.g. https://yourcompany.jamfcloud.com. Changing it requires entering the secret again.", example="https://yourcompany.jamfcloud.com"),
        ConfigField("client_id", "Client ID"),
        ConfigField("client_secret", "Client secret", secret=True, help="Note when it expires and enter the date below."),
    )
    setup = (
        SetupStep("Create a read-only API role", "Jamf Pro > Settings > System > API roles and clients > API Roles > New. Name it “Keystone (read-only)” "
                  "and give it one privilege: Read Computers. Nothing else."),
        SetupStep("Create an API client", "API Clients > New: display name “Keystone”, the role above, enabled. Generate a client secret and copy the client ID and secret."),
        SetupStep("Self-hosted server inside your network?", "The server operator must add its name to KEYSTONE_INTEGRATION_PRIVATE_HOSTS."),
        SetupStep("Check", "Choose Test connection; Keystone lists the Macs it read and the fields it saw.", kind="verify"),
    )

    def collect(self, config: dict, secrets: dict, preview: bool = False) -> Inventory:
        base = validate_base_url(config.get("server", ""), JAMF)
        api = Api(JAMF)
        tok = api.json("POST", f"{base}/api/oauth/token", data={"grant_type": "client_credentials", "client_id": (config.get("client_id") or "").strip(),
                                                             "client_secret": secrets.get("client_secret", "")}).get("access_token")
        if not tok:
            raise ConnectorError("Jamf Pro didn't return an access token.")
        auth = {"Authorization": f"Bearer {tok}"}
        inv, page = Inventory(), 0
        size = 100 if preview else 500
        while True:
            body = api.json("GET", f"{base}/api/v1/computers-inventory?{SECTIONS}&page={page}&page-size={size}", headers=auth)
            rows = body.get("results") or []
            if rows and "jamf computers" not in inv.sample_fields:
                inv.sample_fields["jamf computers"] = fields_of(rows[0])
            for c in rows:
                state = pick(c, "diskEncryption.bootPartitionEncryptionDetails.partitionFileVault2State")
                props = {"disk_encrypted": (str(state).upper() == "ENCRYPTED") if state else None, "mdm_managed": pick(c, "general.remoteManagement.managed")}
                name = pick(c, "general.name") or str(c.get("id"))
                inv.devices.append(DeviceObs(external_id=f"jamf:{c.get('id')}", name=name, category="mdm", hostname=name, serial=pick(c, "hardware.serialNumber"),
                                             os="macOS", os_version=pick(c, "operatingSystem.version"), device_type="workstation",
                                             owner_email=pick(c, "userAndLocation.email") or None, last_seen=parse_time(pick(c, "general.lastContactTime")),
                                             props={k: v for k, v in props.items() if v is not None}))
            total = int(body.get("totalCount") or 0)
            page += 1
            if preview or not rows or page * size >= total:
                break
        if not preview:
            inv.complete.add("devices")
        return inv

    def assess(self, inventory) -> list[Outcome]:
        return fleet_checks(inventory, "Jamf Pro")


# ---- Kandji ------------------------------------------------------------------------------------------------------

KANDJI = HostPolicy(suffixes=(".api.kandji.io", ".api.eu.kandji.io"))
SUBDOMAIN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
KANDJI_DETAILS_MAX = 1000  # FileVault state needs one call per device; larger fleets get a note instead


class KandjiProvider(InventoryProvider):
    key = "kandji"
    name = "Kandji"
    description = "Read-only: Apple devices managed by Kandji, FileVault state, OS version and last check-in."
    category = "mdm"
    mapping_note = ("Field names from the Kandji API reference: GET /api/v1/devices (device_id, device_name, serial_number, platform, os_version, last_check_in, user.email) "
                    "and /api/v1/devices/{id}/details (filevault.filevault_enabled). Confirm them with Test connection.")
    checks = FLEET_CHECKS
    fields = (
        ConfigField("subdomain", "Tenant sub-domain", help="The first part of your Kandji API address, e.g. yourcompany in yourcompany.api.kandji.io.", example="yourcompany"),
        ConfigField("region", "Region", options=(("us", "United States"), ("eu", "Europe"))),
        ConfigField("token", "API token", secret=True, help="Note when it expires and enter the date below."),
    )
    setup = (
        SetupStep("Create a read-only API token", "Kandji > Settings > Access > API Token > Add Token. Name it “Keystone (read-only)”, then under Manage API Permissions "
                  "allow only Devices: Device list and Device details. Copy the token: Kandji shows it once."),
        SetupStep("Check", "Choose Test connection; Keystone lists the devices it read and the fields it saw.", kind="verify"),
    )

    def collect(self, config: dict, secrets: dict, preview: bool = False) -> Inventory:
        sub = (config.get("subdomain") or "").strip().lower()
        if not SUBDOMAIN.match(sub):
            raise ConnectorError("Enter the sub-domain only (letters, digits and hyphens), e.g. yourcompany.")
        host = f"{sub}.api.eu.kandji.io" if config.get("region") == "eu" else f"{sub}.api.kandji.io"
        api, base = Api(KANDJI), f"https://{host}"
        auth = {"Authorization": f"Bearer {secrets.get('token', '')}"}
        inv, offset, devices = Inventory(), 0, []
        while True:
            rows = api.json("GET", f"{base}/api/v1/devices?limit=300&offset={offset}", headers=auth)
            if not isinstance(rows, list) or not rows:
                break
            devices += rows
            offset += len(rows)
            if preview or len(rows) < 300:
                break
        inv.sample_fields["kandji devices"] = fields_of(devices[0] if devices else None)
        details = not preview and len(devices) <= KANDJI_DETAILS_MAX
        if not preview and not details:
            inv.notes.append(f"FileVault state not read: more than {KANDJI_DETAILS_MAX} devices")
        for d in devices:
            if d.get("is_removed"):
                continue
            props: dict = {}
            if details and (d.get("platform") or "").lower() == "mac":
                fv = pick(api.json("GET", f"{base}/api/v1/devices/{d['device_id']}/details", headers=auth), "filevault.filevault_enabled")
                if isinstance(fv, bool):
                    props["disk_encrypted"] = fv
            name = d.get("device_name") or str(d.get("device_id"))
            inv.devices.append(DeviceObs(external_id=f"kandji:{d.get('device_id')}", name=name, category="mdm", hostname=name, serial=d.get("serial_number"),
                                         os={"mac": "macOS", "iphone": "iOS", "ipad": "iPadOS", "apple tv": "tvOS"}.get((d.get("platform") or "").lower(), d.get("platform")),
                                         os_version=d.get("os_version"), device_type=device_type_from(d.get("platform")),
                                         owner_email=pick(d, "user.email") or None, last_seen=parse_time(d.get("last_check_in")), props=props))
        if not preview:
            inv.complete.add("devices")
        return inv

    def assess(self, inventory) -> list[Outcome]:
        out = fleet_checks(inventory, "Kandji")
        if any("FileVault state not read" in n for n in inventory.notes):
            out[0] = Outcome("fleet_encrypted", "unknown", f"FileVault state isn't read for more than {KANDJI_DETAILS_MAX} devices")
        return out
