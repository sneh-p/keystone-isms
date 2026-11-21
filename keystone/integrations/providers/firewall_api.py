"""Firewall configurations read over the firewall's own read-only API (round 9, approved by human:sneh, 2026-11-21),
instead of uploading an export by hand. Each run reads the configuration, checks it against the configuration
baselines exactly like an upload (keystone/configcheck/service.fetched_firewall), and keeps only the values checked and
the SHA-256: never the file, which holds password hashes and keys.

The firewall is usually inside your network: its address must be listed in KEYSTONE_INTEGRATION_PRIVATE_HOSTS, and its
management certificate must be trusted (a public certificate, or your own CA in KEYSTONE_EXTRA_CA_FILE). Certificates
are always verified; credentials are bound to the address they were entered for (SC-SSRF-003).
"""

from __future__ import annotations

from urllib.parse import urlparse
from xml.etree.ElementTree import tostring  # serialising only; parsing goes through defusedxml (parsers._xml)

from ..http import Api, ConnectorError, HostPolicy, validate_base_url
from .base import CheckDef, ConfigField, Outcome, Provider, SetupStep

SELF_HOSTED = HostPolicy(self_hosted=True)
CHECK = CheckDef("config_read", "Configuration read and checked against the baselines", ())


class FirewallApiProvider(Provider):
    platform = ""
    host_field = "server"
    checks = (CHECK,)
    stores_results = True

    def fetch(self, base: str, secrets: dict) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError

    def describe(self) -> dict:
        return {**super().describe(), "firewall": True}

    def run(self, config: dict, secrets: dict, session=None) -> list[Outcome]:
        from keystone.configcheck.parsers import ParseError
        from keystone.configcheck.service import fetched_firewall

        base = validate_base_url(config.get("server", ""), SELF_HOSTED)
        data = self.fetch(base, secrets)
        if session is None:  # Test connection: read and parse, store nothing
            from keystone.configcheck.parsers import parse

            try:
                parsed = parse(self.platform, data)
            except ParseError as e:
                raise ConnectorError(f"The configuration couldn't be read: {e}") from None
            return [Outcome("config_read", "pass", f"Read {len(data):,} bytes; {len(parsed.facts)} setting(s) found. Nothing was stored.")]
        try:
            t, result, _ = fetched_firewall(session, platform=self.platform, source=f"API: {urlparse(base).hostname}", data=data, name=(config.get("name") or "").strip() or None)
        except ParseError as e:
            raise ConnectorError(f"The configuration couldn't be read: {e}") from None
        return [Outcome("config_read", "pass", f"{t.name}: {result['fail']} failing, {result['unknown']} unknown, {result['pass']} passing",
                        {"target_id": t.id, "sha256": t.source_sha256})]


class FortiGateApiProvider(FirewallApiProvider):
    key = "fortigate_api"
    name = "FortiGate (configuration by API)"
    platform = "fortigate"
    description = "Reads the FortiGate's configuration backup through its REST API with a read-only administrator, and checks it against your FortiGate baseline."
    fields = (
        ConfigField("server", "Firewall management address", help="e.g. https://fw1.example.org. Changing it requires entering the key again.", example="https://fw1.example.org"),
        ConfigField("token", "REST API key", secret=True, help="Of a REST API administrator with a read-only profile."),
        ConfigField("name", "Name in Keystone", required=False, help="Defaults to the host name in the configuration."),
    )
    setup = (
        SetupStep("Create a read-only profile", "System > Admin Profiles > Create New: “keystone-readonly”, every permission Read (or None), nothing Read/Write."),
        SetupStep("Create a REST API administrator", "System > Administrators > Create New > REST API Admin: profile keystone-readonly, Trusted Hosts: Keystone's address "
                  "only. Copy the API key; FortiGate shows it once."),
        SetupStep("Let Keystone reach it", "The server operator adds the firewall's name to KEYSTONE_INTEGRATION_PRIVATE_HOSTS, and, if its certificate comes from your own CA, "
                  "puts that CA in the file named by KEYSTONE_EXTRA_CA_FILE. Keystone never skips certificate checks."),
        SetupStep("Check", "Choose Test connection: Keystone reads the configuration, counts the settings it understands, and stores nothing.", kind="verify"),
    )

    def fetch(self, base: str, secrets: dict) -> bytes:
        api = Api(SELF_HOSTED, headers={"Authorization": f"Bearer {secrets.get('token', '')}"})
        url = f"{base}/api/v2/monitor/system/config/backup?scope=global"
        try:
            return api.request("GET", url, headers={"Accept": "*/*"}).content
        except ConnectorError as e:
            if "returned 405" not in str(e):
                raise
        # FortiOS 7.4 and later take the same read-only backup request as a POST.
        return api.request("POST", url, headers={"Accept": "*/*"}, json={"destination": "file", "scope": "global"}).content


class PanOsApiProvider(FirewallApiProvider):
    key = "panos_api"
    name = "PAN-OS (configuration by API)"
    platform = "panos"
    description = "Reads the firewall's running configuration through the PAN-OS XML API with a read-only administrator, and checks it against your PAN-OS baseline."
    fields = (
        ConfigField("server", "Firewall or Panorama-managed firewall address", help="e.g. https://pa1.example.org. Changing it requires entering the key again.",
                    example="https://pa1.example.org"),
        ConfigField("token", "API key", secret=True, help="Of an administrator whose role allows only the XML API's Configuration read."),
        ConfigField("name", "Name in Keystone", required=False, help="Defaults to the host name in the configuration."),
    )
    setup = (
        SetupStep("Create a read-only role", "Device > Admin Roles > Add: “keystone-readonly”. Web UI: all Disable. XML API: only Configuration enabled. REST API and Command Line: none."),
        SetupStep("Create the administrator", "Device > Administrators > Add: that role, a long random password. Then generate its API key; the POST form keeps the password out of logs:",
                  code="curl -s -X POST 'https://{host}/api/?type=keygen' --data-urlencode 'user=keystone' --data-urlencode 'password=…'"),
        SetupStep("Let Keystone reach it", "The server operator adds the firewall's name to KEYSTONE_INTEGRATION_PRIVATE_HOSTS, and, if its certificate comes from your own CA, "
                  "puts that CA in the file named by KEYSTONE_EXTRA_CA_FILE. Keystone never skips certificate checks."),
        SetupStep("Check", "Choose Test connection: Keystone reads the configuration, counts the settings it understands, and stores nothing.", kind="verify"),
    )

    def fetch(self, base: str, secrets: dict) -> bytes:
        from keystone.configcheck.parsers import ParseError, _xml

        api = Api(SELF_HOSTED, headers={"X-PAN-KEY": secrets.get("token", "")})  # the key goes in a header, never in the URL
        raw = api.request("GET", f"{base}/api/?type=config&action=show", headers={"Accept": "application/xml"}).content
        try:
            root = _xml(raw)
        except ParseError:
            raise ConnectorError("PAN-OS didn't return XML.") from None
        if root.get("status") != "success":
            raise ConnectorError("PAN-OS refused the request: check the key and that the role allows the XML API's Configuration.")
        cfg = root.find("result/config")
        if cfg is None:
            raise ConnectorError("PAN-OS returned no configuration.")
        return tostring(cfg)
