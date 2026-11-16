"""Vulnerability management connectors (read-only): Tenable, Qualys, Rapid7 InsightVM. Critical, high and medium
findings only (low and informational are left out to keep volumes sensible)."""

from __future__ import annotations

import re
import time
from urllib.parse import quote, urlencode

from keystone.asm.vocabulary import DeviceObs, Inventory, VulnObs, device_type_from, parse_time, pick, severity_from

from ..http import Api, ConnectorError, HostPolicy, fields_of
from .base import ConfigField, InventoryProvider, SetupStep

# ---- Tenable Vulnerability Management ---------------------------------------------------------------------------------

TENABLE = "https://cloud.tenable.com"


class TenableProvider(InventoryProvider):
    key = "tenable"
    name = "Tenable Vulnerability Management"
    description = "Read-only: open critical, high and medium vulnerabilities and the assets they're on (vulnerability export API)."
    category = "vuln"
    mapping_note = "Field names from Tenable's vulns export API (POST /vulns/export, status, chunks): asset.*, plugin.*, severity, first_found, state."
    fields = (
        ConfigField("access_key", "Access key"),
        ConfigField("secret_key", "Secret key", secret=True),
    )
    setup = (
        SetupStep("Create API keys for a read-only user", "Tenable > Settings > Access Control > Users: a user with the Basic or Scan Operator role and Can View access to your assets. My Account > API Keys > Generate."),
        SetupStep("Check", "Choose Test connection; Keystone checks the keys and reads a sample of assets.", kind="verify"),
    )
    max_wait = 600  # seconds to wait for an export

    def collect(self, config: dict, secrets: dict, preview: bool = False) -> Inventory:
        api = Api(HostPolicy(hosts=frozenset({"cloud.tenable.com"})), headers={"X-ApiKeys": f"accessKey={config.get('access_key', '')};secretKey={secrets.get('secret_key', '')}"})
        inv = Inventory()
        if preview:  # quick: a sample of assets, no export
            assets = api.json("GET", f"{TENABLE}/assets").get("assets", [])[:50]
            inv.sample_fields["tenable assets"] = fields_of(assets[0] if assets else None)
            for a in assets:
                inv.devices.append(self._device(a.get("id"), a))
            inv.notes.append("Preview reads assets only; vulnerabilities are exported on the scheduled run")
            return inv
        job = api.json("POST", f"{TENABLE}/vulns/export", json={"num_assets": 500, "filters": {"severity": ["critical", "high", "medium"], "state": ["OPEN", "REOPENED"]}})
        uuid = job.get("export_uuid")
        if not uuid or not re.fullmatch(r"[0-9a-f-]{36}", uuid):
            raise ConnectorError("Tenable didn't start an export.")
        started, done, seen_chunks = time.monotonic(), False, set()
        devices: dict[str, DeviceObs] = {}
        while time.monotonic() - started < self.max_wait:
            st = api.json("GET", f"{TENABLE}/vulns/export/{uuid}/status")
            for chunk in st.get("chunks_available", []):
                if chunk in seen_chunks:
                    continue
                seen_chunks.add(chunk)
                for v in api.json("GET", f"{TENABLE}/vulns/export/{uuid}/chunks/{int(chunk)}"):
                    a = v.get("asset") or {}
                    aid = a.get("uuid") or a.get("id")
                    if not aid:
                        continue
                    if aid not in devices:
                        devices[aid] = self._device(aid, a)
                        inv.sample_fields.setdefault("tenable vulnerability", fields_of(v))
                    p = v.get("plugin") or {}
                    cves = p.get("cve") or []
                    fs = parse_time(v.get("first_found"))
                    inv.vulns.append(VulnObs(device_external_id=aid, key=str(p.get("id") or v.get("plugin_id") or "unknown"), title=p.get("name") or "Vulnerability",
                                             severity=severity_from(v.get("severity")), cve=", ".join(cves[:5]) if cves else None, cvss=p.get("cvss3_base_score") or p.get("cvss_base_score"),
                                             exploitable=bool(p.get("exploit_available")), first_seen=fs.date() if fs else None))
            if st.get("status") == "FINISHED":
                done = True
                break
            if st.get("status") in ("ERROR", "CANCELLED"):
                raise ConnectorError(f"Tenable export {st.get('status').lower()}.")
            time.sleep(5)
        inv.devices = list(devices.values())
        if done:
            inv.complete.update({"vulns"})  # devices aren't complete: assets without open findings aren't exported
        else:
            inv.notes.append("Tenable export didn't finish in time; vulnerabilities kept from earlier runs")
        return inv

    @staticmethod
    def _device(aid, a: dict) -> DeviceObs:
        def first(x):
            return x[0] if isinstance(x, list) and x else x

        name = first(a.get("hostname")) or first(a.get("fqdn")) or first(a.get("netbios_name")) or first(a.get("ipv4")) or str(aid)
        os_ = first(a.get("operating_system"))
        return DeviceObs(external_id=str(aid), name=str(name), category="vuln", hostname=str(first(a.get("hostname")) or first(a.get("fqdn")) or "") or None,
                         os=os_, device_type=device_type_from(first(a.get("device_type")) or os_), last_seen=parse_time(a.get("last_seen") or a.get("last_scan_time")))


# ---- Qualys VMDR ----------------------------------------------------------------------------------------------------------

QUALYS_SUFFIXES = (".qualys.com", ".qualys.eu", ".qualys.in", ".qualys.ca", ".qualys.ae", ".qualys.co.uk", ".qualys.com.au", ".qualysksa.com")
QUALYS_POLICY = HostPolicy(suffixes=QUALYS_SUFFIXES)
QUALYS_SEVERITY = {"5": "critical", "4": "high", "3": "medium"}


class QualysProvider(InventoryProvider):
    key = "qualys"
    name = "Qualys VMDR"
    description = "Read-only: hosts with open severity 3-5 detections (Qualys 5 is critical, 4 high, 3 medium)."
    category = "vuln"
    mapping_note = "Host list detection API (/api/2.0/fo/asset/host/vm/detection/): HOST ID, DNS, NETBIOS, OS; DETECTION QID, SEVERITY, STATUS, FIRST_FOUND_DATETIME."
    fields = (
        ConfigField("api_server", "API server", help="Your platform's API address, e.g. https://qualysapi.qg2.apps.qualys.com", example="https://qualysapi.qualys.com"),
        ConfigField("username", "User name", help="A Reader user with API access."),
        ConfigField("password", "Password", secret=True),
    )
    setup = (
        SetupStep("Create a read-only API user", "Qualys > Users > New user with the Reader role and API access enabled. Find your API server under Help > About."),
        SetupStep("Check", "Choose Test connection; Keystone reads a sample of hosts and detections.", kind="verify"),
    )

    def collect(self, config: dict, secrets: dict, preview: bool = False) -> Inventory:
        from base64 import b64encode

        from defusedxml import DefusedXmlException, ElementTree  # SC-FILE-004: untrusted XML

        from ..http import validate_base_url

        base = validate_base_url(config.get("api_server", ""), QUALYS_POLICY)
        if not base.split("//", 1)[1].startswith("qualysapi."):
            raise ConnectorError("Use your platform's API server (it starts with qualysapi.).")
        auth = b64encode(f"{config.get('username', '')}:{secrets.get('password', '')}".encode()).decode()
        api = Api(QUALYS_POLICY, headers={"Authorization": f"Basic {auth}", "X-Requested-With": "Keystone-ISMS"})
        params = {"action": "list", "severities": "3-5", "status": "New,Active,Re-Opened", "show_results": "0", "output_format": "XML", "truncation_limit": "100" if preview else "1000"}
        url: str | None = f"{base}/api/2.0/fo/asset/host/vm/detection/?{urlencode(params)}"
        inv = Inventory()
        while url:
            r = api.request("GET", url, headers={"Accept": "application/xml"})
            try:
                root = ElementTree.fromstring(r.content)
            except ElementTree.ParseError:
                raise ConnectorError("Qualys returned XML Keystone couldn't read.") from None
            except DefusedXmlException:
                raise ConnectorError("Qualys returned XML with entity declarations; Keystone refused to read it.") from None
            hosts = root.findall(".//HOST_LIST/HOST")
            if hosts and "qualys host" not in inv.sample_fields:
                inv.sample_fields["qualys host"] = sorted({c.tag for c in hosts[0]})
            for h in hosts:
                hid = h.findtext("ID")
                if not hid:
                    continue
                name = h.findtext("DNS") or h.findtext("NETBIOS") or h.findtext("IP") or hid
                os_ = h.findtext("OS")
                inv.devices.append(DeviceObs(external_id=hid, name=name, category="vuln", hostname=h.findtext("DNS") or h.findtext("NETBIOS"), os=os_,
                                             device_type=device_type_from(os_), last_seen=parse_time(h.findtext("LAST_VM_SCANNED_DATE") or h.findtext("LAST_SCAN_DATETIME"))))
                for d in h.findall(".//DETECTION_LIST/DETECTION"):
                    sev = QUALYS_SEVERITY.get((d.findtext("SEVERITY") or "").strip())
                    if not sev:
                        continue
                    fs = parse_time(d.findtext("FIRST_FOUND_DATETIME"))
                    qid = d.findtext("QID") or "?"
                    inv.vulns.append(VulnObs(device_external_id=hid, key=f"qid:{qid}", title=f"Qualys QID {qid}", severity=sev, first_seen=fs.date() if fs else None))
            nxt = root.findtext(".//WARNING/URL")
            url = None if preview or not nxt else nxt
        if not preview:
            inv.complete.add("vulns")
        return inv


# ---- Rapid7 InsightVM (cloud integrations API v4) ---------------------------------------------------------------------------

R7_REGIONS = ("us", "us2", "us3", "eu", "ca", "au", "ap")


class Rapid7Provider(InventoryProvider):
    key = "rapid7"
    name = "Rapid7 InsightVM"
    description = "Read-only: assets with their open critical and severe vulnerabilities (InsightVM cloud integrations API v4)."
    category = "vuln"
    mapping_note = ("POST /vm/v4/integration/assets with a vulnerability filter and includeSame=true. Rapid7's published schema could not be retrieved "
                    "when this connector was written, so field names follow third-party integrations; Test connection lists the fields your account returns.")
    fields = (
        ConfigField("region", "Region", help="us, us2, us3, eu, ca, au or ap (from your Insight platform address).", example="us"),
        ConfigField("api_key", "API key", secret=True, help="An Organization or User key for a user with the Read Only role in InsightVM."),
    )
    setup = (
        SetupStep("Create an API key", "Insight platform > Administration > API key management > Generate a User key for a read-only user (or an Organization key).", link="https://insight.rapid7.com/platform#/apiKeyManagement", link_label="API key management"),
        SetupStep("Check", "Choose Test connection; Keystone reads a sample of assets and lists the fields returned.", kind="verify"),
    )

    def collect(self, config: dict, secrets: dict, preview: bool = False) -> Inventory:
        region = (config.get("region") or "us").strip().lower()
        if region not in R7_REGIONS:
            raise ConnectorError(f"Region must be one of {', '.join(R7_REGIONS)}.")
        host = f"{region}.api.insight.rapid7.com"
        api = Api(HostPolicy(hosts=frozenset({host})), headers={"X-Api-Key": secrets.get("api_key", "")})
        body = {"asset": "", "vulnerability": "severity IN ['Critical', 'Severe']"}
        inv, cursor = Inventory(), None
        while True:
            url = f"https://{host}/vm/v4/integration/assets?size={50 if preview else 500}&includeSame=true" + (f"&cursor={quote(cursor, safe='')}" if cursor else "")
            page = api.json("POST", url, json=body)
            rows = page.get("data") or []
            if rows and "rapid7 asset" not in inv.sample_fields:
                inv.sample_fields["rapid7 asset"] = fields_of(rows[0])
            for a in rows:
                aid = str(a.get("id"))
                name = pick(a, "host_name", "hostName", "ip", default=aid)
                os_ = pick(a, "os_description", "os_family", "os")
                inv.devices.append(DeviceObs(external_id=aid, name=str(name), category="vuln", hostname=pick(a, "host_name", "hostName"), os=os_,
                                             device_type=device_type_from(pick(a, "os_type", default=os_)), last_seen=parse_time(pick(a, "last_scan_end", "last_assessed_for_vulnerabilities"))))
                for v in (a.get("same") or []) + (a.get("new") or []):
                    fs = parse_time(pick(v, "first_found", "firstFound"))
                    sev = severity_from(pick(v, "severity", "severity_score", default=""))
                    vid = str(pick(v, "vulnerability_id", "id", "check_id", default="unknown"))
                    inv.vulns.append(VulnObs(device_external_id=aid, key=vid, title=str(pick(v, "title", "vulnerability_id", default=vid)), severity=sev,
                                             cve=None, cvss=pick(v, "cvss_v3_score", "cvss_score"), exploitable=bool(pick(v, "has_exploits", "exploits", default=False)),
                                             first_seen=fs.date() if fs else None))
            cursor = pick(page, "metadata.cursor")
            if preview or not cursor or not rows:
                break
        if not preview:
            inv.complete.add("vulns")
        return inv
