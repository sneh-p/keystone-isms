"""Cloud security posture sources: AWS Security Hub, Microsoft Defender for Cloud, Google Security Command Center.

Each reads the platform's own posture assessments, read-only, and reports one configuration setting per control or
category ("N of M resources failing"), which baselines over settings turn into findings. Field names come from the
vendors' API documentation (mapping_note); they haven't been validated against a live account yet.
"""

from __future__ import annotations

import json
import re
import time
from collections import defaultdict
from urllib.parse import quote, urlencode

from keystone.asm.vocabulary import Inventory, SettingObs

from ..http import Api, ConnectorError, HostPolicy, fields_of
from .base import ConfigField, InventoryProvider, SetupStep

GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-\d{1,2}")
MAX_ITEMS = 50_000
DOC_NOTE = "Field names from the vendor's API documentation; not yet validated against a live account."


def _setting(key: str, title: str, total: int, failing: int, category: str | None) -> SettingObs:
    return SettingObs(key=key[:200], title=title[:500], compliant=failing == 0, category=(category or "")[:100] or None,
                      detail=f"{failing} of {total} resource(s) failing" if total else None)


# ---- AWS Security Hub ---------------------------------------------------------------------------------------------

class AwsSecurityHubProvider(InventoryProvider):
    key = "aws_security_hub"
    name = "AWS Security Hub"
    description = "Read-only: Security Hub control results (passed and failed resources per control) for one region."
    category = "posture"
    categories = ("posture",)
    mapping_note = DOC_NOTE
    fields = (
        ConfigField("region", "Region", help="The Security Hub home or aggregation region, e.g. eu-west-1", example="eu-west-1"),
        ConfigField("access_key_id", "Access key ID", secret=True, help="An IAM user with only the AWS managed AWSSecurityHubReadOnlyAccess (or SecurityAudit) policy."),
        ConfigField("secret_access_key", "Secret access key", secret=True),
    )
    setup = (
        SetupStep("Create a read-only IAM user", "IAM > Users > Create user “keystone-securityhub-readonly”, no console access. Attach only the AWS managed policy AWSSecurityHubReadOnlyAccess.",
                  code="aws iam create-user --user-name keystone-securityhub-readonly\n"
                       "aws iam attach-user-policy --user-name keystone-securityhub-readonly --policy-arn arn:aws:iam::aws:policy/AWSSecurityHubReadOnlyAccess\n"
                       "aws iam create-access-key --user-name keystone-securityhub-readonly"),
        SetupStep("Turn on consolidated control findings", "Security Hub > Settings > General: consolidated control findings on, so each control reports once across standards."),
        SetupStep("Check", "Choose Test connection. Keystone reads one page of findings and saves nothing.", kind="verify",
                  code="aws securityhub get-findings --region {region} --max-items 1 --filters '{\"RecordState\":[{\"Value\":\"ACTIVE\",\"Comparison\":\"EQUALS\"}]}'"),
    )
    FILTERS = {
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "ComplianceStatus": [{"Value": "PASSED", "Comparison": "EQUALS"}, {"Value": "FAILED", "Comparison": "EQUALS"}],
        "WorkflowStatus": [{"Value": "SUPPRESSED", "Comparison": "NOT_EQUALS"}],
    }

    def __init__(self, client_factory=None):
        self.client_factory = client_factory

    def _client(self, config: dict, secrets: dict):
        region = (config.get("region") or "").strip()
        if not REGION.fullmatch(region):  # boto3 builds the endpoint host from the region (SC-SSRF-001)
            raise ConnectorError("Enter an AWS region such as eu-west-1.")
        if self.client_factory:
            return self.client_factory(region)
        import boto3
        from botocore.config import Config

        s = boto3.session.Session(aws_access_key_id=secrets.get("access_key_id"), aws_secret_access_key=secrets.get("secret_access_key"), region_name=region)
        return s.client("securityhub", config=Config(connect_timeout=10, read_timeout=30, retries={"max_attempts": 3, "mode": "standard"}))

    def collect(self, config: dict, secrets: dict, preview: bool = False) -> Inventory:
        from botocore.exceptions import BotoCoreError, ClientError

        sh = self._client(config, secrets)
        inv = Inventory()
        per: dict[str, dict] = {}
        token, seen = None, 0
        try:
            while True:
                kw: dict = {"Filters": self.FILTERS, "MaxResults": 100}
                if token:
                    kw["NextToken"] = token
                page = sh.get_findings(**kw)
                rows = page.get("Findings") or []
                if seen == 0:
                    inv.sample_fields["securityhub findings"] = fields_of(rows[0] if rows else None)
                for f in rows:
                    comp = f.get("Compliance") or {}
                    cid = comp.get("SecurityControlId") or f.get("GeneratorId") or f.get("Id")
                    if not cid:
                        continue
                    c = per.setdefault(cid, {"title": f.get("Title") or cid, "total": set(), "failing": set(), "category": None})
                    res = ",".join(r.get("Id", "") for r in (f.get("Resources") or [])[:3]) or f.get("Id")
                    c["total"].add(res)
                    if comp.get("Status") == "FAILED":
                        c["failing"].add(res)
                    stds = comp.get("AssociatedStandards") or []
                    if stds and not c["category"]:
                        parts = str(stds[0].get("StandardsId", "")).split("/")  # standards/<name>/v/<version>
                        c["category"] = parts[1] if len(parts) > 1 else None
                seen += len(rows)
                token = page.get("NextToken")
                if preview or not token or seen >= MAX_ITEMS:
                    break
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("InvalidAccessException",):
                raise ConnectorError("Security Hub isn't enabled in this region for this account.") from None
            raise ConnectorError(f"AWS refused the request ({code or 'error'}): check the region and the read-only policy.") from None
        except BotoCoreError as e:
            raise ConnectorError(f"Couldn't reach AWS ({type(e).__name__}).") from None
        for cid, c in per.items():
            inv.settings.append(_setting(f"aws:{cid}", f"{cid} {c['title']}", len(c["total"]), len(c["failing"]), c["category"] or "AWS"))
        if not preview and seen < MAX_ITEMS:
            inv.complete.add("settings")
        if seen >= MAX_ITEMS:
            inv.notes.append(f"Stopped after {MAX_ITEMS} findings; results are partial.")
        return inv


# ---- Microsoft Defender for Cloud ----------------------------------------------------------------------------------

AZ_LOGIN, ARM = "https://login.microsoftonline.com", "https://management.azure.com"
AZ_POLICY = HostPolicy(hosts=frozenset({"login.microsoftonline.com", "management.azure.com"}))


class DefenderForCloudProvider(InventoryProvider):
    key = "defender_for_cloud"
    name = "Microsoft Defender for Cloud"
    description = "Read-only: Defender for Cloud security recommendations (healthy and unhealthy resources) for your Azure subscriptions."
    category = "posture"
    categories = ("posture",)
    mapping_note = DOC_NOTE
    fields = (
        ConfigField("tenant_id", "Directory (tenant) ID", example="00000000-0000-0000-0000-000000000000"),
        ConfigField("client_id", "Application (client) ID"),
        ConfigField("client_secret", "Client secret", secret=True),
        ConfigField("subscription_ids", "Subscription IDs", help="Comma-separated, up to 20.", example="00000000-0000-0000-0000-000000000000"),
    )
    setup = (
        SetupStep("Register an app", "Entra ID > App registrations > New registration “Keystone Defender for Cloud (read-only)”. No API permissions are needed.",
                  link="https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade", link_label="Open App registrations"),
        SetupStep("Give it Security Reader", "On each subscription: Access control (IAM) > Add role assignment > Security Reader > the app. Nothing else.",
                  code="az role assignment create --assignee <client-id> --role \"Security Reader\" --scope /subscriptions/{subscription_ids}"),
        SetupStep("Create a client secret", "Certificates & secrets > New client secret; copy the value into Keystone. Set a reminder before it expires."),
        SetupStep("Check", "Choose Test connection. Keystone reads one page of recommendations per subscription and saves nothing.", kind="verify"),
    )

    def collect(self, config: dict, secrets: dict, preview: bool = False) -> Inventory:
        tid = (config.get("tenant_id") or "").strip()
        subs = [s.strip() for s in (config.get("subscription_ids") or "").split(",") if s.strip()]
        if not GUID.match(tid) or not subs or len(subs) > 20 or not all(GUID.match(s) for s in subs):
            raise ConnectorError("Enter the tenant ID and up to 20 subscription IDs (GUIDs).")
        api = Api(AZ_POLICY)
        tok = api.json("POST", f"{AZ_LOGIN}/{tid}/oauth2/v2.0/token", data={"grant_type": "client_credentials", "client_id": (config.get("client_id") or "").strip(),
                                                                           "client_secret": secrets.get("client_secret", ""), "scope": f"{ARM}/.default"}).get("access_token")
        if not tok:
            raise ConnectorError("Microsoft didn't return an access token.")
        auth = {"Authorization": f"Bearer {tok}"}
        inv = Inventory()
        per: dict[str, dict] = {}
        seen = 0
        for sub in subs:
            url: str | None = f"{ARM}/subscriptions/{sub}/providers/Microsoft.Security/assessments?api-version=2021-06-01"
            while url:
                body = api.json("GET", url, headers=auth)
                rows = body.get("value") or []
                inv.sample_fields.setdefault("defender assessments", fields_of(rows[0] if rows else None))
                for a in rows:
                    props = a.get("properties") or {}
                    code = (props.get("status") or {}).get("code")
                    if code not in ("Healthy", "Unhealthy"):
                        continue  # NotApplicable
                    name = a.get("name") or props.get("displayName")
                    if not name:
                        continue
                    c = per.setdefault(name, {"title": props.get("displayName") or name, "total": 0, "failing": 0,
                                              "category": ", ".join((props.get("metadata") or {}).get("categories") or []) or "Azure"})
                    c["total"] += 1
                    c["failing"] += code == "Unhealthy"
                seen += len(rows)
                url = None if preview or seen >= MAX_ITEMS else body.get("nextLink")
        for name, c in per.items():
            inv.settings.append(_setting(f"mdc:{name}", c["title"], c["total"], c["failing"], c["category"]))
        if not preview and seen < MAX_ITEMS:
            inv.complete.add("settings")
        return inv


# ---- Google Security Command Center ------------------------------------------------------------------------------

G_TOKEN, SCC = "https://oauth2.googleapis.com/token", "https://securitycenter.googleapis.com"
G_POLICY = HostPolicy(hosts=frozenset({"oauth2.googleapis.com", "securitycenter.googleapis.com"}))


class GoogleSccProvider(InventoryProvider):
    key = "google_scc"
    name = "Google Security Command Center"
    description = "Read-only: active misconfiguration findings from Security Command Center for your organisation, grouped by category."
    category = "posture"
    categories = ("posture",)
    mapping_note = DOC_NOTE
    fields = (
        ConfigField("organization_id", "Organization ID", help="Numbers only, from IAM & Admin > Settings.", example="123456789012"),
        ConfigField("service_account_json", "Service account key (JSON)", secret=True, help="The JSON key of a service account with only Security Center Findings Viewer."),
    )
    setup = (
        SetupStep("Create a service account", "IAM & Admin > Service accounts > Create “keystone-scc-readonly” in any project."),
        SetupStep("Grant Findings Viewer on the organisation", "IAM at organisation level > Grant access > the service account > Security Center Findings Viewer. Nothing else.",
                  code="gcloud organizations add-iam-policy-binding {organization_id} --member=serviceAccount:keystone-scc-readonly@<project>.iam.gserviceaccount.com --role=roles/securitycenter.findingsViewer"),
        SetupStep("Create a key", "Keys > Add key > JSON. Paste the whole file into Keystone; it's encrypted and can't be read back. Delete the downloaded copy."),
        SetupStep("Check", "Choose Test connection. Keystone reads one page of findings and saves nothing.", kind="verify"),
    )

    @staticmethod
    def _assertion(sa: dict, now: int) -> str:
        from joserfc import jwt
        from joserfc.jwk import RSAKey

        try:
            key = RSAKey.import_key(sa["private_key"])
        except (KeyError, ValueError, TypeError) as e:
            raise ConnectorError("The service account key couldn't be read; paste the whole JSON key file.") from e
        claims = {"iss": sa["client_email"], "scope": "https://www.googleapis.com/auth/cloud-platform", "aud": G_TOKEN, "iat": now, "exp": now + 600}
        return jwt.encode({"alg": "RS256", "typ": "JWT"}, claims, key)

    def collect(self, config: dict, secrets: dict, preview: bool = False) -> Inventory:
        org = (config.get("organization_id") or "").strip()
        if not re.fullmatch(r"\d{6,20}", org):
            raise ConnectorError("The organization ID is a number, for example 123456789012.")
        try:
            sa = json.loads(secrets.get("service_account_json") or "")
        except ValueError:
            raise ConnectorError("The service account key must be the JSON key file.") from None
        if not isinstance(sa, dict) or sa.get("type") != "service_account" or not sa.get("client_email") or not sa.get("private_key"):
            raise ConnectorError("The service account key must be a JSON key for a service account.")
        api = Api(G_POLICY)
        # The token endpoint is fixed: a token_uri inside the uploaded file is ignored (SC-SSRF-003).
        tok = api.json("POST", G_TOKEN, data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": self._assertion(sa, int(time.time()))}).get("access_token")
        if not tok:
            raise ConnectorError("Google didn't return an access token.")
        auth = {"Authorization": f"Bearer {tok}"}
        inv = Inventory()
        per: dict[str, dict] = defaultdict(lambda: {"resources": set(), "severity": None})
        params = {"filter": 'state="ACTIVE" AND findingClass="MISCONFIGURATION"', "pageSize": 1000}
        base = f"{SCC}/v1/organizations/{org}/sources/-/findings"
        url: str | None = f"{base}?{urlencode(params)}"
        seen = 0
        while url:
            body = api.json("GET", url, headers=auth)
            rows = body.get("listFindingsResults") or []
            inv.sample_fields.setdefault("scc findings", fields_of((rows[0] or {}).get("finding") if rows else None))
            for r in rows:
                f = r.get("finding") or {}
                cat = f.get("category")
                if not cat:
                    continue
                per[cat]["resources"].add(f.get("resourceName") or f.get("name"))
                per[cat]["severity"] = per[cat]["severity"] or f.get("severity")
            seen += len(rows)
            nxt = body.get("nextPageToken")
            url = None if preview or not nxt or seen >= MAX_ITEMS else f"{base}?{urlencode(params)}&pageToken={quote(nxt, safe='')}"
        for cat, c in per.items():
            n = len(c["resources"])
            title = cat.replace("_", " ").capitalize()
            inv.settings.append(SettingObs(key=f"scc:{cat}"[:200], title=title[:500], compliant=False, category=f"Google Cloud ({(c['severity'] or 'unknown').lower()})",
                                           detail=f"{n} resource(s) affected"))
        # SCC lists only what is failing, so a category that disappears has been fixed.
        if not preview and seen < MAX_ITEMS:
            inv.complete.add("settings")
        return inv
