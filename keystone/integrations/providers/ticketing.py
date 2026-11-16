"""Ticketing systems: Jira Cloud, ServiceNow, ConnectWise PSA and Autotask.

Unlike every other connector these write: they create one ticket per Keystone record when someone asks (or, if the
administrator turns it on, for new known-exploited or high-priority vulnerabilities), and read that ticket's status
back. They never edit or close tickets, and never read anything else. Credentials should belong to an API user that
can only create and read tickets in one project, table, board or queue.

API field names come from each vendor's REST documentation (mapping_note); they haven't been validated against a live
instance yet.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from ..http import Api, ConnectorError, HostPolicy, validate_base_url
from .base import CheckDef, ConfigField, Outcome, Provider, SetupStep

DOC_NOTE = "Field names from the vendor's REST API documentation; not yet validated against a live instance."
AUTO_CREATE = ConfigField("auto_create", "Open tickets automatically", required=False,
                          help="Keystone can open a ticket for each new vulnerability that matches, at most 25 per run.",
                          options=(("", "No, only when someone asks"), ("known_exploited", "Known-exploited vulnerabilities (P1)"),
                                   ("p1_p2", "P1 and P2 vulnerabilities")))


@dataclass(frozen=True)
class Ticket:
    title: str
    description: str


@dataclass(frozen=True)
class Created:
    external_id: str
    key: str
    url: str | None


class TicketProvider(Provider):
    """A ticketing system. `run` (Test connection and the scheduled run's first step) only reads."""

    policy: HostPolicy = HostPolicy()
    host_field: str | None = None
    mapping_note = DOC_NOTE
    checks = (CheckDef("connection", "Connection", ()), CheckDef("sync", "Ticket status", ()))

    def describe(self) -> dict:
        return {**super().describe(), "ticketing": True, "mapping_note": self.mapping_note}

    def base(self, config: dict) -> str:
        return validate_base_url(config.get(self.host_field or "") or "", self.policy)

    def api(self, config: dict, secrets: dict) -> Api:
        return Api(self.policy, headers=self.headers(config, secrets), max_pages=50)

    def headers(self, config: dict, secrets: dict) -> dict:  # pragma: no cover - interface
        raise NotImplementedError

    def whoami(self, api: Api, base: str, config: dict) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def create(self, api: Api, base: str, config: dict, t: Ticket) -> Created:  # pragma: no cover - interface
        raise NotImplementedError

    def is_closed(self, api: Api, base: str, config: dict, external_id: str) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def run(self, config: dict, secrets: dict, session=None) -> list[Outcome]:
        base = self.base(config)
        who = self.whoami(self.api(config, secrets), base, config)
        return [Outcome("connection", "pass", f"Connected as {who}"[:300])]


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def _int(config: dict, name: str, label: str) -> int:
    v = str(config.get(name) or "").strip()
    if not v.isdigit():
        raise ConnectorError(f"{label} must be a number.")
    return int(v)


# ---- Jira Cloud -----------------------------------------------------------------------------------------------------

class JiraProvider(TicketProvider):
    key = "jira"
    name = "Jira Cloud"
    description = "Creates a Jira issue for a Keystone record when you ask, and shows when it's done."
    policy = HostPolicy(suffixes=(".atlassian.net",))
    host_field = "site_url"
    fields = (
        ConfigField("site_url", "Site", help="Your Jira Cloud address.", example="https://yourcompany.atlassian.net"),
        ConfigField("email", "Account email", help="Of a dedicated Jira user that can only create and browse issues in this project."),
        ConfigField("api_token", "API token", secret=True, help="id.atlassian.com > Security > API tokens, created while signed in as that user."),
        ConfigField("project_key", "Project key", example="SEC"),
        ConfigField("issue_type", "Issue type", required=False, help="Defaults to Task.", example="Task"),
        AUTO_CREATE,
    )
    setup = (
        SetupStep("Create a dedicated user", "Add a user for Keystone and give it only Browse projects and Create issues in the security project (a project role or permission scheme)."),
        SetupStep("Create an API token", "Signed in as that user, create an API token and paste it into Keystone. It's encrypted and can't be read back.",
                  link="https://id.atlassian.com/manage-profile/security/api-tokens", link_label="Open API tokens"),
        SetupStep("Check", "Choose Test connection. Keystone reads the user's profile; it creates nothing.", kind="verify",
                  code="curl -s -u '<email>:<token>' https://{host}/rest/api/3/myself | grep -o '\"displayName\":\"[^\"]*\"'"),
    )

    def headers(self, config, secrets):
        return {"Authorization": _basic((config.get("email") or "").strip(), secrets.get("api_token", "")), "Content-Type": "application/json"}

    def whoami(self, api, base, config):
        return str(api.json("GET", f"{base}/rest/api/3/myself").get("displayName") or "Jira user")

    def create(self, api, base, config, t):
        project = (config.get("project_key") or "").strip().upper()
        if not project.replace("_", "").isalnum():
            raise ConnectorError("The project key should look like SEC.")
        doc = {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": line}]} for line in t.description.split("\n") if line.strip()]}
        body = {"fields": {"project": {"key": project}, "summary": t.title[:250], "issuetype": {"name": (config.get("issue_type") or "Task").strip()[:60]}, "description": doc}}
        r = api.json("POST", f"{base}/rest/api/3/issue", json=body)
        if not r.get("id") or not r.get("key"):
            raise ConnectorError("Jira didn't return the new issue.")
        return Created(str(r["id"]), str(r["key"]), f"{base}/browse/{r['key']}")

    def is_closed(self, api, base, config, external_id):
        r = api.json("GET", f"{base}/rest/api/3/issue/{int(external_id)}?fields=status")
        return (((r.get("fields") or {}).get("status") or {}).get("statusCategory") or {}).get("key") == "done"


# ---- ServiceNow ---------------------------------------------------------------------------------------------------

class ServiceNowProvider(TicketProvider):
    key = "servicenow"
    name = "ServiceNow"
    description = "Creates a ServiceNow incident (or problem) for a Keystone record when you ask, and shows when it's resolved."
    policy = HostPolicy(suffixes=(".service-now.com",))
    host_field = "instance_url"
    TABLES = (("incident", "Incident"), ("problem", "Problem"))
    fields = (
        ConfigField("instance_url", "Instance", example="https://yourcompany.service-now.com"),
        ConfigField("username", "User name", help="A dedicated integration user (web service access only)."),
        ConfigField("password", "Password", secret=True),
        ConfigField("table", "Record type", options=TABLES),
        ConfigField("assignment_group", "Assignment group sys_id", required=False, help="Optional: the group new records are assigned to."),
        AUTO_CREATE,
    )
    setup = (
        SetupStep("Create an integration user", "User Administration > Users > New: tick Web service access only, and give it only the roles needed to create and read records in the chosen table (for incidents, itil)."),
        SetupStep("Check", "Choose Test connection. Keystone reads one record from the table; it creates nothing.", kind="verify",
                  code="curl -s -u '<user>:<password>' 'https://{host}/api/now/table/incident?sysparm_limit=1&sysparm_fields=number'"),
    )

    def _table(self, config) -> str:
        t = config.get("table") or "incident"
        if t not in {v for v, _ in self.TABLES}:
            raise ConnectorError("Choose incident or problem.")
        return t

    def headers(self, config, secrets):
        return {"Authorization": _basic((config.get("username") or "").strip(), secrets.get("password", "")), "Content-Type": "application/json"}

    def whoami(self, api, base, config):
        api.json("GET", f"{base}/api/now/table/{self._table(config)}?sysparm_limit=1&sysparm_fields=number")
        return (config.get("username") or "integration user").strip()

    def create(self, api, base, config, t):
        table = self._table(config)
        body = {"short_description": t.title[:160], "description": t.description[:4000]}
        group = (config.get("assignment_group") or "").strip()
        if group:
            if not group.isalnum() or len(group) != 32:
                raise ConnectorError("The assignment group is a 32-character sys_id.")
            body["assignment_group"] = group
        r = (api.json("POST", f"{base}/api/now/table/{table}", json=body).get("result") or {})
        if not r.get("sys_id"):
            raise ConnectorError("ServiceNow didn't return the new record.")
        return Created(str(r["sys_id"]), str(r.get("number") or r["sys_id"]), f"{base}/nav_to.do?uri={table}.do%3Fsys_id%3D{r['sys_id']}")

    def is_closed(self, api, base, config, external_id):
        if not external_id.isalnum():
            raise ConnectorError("Unexpected record id.")
        r = api.json("GET", f"{base}/api/now/table/{self._table(config)}/{external_id}?sysparm_fields=active,state").get("result") or {}
        return str(r.get("active")).lower() == "false"


# ---- ConnectWise PSA (Manage) ---------------------------------------------------------------------------------------

class ConnectWisePsaProvider(TicketProvider):
    key = "connectwise_psa"
    name = "ConnectWise PSA"
    description = "Creates a service ticket on a ConnectWise PSA (Manage) board for a Keystone record, and shows when it's closed."
    policy = HostPolicy(hosts=frozenset({"api-na.myconnectwise.net", "api-eu.myconnectwise.net", "api-au.myconnectwise.net"}), self_hosted=True)
    host_field = "site"
    PATH = "/v4_6_release/apis/3.0"
    fields = (
        ConfigField("site", "API site", help="api-na, api-eu or api-au .myconnectwise.net, or your own server.", example="https://api-eu.myconnectwise.net"),
        ConfigField("company_id", "Company ID", help="The company you sign in with."),
        ConfigField("public_key", "Public key", help="Of an API member with a security role that can only add and view service tickets."),
        ConfigField("private_key", "Private key", secret=True),
        ConfigField("client_id", "Client ID", secret=True, help="Your clientId from the ConnectWise developer portal."),
        ConfigField("board_id", "Service board ID", example="12"),
        ConfigField("company_rec_id", "Company record ID", help="The company (your organisation) tickets are filed under.", example="250"),
        AUTO_CREATE,
    )
    setup = (
        SetupStep("Create an API member", "System > Members > API Members: a member with a security role allowing only Service Desk > Service Tickets: Add and Inquire. Generate its keys."),
        SetupStep("Check", "Choose Test connection. Keystone reads the system info; it creates nothing.", kind="verify"),
    )

    def headers(self, config, secrets):
        user = f"{(config.get('company_id') or '').strip()}+{(config.get('public_key') or '').strip()}"
        return {"Authorization": _basic(user, secrets.get("private_key", "")), "clientId": secrets.get("client_id", ""), "Content-Type": "application/json"}

    def whoami(self, api, base, config):
        info = api.json("GET", f"{base}{self.PATH}/system/info")
        return f"ConnectWise {info.get('version') or ''}".strip()

    def create(self, api, base, config, t):
        body = {"summary": t.title[:100], "board": {"id": _int(config, "board_id", "Service board ID")},
                "company": {"id": _int(config, "company_rec_id", "Company record ID")}, "initialDescription": t.description[:8000]}
        r = api.json("POST", f"{base}{self.PATH}/service/tickets", json=body)
        if not r.get("id"):
            raise ConnectorError("ConnectWise didn't return the new ticket.")
        return Created(str(r["id"]), f"#{r['id']}", None)

    def is_closed(self, api, base, config, external_id):
        return bool(api.json("GET", f"{base}{self.PATH}/service/tickets/{int(external_id)}?fields=closedFlag").get("closedFlag"))


# ---- Autotask ---------------------------------------------------------------------------------------------------

class AutotaskProvider(TicketProvider):
    key = "autotask"
    name = "Autotask PSA"
    description = "Creates an Autotask ticket for a Keystone record when you ask, and shows when it's complete."
    policy = HostPolicy(suffixes=(".autotask.net",))
    host_field = "zone_url"
    PATH = "/ATServicesRest/V1.0"
    COMPLETE = 5
    fields = (
        ConfigField("zone_url", "Zone URL", help="Your web services zone, e.g. https://webservices16.autotask.net", example="https://webservices16.autotask.net"),
        ConfigField("username", "API user name"),
        ConfigField("secret", "API secret", secret=True),
        ConfigField("integration_code", "Tracking identifier", secret=True, help="The API tracking identifier of the API user."),
        ConfigField("company_id", "Company ID", help="Your organisation's company ID in Autotask.", example="0"),
        ConfigField("queue_id", "Queue ID", required=False),
        AUTO_CREATE,
    )
    setup = (
        SetupStep("Create an API user", "Admin > Resources > New API user, with a security level that can only add and view tickets. Note its tracking identifier."),
        SetupStep("Check", "Choose Test connection. Keystone reads the company record; it creates nothing.", kind="verify"),
    )

    def headers(self, config, secrets):
        return {"UserName": (config.get("username") or "").strip(), "Secret": secrets.get("secret", ""), "ApiIntegrationCode": secrets.get("integration_code", ""), "Content-Type": "application/json"}

    def whoami(self, api, base, config):
        item = api.json("GET", f"{base}{self.PATH}/Companies/{_int(config, 'company_id', 'Company ID')}").get("item") or {}
        return str(item.get("companyName") or "Autotask")

    def create(self, api, base, config, t):
        body = {"companyID": _int(config, "company_id", "Company ID"), "title": t.title[:255], "description": t.description[:8000], "status": 1, "priority": 2}
        if str(config.get("queue_id") or "").strip():
            body["queueID"] = _int(config, "queue_id", "Queue ID")
        r = api.json("POST", f"{base}{self.PATH}/Tickets", json=body)
        if not r.get("itemId"):
            raise ConnectorError("Autotask didn't return the new ticket.")
        return Created(str(r["itemId"]), f"T{r['itemId']}", None)

    def is_closed(self, api, base, config, external_id):
        item = api.json("GET", f"{base}{self.PATH}/Tickets/{int(external_id)}").get("item") or {}
        return item.get("status") == self.COMPLETE


TICKET_PROVIDERS = (JiraProvider(), ServiceNowProvider(), ConnectWisePsaProvider(), AutotaskProvider())
