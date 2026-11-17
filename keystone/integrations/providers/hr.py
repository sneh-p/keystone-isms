"""HR systems: BambooHR, Personio and HiBob, read-only, as the source for the People register.

Each provider returns the organisation's people (name, work email, job title, department, start and end dates,
manager's email); keystone/people/hr_sync.py applies them. Field names come from each vendor's API documentation
(mapping_note); they haven't been validated against a live account yet. Only work data is read: no salaries, home
addresses, personal contact details or anything else from the HR record.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

from ..http import Api, ConnectorError, HostPolicy, fields_of
from .base import CheckDef, ConfigField, Outcome, Provider, SetupStep

DOC_NOTE = "Field names from the vendor's API documentation; not yet validated against a live account."
MAX_PEOPLE = 20_000


@dataclass
class HrPerson:
    external_id: str
    full_name: str
    email: str | None
    job_title: str | None = None
    department: str | None = None
    employment_type: str | None = None  # employee | contractor
    start_date: date | None = None
    end_date: date | None = None
    left: bool = False  # the HR system marks them inactive or terminated
    manager_email: str | None = None


@dataclass
class HrResult:
    people: list[HrPerson]
    complete: bool  # every person was read (not a preview, not capped)
    sample_fields: dict[str, list[str]]


def _d(v) -> date | None:
    if not v:
        return None
    s = str(v)[:10]
    if s.startswith("0000"):
        return None
    try:
        return date.fromisoformat(s)
    except ValueError:
        return None


def _s(v, n: int = 200) -> str | None:
    return (str(v).strip()[:n] or None) if v not in (None, "") else None


def _contractor(text) -> str | None:
    t = str(text or "").lower()
    if not t:
        return None
    return "contractor" if any(k in t for k in ("contract", "freelanc", "external", "consult")) else "employee"


class HrProvider(Provider):
    policy: HostPolicy = HostPolicy()
    mapping_note = DOC_NOTE
    checks = (CheckDef("people", "People synced", ()),)

    def describe(self) -> dict:
        return {**super().describe(), "hr": True, "mapping_note": self.mapping_note}

    def collect(self, config: dict, secrets: dict, preview: bool = False) -> HrResult:  # pragma: no cover - interface
        raise NotImplementedError

    def run(self, config: dict, secrets: dict, session=None) -> list[Outcome]:
        """Test connection: read one page and report what was found. Saves nothing."""
        r = self.collect(config, secrets, preview=True)
        return [Outcome("people", "pass", f"Read {len(r.people)} people (first page). Fields: " + ", ".join(sorted({f for v in r.sample_fields.values() for f in v}))[:400])]


class BambooHrProvider(HrProvider):
    key = "bamboohr"
    name = "BambooHR"
    description = "Read-only: employees' names, work emails, job titles, departments, hire and termination dates."
    policy = HostPolicy(hosts=frozenset({"api.bamboohr.com"}))
    fields = (
        ConfigField("subdomain", "Company subdomain", help="The part before .bamboohr.com in your BambooHR address.", example="alpineskihouse"),
        ConfigField("api_key", "API key", secret=True, help="Created by a BambooHR user whose access level can only view the fields listed in the setup guide."),
    )
    setup = (
        SetupStep("Create a restricted access level", "Settings > Access Levels: a custom level that can view only name, work email, job title, department, supervisor, hire date, termination date and status."),
        SetupStep("Create an API key", "Signed in as a user with that access level: your name > API Keys > Add New Key. Paste it into Keystone."),
        SetupStep("Check", "Choose Test connection. Keystone reads the employee report once and saves nothing.", kind="verify"),
    )
    FIELDS = ["firstName", "lastName", "displayName", "workEmail", "jobTitle", "department", "hireDate", "terminationDate", "status", "employmentHistoryStatus", "supervisorEmail"]

    def collect(self, config, secrets, preview=False):
        import base64

        sub = (config.get("subdomain") or "").strip().lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", sub):
            raise ConnectorError("The subdomain is the part before .bamboohr.com, for example alpineskihouse.")
        auth = "Basic " + base64.b64encode(f"{secrets.get('api_key', '')}:x".encode()).decode()
        api = Api(self.policy, headers={"Authorization": auth})
        body = api.json("POST", f"https://api.bamboohr.com/api/gateway.php/{sub}/v1/reports/custom?format=JSON&onlyCurrent=false", json={"fields": self.FIELDS})
        rows = body.get("employees") or []
        out = []
        for e in rows[: 50 if preview else MAX_PEOPLE]:
            name = _s(e.get("displayName")) or " ".join(x for x in (e.get("firstName"), e.get("lastName")) if x)
            if not e.get("id") or not name:
                continue
            out.append(HrPerson(external_id=str(e["id"]), full_name=name, email=_s(e.get("workEmail"), 320), job_title=_s(e.get("jobTitle")), department=_s(e.get("department")),
                                employment_type=_contractor(e.get("employmentHistoryStatus")), start_date=_d(e.get("hireDate")), end_date=_d(e.get("terminationDate")),
                                left=str(e.get("status") or "").lower() == "inactive", manager_email=_s(e.get("supervisorEmail"), 320)))
        return HrResult(out, complete=not preview and len(rows) <= MAX_PEOPLE, sample_fields={"employees": fields_of(rows[0] if rows else None)})


class PersonioProvider(HrProvider):
    key = "personio"
    name = "Personio"
    description = "Read-only: employees' names, work emails, positions, departments, hire and termination dates."
    policy = HostPolicy(hosts=frozenset({"api.personio.de"}))
    fields = (
        ConfigField("client_id", "Client ID", help="Settings > Integrations > API credentials."),
        ConfigField("client_secret", "Client secret", secret=True),
    )
    setup = (
        SetupStep("Create API credentials", "Settings > Integrations > API credentials > Generate new credential. Readable employee attributes: first name, last name, email, position, department, hire date, termination date, status, employment type, supervisor. Nothing else."),
        SetupStep("Check", "Choose Test connection. Keystone reads one page of employees and saves nothing.", kind="verify"),
    )

    @staticmethod
    def _v(attrs: dict, key: str):
        a = attrs.get(key)
        return a.get("value") if isinstance(a, dict) else a

    def collect(self, config, secrets, preview=False):
        api = Api(self.policy)
        auth = api.json("POST", "https://api.personio.de/v1/auth", json={"client_id": (config.get("client_id") or "").strip(), "client_secret": secrets.get("client_secret", "")})
        token = (auth.get("data") or {}).get("token")
        if not token:
            raise ConnectorError("Personio didn't return a token: check the client ID and secret.")
        out, offset, sample = [], 0, None
        while True:
            body = api.json("GET", f"https://api.personio.de/v1/company/employees?limit=200&offset={offset}", headers={"Authorization": f"Bearer {token}"})
            rows = body.get("data") or []
            for r in rows:
                a = r.get("attributes") or {}
                sample = sample or a
                dept = self._v(a, "department")
                dept_name = ((dept or {}).get("attributes") or {}).get("name") if isinstance(dept, dict) else dept
                sup = self._v(a, "supervisor")
                sup_attrs = sup.get("attributes") if isinstance(sup, dict) else None
                sup_email = self._v(sup_attrs, "email") if isinstance(sup_attrs, dict) else None
                name = " ".join(x for x in (self._v(a, "first_name"), self._v(a, "last_name")) if x)
                pid = self._v(a, "id")
                if not pid or not name:
                    continue
                out.append(HrPerson(external_id=str(pid), full_name=name[:200], email=_s(self._v(a, "email"), 320), job_title=_s(self._v(a, "position")), department=_s(dept_name),
                                    employment_type=_contractor(self._v(a, "employment_type")), start_date=_d(self._v(a, "hire_date")),
                                    end_date=_d(self._v(a, "termination_date")), left=str(self._v(a, "status") or "").lower() == "inactive", manager_email=_s(sup_email, 320)))
            offset += len(rows)
            if preview or len(rows) < 200 or offset >= MAX_PEOPLE:
                break
        return HrResult(out, complete=not preview and offset < MAX_PEOPLE, sample_fields={"employees": sorted((sample or {}).keys())})


class HiBobProvider(HrProvider):
    key = "hibob"
    name = "HiBob"
    description = "Read-only: employees' names, work emails, titles, departments, start and termination dates."
    policy = HostPolicy(hosts=frozenset({"api.hibob.com"}))
    fields = (
        ConfigField("service_user_id", "Service user ID", help="Settings > Integrations > Service users."),
        ConfigField("service_user_token", "Service user token", secret=True),
    )
    setup = (
        SetupStep("Create a service user", "Settings > Integrations > Service users > New. Give it a permission group that can view only About and Work (title, department, start date, manager) and Lifecycle status, for all employees."),
        SetupStep("Check", "Choose Test connection. Keystone reads the people list once and saves nothing.", kind="verify"),
    )
    FIELDS = ["root.id", "root.displayName", "root.email", "work.title", "work.department", "work.startDate", "work.reportsTo.email", "internal.terminationDate",
              "internal.lifecycleStatus", "internal.status", "payroll.employment.type"]

    def collect(self, config, secrets, preview=False):
        import base64

        auth = "Basic " + base64.b64encode(f"{(config.get('service_user_id') or '').strip()}:{secrets.get('service_user_token', '')}".encode()).decode()
        api = Api(self.policy, headers={"Authorization": auth})
        body = api.json("POST", "https://api.hibob.com/v1/people/search", json={"fields": self.FIELDS, "showInactive": True, "humanReadable": "REPLACE"})
        rows = body.get("employees") or []
        out = []
        for e in rows[: 50 if preview else MAX_PEOPLE]:
            work, internal = e.get("work") or {}, e.get("internal") or {}
            if not e.get("id") or not e.get("displayName"):
                continue
            status = str(internal.get("lifecycleStatus") or internal.get("status") or "").lower()
            out.append(HrPerson(external_id=str(e["id"]), full_name=str(e["displayName"])[:200], email=_s(e.get("email"), 320), job_title=_s(work.get("title")),
                                department=_s(work.get("department")), employment_type=_contractor(((e.get("payroll") or {}).get("employment") or {}).get("type")),
                                start_date=_d(work.get("startDate")), end_date=_d(internal.get("terminationDate")), left=status in ("terminated", "inactive"),
                                manager_email=_s(((work.get("reportsTo") or {}).get("email")), 320)))
        return HrResult(out, complete=not preview and len(rows) <= MAX_PEOPLE, sample_fields={"employees": fields_of(rows[0] if rows else None)})


HR_PROVIDERS = (BambooHrProvider(), PersonioProvider(), HiBobProvider())
