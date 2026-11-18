"""Declared registers: each is a list of typed fields, who may read and change it, and a small workflow.

The server validates every value against these declarations (SC-VAL-001/002): unknown fields are refused, text is
bounded, choices are allowlisted, links must point at records that exist. A move (status change) names the permission
it needs and, for approvals, that the person approving isn't the one who raised the record (segregation of duties).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class F:
    key: str
    label: str
    type: str  # text | long | date | choice | bool | int | user | person | assets | controls | vendors | entry
    required: bool = False
    choices: tuple[tuple[str, str], ...] = ()
    listed: bool = False  # shown as a column in the register's table
    hint: str | None = None
    min: int | None = None
    max: int | None = None
    ref: str | None = None  # for "entry": the register it points at


@dataclass(frozen=True)
class Move:
    to: str
    label: str
    frm: tuple[str, ...]
    perm: str
    sod: bool = False  # not by whoever raised the record
    sod_last: bool = False  # not by whoever made the previous step (a retest isn't done by whoever fixed it)
    needs: tuple[str, ...] = ()  # fields that must be filled in first
    note: bool = False  # a note is required (why it was rejected, what was found)
    sets: str | None = None  # a date field set to today
    key: str = ""  # identifies the step when two steps lead to the same status; defaults to `to`

    @property
    def id(self) -> str:
        return self.key or self.to


@dataclass(frozen=True)
class Register:
    key: str
    title: str
    singular: str
    prefix: str
    description: str
    read: str
    write: str
    statuses: tuple[tuple[str, str, str], ...]  # (key, label, tone)
    fields: tuple[F, ...]
    moves: tuple[Move, ...] = ()
    closed: tuple[str, ...] = ()  # statuses in which the record can't be edited
    title_label: str = "Title"
    owner: bool = True
    due: str | None = None  # the date field that is the record's next due date (review, expiry, next check)
    due_label: str = "Review"
    max_due_days: int | None = None  # due date at most this far ahead (an exception for at most a year)
    due_every: tuple[str, str] | None = None  # (last-done date field, months field): next due worked out from them
    due_by: tuple[str, tuple[tuple[str, int], ...]] | None = None  # (choice field, ((choice, days), ...)): due this long after it was raised
    due_resets: bool = True  # recording a new last-done date clears a hand-set due date (False: it's a real date, e.g. a certificate expiry)
    comments: bool = True  # need-to-know registers keep comments off
    iso: str = ""
    help: str = ""  # anchor in the user guide

    @property
    def initial(self) -> str:
        return self.statuses[0][0]

    def field(self, key: str) -> F | None:
        return next((f for f in self.fields if f.key == key), None)


YES_NO = (("yes", "Yes"), ("no", "No"))

REGISTERS: dict[str, Register] = {}


def _add(r: Register) -> None:
    REGISTERS[r.key] = r


_add(Register(
    key="obligations", title="Legal and contract obligations", singular="obligation", prefix="LEG",
    description="Laws, regulations and contract commitments that bear on security and privacy, how each is met, and who keeps it under review (ISO 27001 A.5.31).",
    read="read", write="org.write", iso="A.5.31, A.5.32, A.5.34", help="legal-and-contract-obligations",
    statuses=(("active", "Active", "good"), ("retired", "No longer applies", "neutral")),
    moves=(Move("retired", "No longer applies", ("active",), "org.write", note=True), Move("active", "Applies again", ("retired",), "org.write")),
    closed=("retired",), title_label="Obligation", due="review_on",
    fields=(
        F("kind", "Kind", "choice", True, (("law", "Law"), ("regulation", "Regulation"), ("contract", "Contract"), ("standard", "Industry standard"), ("other", "Other")), listed=True),
        F("source", "Source", "text", hint="e.g. GDPR Article 32, or the customer contract and clause", listed=True, max=300),
        F("jurisdiction", "Jurisdiction or party", "text", max=200),
        F("requirement", "What it requires", "long", True),
        F("how_met", "How it is met", "long"),
        F("controls", "Controls that meet it", "controls"),
        F("review_on", "Next review", "date", listed=True),
    )))

_add(Register(
    key="changes", title="Changes", singular="change", prefix="CHG",
    description="Changes to systems and infrastructure with a security review before approval (ISO 27001 A.8.32). Someone other than the requester approves.",
    read="read", write="task.write", iso="A.8.32, A.8.9", help="changes",
    statuses=(("requested", "Requested", "primary"), ("approved", "Approved", "good"), ("rejected", "Rejected", "critical"),
              ("implemented", "Implemented", "good"), ("closed", "Closed", "neutral")),
    moves=(Move("approved", "Approve", ("requested",), "task.approve", sod=True, needs=("security_review", "rollback")),
           Move("rejected", "Reject", ("requested",), "task.approve", sod=True, note=True),
           Move("implemented", "Mark implemented", ("approved",), "task.write", sets="implemented_on"),
           Move("closed", "Close", ("implemented",), "task.write", needs=("outcome",))),
    closed=("rejected", "closed"), title_label="Change", due="planned_on", due_label="Planned",
    fields=(
        F("change_type", "Type", "choice", True, (("standard", "Standard (pre-approved kind)"), ("normal", "Normal"), ("emergency", "Emergency")), listed=True),
        F("risk_level", "Risk", "choice", True, (("low", "Low"), ("medium", "Medium"), ("high", "High")), listed=True),
        F("description", "What changes and why", "long", True),
        F("assets", "Systems affected", "assets"),
        F("security_review", "Security review", "long", hint="Effect on security: access, exposure, data, logging. Needed before approval."),
        F("rollback", "How to roll back", "long", hint="Needed before approval."),
        F("planned_on", "Planned for", "date", listed=True),
        F("implemented_on", "Implemented on", "date"),
        F("outcome", "Outcome", "long", hint="What happened, including any problems. Needed to close."),
    )))

_add(Register(
    key="policy-exceptions", title="Policy exceptions", singular="policy exception", prefix="PEX",
    description="Approved departures from a policy, with compensating controls and an end date within a year. Someone with risk-acceptance rights who didn't raise it decides.",
    read="read", write="task.write", iso="A.5.1, A.5.36", help="exceptions",
    statuses=(("requested", "Requested", "primary"), ("approved", "Approved", "good"), ("rejected", "Rejected", "critical"), ("ended", "Ended", "neutral")),
    moves=(Move("approved", "Approve", ("requested",), "risk.accept", sod=True, needs=("expires_on", "compensating")),
           Move("rejected", "Reject", ("requested",), "risk.accept", sod=True, note=True),
           Move("ended", "End now", ("approved",), "risk.accept")),
    closed=("rejected", "ended"), title_label="Exception", due="expires_on", due_label="Expires", max_due_days=365,
    fields=(
        F("policy", "Policy", "text", True, hint="The policy and section, e.g. POL-003 Access Control, section 4", listed=True, max=300),
        F("scope", "Who or what it covers", "text", True, max=300),
        F("justification", "Why it's needed", "long", True),
        F("compensating", "Compensating controls", "long", hint="What reduces the risk meanwhile. Needed before approval."),
        F("expires_on", "Ends on", "date", hint="At most a year ahead.", listed=True),
    )))

_add(Register(
    key="screening", title="Background checks", singular="background check", prefix="SCR",
    description="Pre-employment and periodic screening of people in scope (ISO 27001 A.6.1). Personal data: only people who manage people can see it.",
    read="people.write", write="people.write", iso="A.6.1", help="people-security", comments=False, owner=False,
    statuses=(("pending", "Pending", "primary"), ("clear", "Clear", "good"), ("concerns", "Concerns", "warning")),
    moves=(Move("clear", "Record as clear", ("pending",), "people.write", sets="completed_on"),
           Move("concerns", "Record concerns", ("pending",), "people.write", note=True, sets="completed_on"),
           Move("clear", "Resolved: clear", ("concerns",), "people.write", note=True)),
    title_label="Check", due="next_check_on", due_label="Next check",
    fields=(
        F("person", "Person", "person", True, listed=True),
        F("check_type", "Kind of check", "choice", True, (("identity", "Identity"), ("right_to_work", "Right to work"), ("references", "References"),
                                                   ("qualifications", "Qualifications"), ("criminal_record", "Criminal record"), ("credit", "Credit"), ("other", "Other")), listed=True),
        F("provider", "Done by", "text", max=200),
        F("completed_on", "Completed on", "date", listed=True),
        F("next_check_on", "Next check", "date", hint="For roles that need periodic screening."),
        F("note", "Note", "long", hint="Keep to what is needed: no detail of what was found."),
    )))

_add(Register(
    key="confidentiality", title="Confidentiality agreements", singular="agreement", prefix="NDA",
    description="Confidentiality and non-disclosure agreements signed by employees, contractors and others (ISO 27001 A.6.6), and when they need renewing.",
    read="people.write", write="people.write", iso="A.6.2, A.6.6", help="people-security", comments=False, owner=False,
    statuses=(("signed", "Signed", "good"), ("expired", "Expired", "warning"), ("ended", "Ended", "neutral")),
    moves=(Move("expired", "Mark expired", ("signed",), "people.write"), Move("ended", "End", ("signed", "expired"), "people.write"),
           Move("signed", "Renewed", ("expired",), "people.write", sets="signed_on")),
    title_label="Agreement", due="renew_on", due_label="Renew",
    fields=(
        F("person", "Signed by", "person", True, listed=True),
        F("agreement", "Kind", "choice", True, (("employment_contract", "Confidentiality clause in contract"), ("nda", "Non-disclosure agreement"),
                                                 ("contractor_agreement", "Contractor agreement"), ("acceptable_use", "Acceptable use"), ("other", "Other")), listed=True),
        F("signed_on", "Signed on", "date", True, listed=True),
        F("renew_on", "Renew by", "date"),
        F("location", "Where it is kept", "text", hint="e.g. the HR system, not the document itself", max=300),
    )))

_add(Register(
    key="sites", title="Sites and secure areas", singular="site", prefix="SITE",
    description="Offices, server rooms, data centres and other areas to protect, with their security zone and physical controls (ISO 27001 A.7.1 to A.7.4).",
    read="read", write="asset.write", iso="A.7.1, A.7.2, A.7.3, A.7.4", help="physical-security",
    statuses=(("active", "In use", "good"), ("closed", "No longer used", "neutral")),
    moves=(Move("closed", "No longer used", ("active",), "asset.write"), Move("active", "In use again", ("closed",), "asset.write")),
    closed=("closed",), title_label="Site or area", due="review_on",
    fields=(
        F("kind", "Kind", "choice", True, (("office", "Office"), ("server_room", "Server room"), ("data_centre", "Data centre"), ("warehouse", "Warehouse or store"),
                                           ("shop", "Shop or public area"), ("other", "Other")), listed=True),
        F("zone", "Security zone", "choice", True, (("public", "Public"), ("internal", "Internal"), ("secure", "Secure"), ("restricted", "Restricted")), listed=True),
        F("address", "Where", "text", max=300),
        F("controls_text", "Physical controls", "long", hint="Locks, badges, CCTV, alarms, reception, visitor rules."),
        F("assets", "Assets kept there", "assets"),
        F("review_on", "Next review", "date", listed=True),
    )))

_add(Register(
    key="visitors", title="Visitor log", singular="visit", prefix="VIS",
    description="Visitors to secure areas: who, whom they visited, and when they left (ISO 27001 A.7.2). Personal data: only people who manage assets can see it.",
    read="asset.write", write="asset.write", iso="A.7.2", help="physical-security", comments=False,
    statuses=(("on_site", "On site", "primary"), ("left", "Left", "neutral")),
    moves=(Move("left", "Signed out", ("on_site",), "asset.write", sets="left_on"),),
    closed=("left",), title_label="Visitor", owner=False,
    fields=(
        F("organisation", "Organisation", "text", listed=True, max=200),
        F("site", "Site", "entry", True, ref="sites", listed=True),
        F("host", "Host", "user", True, listed=True),
        F("purpose", "Purpose", "text", max=300),
        F("arrived_on", "Arrived", "date", True, listed=True),
        F("left_on", "Left", "date"),
        F("badge_returned", "Badge returned", "bool"),
    )))

_add(Register(
    key="physical-checks", title="Physical security checks", singular="check", prefix="PHY",
    description="Regular checks of physical security equipment and of who holds badges and keys (ISO 27001 A.7.4, A.7.11, A.7.13).",
    read="read", write="asset.write", iso="A.7.4, A.7.11, A.7.13", help="physical-security",
    statuses=(("ok", "OK", "good"), ("issues", "Issues found", "warning"), ("retired", "Retired", "neutral")),
    moves=(Move("issues", "Record issues", ("ok",), "asset.write", note=True, sets="last_done_on"),
           Move("ok", "Record as OK", ("ok", "issues"), "asset.write", sets="last_done_on"),
           Move("retired", "Retire", ("ok", "issues"), "asset.write")),
    closed=("retired",), title_label="Check", due="next_due_on", due_label="Next due", due_every=("last_done_on", "every_months"),
    fields=(
        F("equipment", "What is checked", "choice", True, (("cctv", "CCTV"), ("alarm", "Intruder alarm"), ("access_control", "Access control and badges"),
                                                            ("badge_review", "Badge and key holders"), ("fire", "Fire detection and suppression"),
                                                            ("power", "UPS and power"), ("cooling", "Cooling"), ("other", "Other")), listed=True),
        F("site", "Site", "entry", ref="sites", listed=True),
        F("every_months", "Every (months)", "int", True, min=1, max=36),
        F("last_done_on", "Last done", "date", listed=True),
        F("next_due_on", "Next due", "date", hint="Worked out from the last check and how often, unless you set it."),
        F("findings", "Findings", "long"),
    )))


SEVERITY = (("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low"), ("info", "Information"))

_add(Register(
    key="pentests", title="Penetration tests", singular="test", prefix="PEN",
    description="Penetration tests, red-team exercises, vulnerability assessments and bug bounty reports, with their findings tracked to a verified fix (ISO 27001 A.8.8, A.8.29, A.5.35).",
    read="read", write="risk.write", iso="A.8.8, A.8.29, A.5.35", help="penetration-tests",
    statuses=(("planned", "Planned", "neutral"), ("in_progress", "In progress", "primary"), ("reported", "Reported", "warning"), ("closed", "Closed", "good")),
    moves=(Move("in_progress", "Start", ("planned",), "risk.write", sets="started_on"),
           Move("reported", "Report received", ("in_progress",), "risk.write", sets="finished_on"),
           Move("closed", "Close", ("reported",), "risk.write", note=True)),
    closed=("closed",), title_label="Test", due="retest_on", due_label="Retest",
    fields=(
        F("kind", "Kind", "choice", True, (("pentest", "Penetration test"), ("red_team", "Red team"), ("vuln_assessment", "Vulnerability assessment"),
                                           ("bug_bounty", "Bug bounty report"), ("other", "Other")), listed=True),
        F("provider", "Done by", "text", True, listed=True, max=200),
        F("scope", "Scope", "long", True),
        F("assets", "Systems in scope", "assets"),
        F("started_on", "Started", "date"),
        F("finished_on", "Report received", "date", listed=True),
        F("report_location", "Where the report is kept", "text", hint="Reports hold attack detail: keep them access-controlled.", max=300),
        F("retest_on", "Retest by", "date"),
    )))

_add(Register(
    key="findings", title="Test findings", singular="finding", prefix="FND",
    description="Findings from penetration tests and other security tests. A fix is verified by someone other than whoever fixed it.",
    read="read", write="risk.write", iso="A.8.8, A.5.35", help="penetration-tests",
    statuses=(("open", "Open", "critical"), ("fixed", "Fixed, to retest", "warning"), ("verified", "Verified", "good"), ("accepted", "Risk accepted", "neutral")),
    moves=(Move("fixed", "Mark fixed", ("open",), "task.write", note=True),
           Move("verified", "Retest passed", ("fixed",), "audit.findings", sod_last=True),
           Move("open", "Retest failed", ("fixed",), "audit.findings", sod_last=True, note=True, key="reopen"),
           Move("accepted", "Accept the risk", ("open",), "risk.accept", note=True, needs=("risk_note",))),
    closed=("verified", "accepted"), title_label="Finding", due="fix_by", due_label="Fix by",
    due_by=("severity", (("critical", 15), ("high", 30), ("medium", 90), ("low", 180), ("info", 365))),
    fields=(
        F("test", "From test", "entry", True, ref="pentests", listed=True),
        F("severity", "Severity", "choice", True, SEVERITY, listed=True),
        F("assets", "Affected systems", "assets"),
        F("description", "What was found", "long", True),
        F("recommendation", "Recommended fix", "long"),
        F("fix_by", "Fix by", "date", hint="Empty: worked out from the severity (critical 15 days, high 30, medium 90, low 180)."),
        F("risk_note", "Why the risk is accepted", "long", hint="Needed to accept the risk instead of fixing."),
    )))

_add(Register(
    key="applications", title="Applications", singular="application", prefix="APP",
    description="The software you build or run for customers, with its data, criticality and security activities (ISO 27001 A.8.25 to A.8.29).",
    read="read", write="control.write", iso="A.8.25, A.8.26, A.8.27, A.8.28, A.8.29", help="application-security",
    statuses=(("active", "In use", "good"), ("development", "In development", "primary"), ("retired", "Retired", "neutral")),
    moves=(Move("active", "In use", ("development", "retired"), "control.write"), Move("retired", "Retire", ("active", "development"), "control.write")),
    closed=("retired",), title_label="Application", due="review_on",
    fields=(
        F("criticality", "Criticality", "choice", True, (("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low")), listed=True),
        F("data", "Most sensitive data", "choice", True, (("public", "Public"), ("internal", "Internal"), ("confidential", "Confidential"), ("restricted", "Restricted")), listed=True),
        F("personal_data", "Personal data", "bool"),
        F("description", "What it does", "long"),
        F("repository", "Source code", "text", hint="Repository name or location", max=300),
        F("hosting", "Where it runs", "text", max=300),
        F("practices", "Security activities", "long", hint="Code review, dependency and secret scanning, static analysis, tests."),
        F("assets", "Related assets", "assets"),
        F("review_on", "Next review", "date"),
    )))

_add(Register(
    key="threat-models", title="Threat models", singular="threat model", prefix="TMD",
    description="What could go wrong with an application or system, and what is done about it (ISO 27001 A.8.27). Someone other than the author approves it.",
    read="read", write="control.write", iso="A.8.27, A.5.8", help="application-security",
    statuses=(("draft", "Draft", "primary"), ("approved", "Approved", "good"), ("retired", "Retired", "neutral")),
    moves=(Move("approved", "Approve", ("draft",), "task.approve", sod=True, needs=("mitigations",)),
           Move("draft", "Revise", ("approved",), "control.write", key="revise"),
           Move("retired", "Retire", ("draft", "approved"), "control.write")),
    closed=("retired",), title_label="Threat model", due="review_on",
    fields=(
        F("application", "Application", "entry", True, ref="applications", listed=True),
        F("method", "Method", "choice", True, (("stride", "STRIDE"), ("linddun", "LINDDUN (privacy)"), ("pasta", "PASTA"), ("attack_trees", "Attack trees"), ("other", "Other")), listed=True),
        F("scope", "Scope and data flows", "long", True),
        F("threats", "Threats", "long", True),
        F("mitigations", "Mitigations", "long", hint="Needed before approval."),
        F("residual", "Residual risk", "choice", choices=(("low", "Low"), ("medium", "Medium"), ("high", "High"))),
        F("review_on", "Next review", "date", listed=True),
    )))

_add(Register(
    key="release-signoffs", title="Release sign-offs", singular="sign-off", prefix="REL",
    description="Security sign-off before a release goes live: what changed, what was tested, and what is still open (ISO 27001 A.8.29). Someone other than the requester signs off.",
    read="read", write="control.write", iso="A.8.29, A.8.32", help="application-security",
    statuses=(("requested", "Requested", "primary"), ("approved", "Signed off", "good"), ("rejected", "Not signed off", "critical")),
    moves=(Move("approved", "Sign off", ("requested",), "task.approve", sod=True, needs=("tests",)),
           Move("rejected", "Don't sign off", ("requested",), "task.approve", sod=True, note=True)),
    closed=("approved", "rejected"), title_label="Release", due="release_on", due_label="Release date",
    fields=(
        F("application", "Application", "entry", True, ref="applications", listed=True),
        F("version", "Version", "text", True, listed=True, max=60),
        F("changes", "What changed", "long", True),
        F("tests", "Security testing done", "long", hint="Dependency and secret scanning, static analysis, tests, pentest. Needed to sign off."),
        F("open_findings", "Known open findings", "long"),
        F("release_on", "Release date", "date"),
    )))

_add(Register(
    key="crypto", title="Certificates and keys", singular="certificate or key", prefix="KEY",
    description="Certificates, keys and secrets you depend on, with their owner, expiry and rotation (ISO 27001 A.8.24). Public certificates seen by the internet-facing checks are added by themselves.",
    read="read", write="asset.write", iso="A.8.24", help="certificates-and-keys",
    statuses=(("active", "In use", "good"), ("retired", "Retired", "neutral")),
    moves=(Move("active", "Record rotation", ("active",), "asset.write", sets="last_rotated_on", key="rotated"),
           Move("retired", "Retire", ("active",), "asset.write")),
    closed=("retired",), title_label="Certificate or key", due="expires_on", due_label="Renew by", due_every=("last_rotated_on", "rotate_every_months"), due_resets=False,
    fields=(
        F("kind", "Kind", "choice", True, (("tls_certificate", "TLS certificate"), ("code_signing", "Code signing certificate"), ("encryption_key", "Encryption key"),
                                           ("signing_key", "Signing key"), ("ssh_key", "SSH key"), ("api_secret", "API key or secret"), ("other", "Other")), listed=True),
        F("location", "Where it is used", "text", True, listed=True, max=300),
        F("storage", "Where it is kept", "text", hint="e.g. the key vault or HSM; never the key itself", max=300),
        F("algorithm", "Algorithm and size", "text", max=100),
        F("expires_on", "Expires", "date"),
        F("rotate_every_months", "Rotate every (months)", "int", min=1, max=120),
        F("last_rotated_on", "Last rotated", "date"),
        F("source", "Added by", "text", max=100),
    )))

_add(Register(
    key="backups", title="Backup jobs", singular="backup job", prefix="BAK",
    description="What is backed up, how often, and when a restore was last tested (ISO 27001 A.8.13). Restore tests are due on a schedule.",
    read="read", write="continuity.write", iso="A.8.13, A.5.30", help="backup-assurance",
    statuses=(("ok", "Working", "good"), ("failing", "Failing", "critical"), ("retired", "Retired", "neutral")),
    moves=(Move("ok", "Record a successful backup", ("ok", "failing"), "continuity.write", sets="last_success_on", key="success"),
           Move("failing", "Record a failure", ("ok", "failing"), "continuity.write", note=True, key="failure"),
           Move("ok", "Record a restore test", ("ok",), "continuity.write", sets="last_restore_test_on", note=True, key="restore_test"),
           Move("retired", "Retire", ("ok", "failing"), "continuity.write")),
    closed=("retired",), title_label="Backup job", due="restore_test_due", due_label="Restore test due", due_every=("last_restore_test_on", "restore_test_every_months"),
    fields=(
        F("assets", "Systems backed up", "assets"),
        F("tool", "Backup tool", "text", True, listed=True, max=200),
        F("frequency", "How often", "choice", True, (("hourly", "Hourly"), ("daily", "Daily"), ("weekly", "Weekly"), ("monthly", "Monthly")), listed=True),
        F("retention", "Kept for", "text", max=200),
        F("offsite", "Copy kept off-site or immutable", "bool"),
        F("last_success_on", "Last successful backup", "date", listed=True),
        F("last_restore_test_on", "Last restore test", "date"),
        F("restore_test_every_months", "Restore test every (months)", "int", True, min=1, max=24),
        F("restore_test_due", "Restore test due", "date", hint="Worked out from the last test unless you set it."),
    )))


def visible(has_permission) -> list[Register]:
    return [r for r in REGISTERS.values() if has_permission(r.read)]

