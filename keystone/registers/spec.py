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
    needs: tuple[str, ...] = ()  # fields that must be filled in first
    note: bool = False  # a note is required (why it was rejected, what was found)
    sets: str | None = None  # a date field set to today


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


def visible(has_permission) -> list[Register]:
    return [r for r in REGISTERS.values() if has_permission(r.read)]

