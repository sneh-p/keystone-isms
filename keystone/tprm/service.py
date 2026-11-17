from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, timedelta
from functools import lru_cache
from urllib.parse import urlparse

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.assets.models import Asset
from keystone.core.db import utcnow
from keystone.core.services import apply_fields, authorize, get_or_404, require_text, today
from keystone.core.settings import PROJECT_ROOT
from keystone.risk import fair
from keystone.risk.models import Risk

from .models import (
    ACCESS_LEVELS, ASSESSMENT_STATUSES, CRITICALITY, SENSITIVITY, VENDOR_STATUSES,
    QuestionnaireTemplate, Vendor, VendorAssessment, VendorQuestionnaire,
)

QUESTION_TYPES = {"yn": ("yes", "no", "na"), "ynp": ("yes", "partial", "no", "na"), "text": None}
ANSWER_VALUE = {"yes": 1.0, "partial": 0.5, "no": 0.0}


@dataclass(frozen=True)
class TprmConfig:
    points: dict
    tiers: list[dict]
    assessment_max_age_days: int
    contract_renewal_warning_days: int

    def tier_label(self, tier: int) -> str:
        return next(t["label"] for t in self.tiers if t["tier"] == tier)

    def review_days(self, tier: int) -> int:
        return next(t["review_days"] for t in self.tiers if t["tier"] == tier)


@lru_cache(maxsize=2)
def load_config(path: str = str(PROJECT_ROOT / "config" / "tprm.yaml")) -> TprmConfig:
    d = yaml.safe_load(open(path, encoding="utf-8"))
    return TprmConfig(d["points"], sorted(d["tiers"], key=lambda t: -t["min_points"]), d["assessment_max_age_days"], d["contract_renewal_warning_days"])


def compute_tier(data_sensitivity: str, operational_criticality: str, access_level: str, processes_personal_data: bool) -> int:
    cfg = load_config()
    p = cfg.points
    total = p["data_sensitivity"][data_sensitivity] + p["operational_criticality"][operational_criticality] + p["access_level"][access_level] + (p["processes_personal_data"] if processes_personal_data else 0)
    for t in cfg.tiers:
        if total >= t["min_points"]:
            return t["tier"]
    return cfg.tiers[-1]["tier"]


_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalise_website(value: str) -> str:
    """Accept 'example.com' or an http(s) URL; reject anything else (e.g. javascript:)."""
    value = value.strip()
    p = urlparse(value if "://" in value else f"https://{value}")
    host = (p.hostname or "").lower()
    if p.scheme not in ("http", "https") or not _HOST.match(host) or p.username or p.password:
        raise ValueError("Website must be a domain or http(s) URL.")
    return value if "://" in value else f"https://{value}"


# ---- vendors ------------------------------------------------------------------------------

VENDOR_FIELDS = {"name", "legal_name", "website", "description", "services", "category", "owner_id", "status", "data_sensitivity", "operational_criticality", "access_level", "processes_personal_data", "tier_override", "tier_override_reason", "contract_start", "contract_end", "dpa_signed", "next_review_date", "notes"}


def save_vendor(session: Session, actor, vendor_id: int | None = None, *, asset_ids: list[int] | None = None, risk_ids: list[int] | None = None, **fields) -> Vendor:
    authorize(session, actor, "vendor.write")
    v = get_or_404(session, Vendor, vendor_id) if vendor_id else Vendor(status="prospective", data_sensitivity="none", operational_criticality="low", access_level="none", processes_personal_data=False, dpa_signed=False)
    was = v.status
    apply_fields(v, fields, VENDOR_FIELDS)
    if v.status == "terminated" and was in ("active", "offboarding"):
        missing = [label for k, label in OFFBOARDING_ITEMS.items() if k not in (v.offboarding or {})]
        if missing:
            raise ValueError("Finish the offboarding checklist before terminating: " + "; ".join(missing[:3]) + ("…" if len(missing) > 3 else "") + ". Set the vendor to offboarding to get the checklist.")
    require_text(v.name, "Vendor name")
    for val, allowed, label in ((v.status, VENDOR_STATUSES, "status"), (v.data_sensitivity, SENSITIVITY, "data_sensitivity"), (v.operational_criticality, CRITICALITY, "operational_criticality"), (v.access_level, ACCESS_LEVELS, "access_level")):
        if val not in allowed:
            raise ValueError(f"{label} must be one of {allowed}")
    if v.website:
        v.website = normalise_website(v.website)
    if v.tier_override is not None:
        if v.tier_override not in (1, 2, 3, 4):
            raise ValueError("Tier override must be 1-4.")
        if not (v.tier_override_reason or "").strip():
            raise ValueError("Explain why the tier is overridden.")
    if v.contract_start and v.contract_end and v.contract_end < v.contract_start:
        raise ValueError("Contract end is before contract start.")
    dup = session.scalar(select(Vendor).where(Vendor.name == v.name, Vendor.id != (v.id or 0)))
    if dup:
        raise ValueError(f"A vendor named {v.name!r} already exists.")
    v.computed_tier = compute_tier(v.data_sensitivity, v.operational_criticality, v.access_level, v.processes_personal_data)
    if v.next_review_date is None:
        v.next_review_date = today() + timedelta(days=load_config().review_days(v.tier))
    if asset_ids is not None:
        v.assets = list(session.scalars(select(Asset).where(Asset.id.in_(asset_ids))))
    if risk_ids is not None:
        v.risks = list(session.scalars(select(Risk).where(Risk.id.in_(risk_ids))))
    session.add(v)
    session.flush()
    return v


def list_vendors(session: Session, include_terminated: bool = False) -> list[Vendor]:
    q = select(Vendor).order_by(Vendor.name)
    if not include_terminated:
        q = q.where(Vendor.status != "terminated")
    return list(session.scalars(q))


def latest_approved_assessment(session: Session, vendor_id: int) -> VendorAssessment | None:
    return session.scalar(select(VendorAssessment).where(VendorAssessment.vendor_id == vendor_id, VendorAssessment.status == "approved").order_by(VendorAssessment.approved_at.desc()).limit(1))


def vendor_attention(session: Session, on: date | None = None) -> dict[str, list[Vendor]]:
    on = on or today()
    cfg = load_config()
    out: dict[str, list[Vendor]] = {"review_overdue": [], "contract_ending": [], "needs_assessment": [], "no_dpa": [], "questionnaire_overdue": [], "offboarding": []}
    overdue_q = {q.vendor_id for q in session.scalars(select(VendorQuestionnaire).where(VendorQuestionnaire.status == "sent", VendorQuestionnaire.due_date < on))}
    for v in list_vendors(session):
        if v.status == "offboarding":
            out["offboarding"].append(v)
        if v.status not in ("active", "prospective"):
            continue
        if v.next_review_date and v.next_review_date < on:
            out["review_overdue"].append(v)
        if v.contract_end and on <= v.contract_end <= on + timedelta(days=cfg.contract_renewal_warning_days):
            out["contract_ending"].append(v)
        if v.tier <= 2:
            a = latest_approved_assessment(session, v.id)
            if a is None or a.approved_at is None or (on - a.approved_at.date()).days > cfg.assessment_max_age_days:
                out["needs_assessment"].append(v)
        if v.processes_personal_data and not v.dpa_signed:
            out["no_dpa"].append(v)
        if v.id in overdue_q:
            out["questionnaire_overdue"].append(v)
    return out


def mark_vendor_reviewed(session: Session, actor, vendor_id: int) -> Vendor:
    authorize(session, actor, "vendor.write")
    v = get_or_404(session, Vendor, vendor_id)
    v.next_review_date = today() + timedelta(days=load_config().review_days(v.tier))
    session.flush()
    return v


# ---- questionnaires ---------------------------------------------------------------------------

def validate_questions(questions: list[dict]) -> None:
    ids = [q.get("id") for q in questions]
    if not questions or len(ids) != len(set(ids)) or not all(ids):
        raise ValueError("Questions need unique ids.")
    for q in questions:
        if q.get("type") not in QUESTION_TYPES:
            raise ValueError(f"Question {q['id']}: type must be one of {list(QUESTION_TYPES)}")
        require_text(q.get("text"), f"Question {q['id']} text")
        if float(q.get("weight", 1)) < 0:
            raise ValueError(f"Question {q['id']}: weight must not be negative")


QUESTION_KEYS = {"id", "section", "text", "type", "weight", "control", "required"}
MAX_QUESTIONS = 200


def clean_questions(questions: list[dict]) -> list[dict]:
    """Questions as stored: known keys only, trimmed text, ids short and unique, weights 0-10, control codes checked by
    format only (a template may name a control a later content pack adds)."""
    import re

    if not isinstance(questions, list) or not 0 < len(questions) <= MAX_QUESTIONS:
        raise ValueError(f"A template has between 1 and {MAX_QUESTIONS} questions.")
    out = []
    for q in questions:
        if not isinstance(q, dict) or set(q) - QUESTION_KEYS:
            raise ValueError("Each question has an id, section, text, type, weight, control and required flag only.")
        qid = str(q.get("id") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,30}", qid):
            raise ValueError(f"Question id {qid[:30]!r}: letters, digits, - and _ (up to 30).")
        try:
            weight = float(q.get("weight", 1))
        except (TypeError, ValueError):
            raise ValueError(f"Question {qid}: weight must be a number.") from None
        if not 0 <= weight <= 10:
            raise ValueError(f"Question {qid}: weight must be between 0 and 10.")
        control = str(q.get("control") or "").strip() or None
        if control and not re.fullmatch(r"KC-[A-Z]{2,4}-[0-9]{2,3}", control):
            raise ValueError(f"Question {qid}: {control[:20]!r} isn't a Keystone control code.")
        out.append({"id": qid, "section": str(q.get("section") or "General").strip()[:100], "text": str(q.get("text") or "").strip()[:2000],
                    "type": q.get("type"), "weight": weight, **({"control": control} if control else {}), "required": bool(q.get("required"))})
    validate_questions(out)
    return out


def template_in_use(session: Session, template_id: int) -> bool:
    return session.scalar(select(VendorQuestionnaire.id).where(VendorQuestionnaire.template_id == template_id)) is not None


def update_template(session: Session, actor, template_id: int, *, name: str | None = None, version: str | None = None, description: str | None = None,
                    questions: list[dict] | None = None, active: bool | None = None) -> QuestionnaireTemplate:
    """Edit a template. Once questionnaires were sent from it, its questions are fixed (answers refer to them): save a
    new version instead."""
    authorize(session, actor, "vendor.write")
    t = get_or_404(session, QuestionnaireTemplate, template_id)
    if questions is not None:
        if template_in_use(session, t.id):
            raise ValueError("Questionnaires were sent from this template, so its questions can't change. Save it as a new version.")
        t.questions = clean_questions(questions)
    if name is not None:
        t.name = require_text(name, "Template name")[:200]
    if version is not None:
        t.version = require_text(version, "Version")[:20]
    if description is not None:
        t.description = description.strip()[:4000] or None
    if active is not None:
        t.active = active
    session.flush()
    return t


def new_template_version(session: Session, actor, template_id: int, version: str, questions: list[dict] | None = None) -> QuestionnaireTemplate:
    """A copy with a new version label (and optionally changed questions); the old version is retired from new sends."""
    authorize(session, actor, "vendor.write")
    old = get_or_404(session, QuestionnaireTemplate, template_id)
    version = require_text(version, "Version")[:20]
    if session.scalar(select(QuestionnaireTemplate.id).where(QuestionnaireTemplate.name == old.name, QuestionnaireTemplate.version == version)):
        raise ValueError(f"Version {version} of {old.name} already exists.")
    t = QuestionnaireTemplate(name=old.name, version=version, description=old.description, questions=clean_questions(questions if questions is not None else list(old.questions)), active=True)
    session.add(t)
    old.active = False
    session.flush()
    return t


# ---- offboarding a vendor (A.5.19, A.5.20, A.5.22) ----------------------------------------------------------------

OFFBOARDING_ITEMS = {
    "access_removed": "Their accounts, VPN, API keys and integrations are removed",
    "data_returned_or_deleted": "Our data is returned or deleted, confirmed in writing",
    "assets_returned": "Equipment and documents we lent them are returned",
    "dpa_closed": "The data processing agreement is closed (or not applicable)",
    "subprocessors_updated": "Subprocessor lists and the Trust Center no longer name them",
    "risks_reviewed": "Risks and assets that depended on them are reviewed",
}


def tick_vendor_offboarding(session: Session, actor, vendor_id: int, item: str, done: bool) -> Vendor:
    from keystone.core.db import utcnow

    authorize(session, actor, "vendor.write")
    v = get_or_404(session, Vendor, vendor_id)
    if v.status != "offboarding":
        raise ValueError("Set the vendor to offboarding first.")
    if item not in OFFBOARDING_ITEMS:
        raise ValueError("Unknown checklist item.")
    state = dict(v.offboarding or {})
    if done:
        state[item] = {"by": getattr(actor, "display_name", None) or actor.username, "at": utcnow().isoformat(timespec="seconds")}
    else:
        state.pop(item, None)
    v.offboarding = state
    session.flush()
    return v


def save_template(session: Session, actor, *, name: str, version: str, questions: list[dict], description: str | None = None, template_id: int | None = None) -> QuestionnaireTemplate:
    authorize(session, actor, "vendor.write")
    validate_questions(questions)
    t = get_or_404(session, QuestionnaireTemplate, template_id) if template_id else QuestionnaireTemplate(active=True)
    t.name, t.version, t.description, t.questions = require_text(name, "Template name"), require_text(version, "Version"), description, questions
    session.add(t)
    session.flush()
    return t


def load_default_templates(session: Session, actor) -> list[QuestionnaireTemplate]:
    out = []
    for path in sorted((PROJECT_ROOT / "content" / "questionnaires").glob("*.yaml")):
        d = yaml.safe_load(path.read_text(encoding="utf-8"))
        existing = session.scalar(select(QuestionnaireTemplate).where(QuestionnaireTemplate.name == d["name"], QuestionnaireTemplate.version == d["version"]))
        out.append(existing or save_template(session, actor, name=d["name"], version=d["version"], description=d.get("description"), questions=d["questions"]))
    return out


def templates(session: Session) -> list[QuestionnaireTemplate]:
    return list(session.scalars(select(QuestionnaireTemplate).where(QuestionnaireTemplate.active.is_(True)).order_by(QuestionnaireTemplate.name)))


def score_responses(questions: list[dict], responses: dict) -> tuple[float | None, list[dict]]:
    """Weighted % score over answered, applicable questions, plus findings (no/partial answers)."""
    total = got = 0.0
    findings = []
    for q in questions:
        if q["type"] == "text":
            continue
        ans = (responses.get(q["id"]) or {}).get("answer")
        if ans not in ANSWER_VALUE:
            continue
        w = float(q.get("weight", 1))
        total += w
        got += w * ANSWER_VALUE[ans]
        if ans in ("no", "partial"):
            findings.append({"id": q["id"], "question": q["text"], "answer": ans, "control": q.get("control"), "weight": w, "comment": (responses.get(q["id"]) or {}).get("comment")})
    findings.sort(key=lambda f: (-f["weight"], f["answer"] != "no"))
    return (round(100 * got / total, 1) if total else None), findings


def missing_required(questions: list[dict], responses: dict) -> list[str]:
    return [q["id"] for q in questions if q.get("required") and not (responses.get(q["id"]) or {}).get("answer")]


def send_questionnaire(session: Session, actor, vendor_id: int, template_id: int, due_date: date | None = None) -> VendorQuestionnaire:
    authorize(session, actor, "vendor.write")
    get_or_404(session, Vendor, vendor_id)
    get_or_404(session, QuestionnaireTemplate, template_id)
    q = VendorQuestionnaire(vendor_id=vendor_id, template_id=template_id, status="sent", responses={}, sent_at=utcnow(), due_date=due_date or today() + timedelta(days=30))
    session.add(q)
    session.flush()
    return q


def record_responses(session: Session, actor, questionnaire_id: int, responses: dict, complete: bool = False) -> VendorQuestionnaire:
    """Store responses (entered by staff from the vendor's reply). complete=True marks it received."""
    authorize(session, actor, "vendor.write")
    vq = get_or_404(session, VendorQuestionnaire, questionnaire_id)
    apply_responses(vq, responses, complete)
    session.flush()
    return vq


MAX_ANSWER = 10_000


def apply_responses(vq: VendorQuestionnaire, responses: dict, complete: bool = False) -> None:
    """Validate and merge responses (shared by staff entry and the vendor portal; callers authorise)."""
    if vq.status == "reviewed":
        raise ValueError("This questionnaire has been reviewed and is locked.")
    questions = {q["id"]: q for q in vq.template.questions}
    clean = {}
    for qid, resp in responses.items():
        if qid not in questions:
            raise ValueError(f"Unknown question {qid}")
        if resp is not None and not isinstance(resp, dict):
            raise ValueError(f"Question {qid}: invalid response")
        allowed = QUESTION_TYPES[questions[qid]["type"]]
        ans = (resp or {}).get("answer")
        comment = (resp or {}).get("comment")
        if not isinstance(ans, (str, type(None))) or not isinstance(comment, (str, type(None))):
            raise ValueError(f"Question {qid}: answers and comments must be text")
        if len(ans or "") > MAX_ANSWER or len(comment or "") > MAX_ANSWER:
            raise ValueError(f"Question {qid}: answers are limited to {MAX_ANSWER} characters")
        if allowed and ans not in (*allowed, None, ""):
            raise ValueError(f"Question {qid}: answer must be one of {allowed}")
        clean[qid] = {"answer": ans or None, "comment": (comment or "").strip() or None}
    vq.responses = {**(vq.responses or {}), **clean}
    if complete:
        missing = missing_required(vq.template.questions, vq.responses)
        if missing:
            raise ValueError("Required questions unanswered: " + ", ".join(missing))
        vq.status, vq.received_at = "received", utcnow()
    vq.score, _ = score_responses(vq.template.questions, vq.responses)


def review_questionnaire(session: Session, actor, questionnaire_id: int, notes: str) -> VendorQuestionnaire:
    authorize(session, actor, "vendor.write")
    vq = get_or_404(session, VendorQuestionnaire, questionnaire_id)
    if vq.status != "received":
        raise ValueError("Only received questionnaires can be reviewed.")
    vq.status, vq.reviewed_by_id, vq.reviewed_at, vq.review_notes = "reviewed", actor.id, utcnow(), require_text(notes, "Review notes")
    session.flush()
    return vq


def questionnaires_for(session: Session, vendor_id: int | None = None) -> list[VendorQuestionnaire]:
    q = select(VendorQuestionnaire).order_by(VendorQuestionnaire.sent_at.desc())
    if vendor_id:
        q = q.where(VendorQuestionnaire.vendor_id == vendor_id)
    return list(session.scalars(q))


# ---- FAIR vendor assessments ----------------------------------------------------------------------

RANGE_FIELDS = ("tef", "tcap", "control_strength", "plm", "slef", "slm")
ASSESSMENT_FIELDS = {"title", "scenario", "integration_depth", "entra_tenant_id", "questionnaire_id", "conclusion", *RANGE_FIELDS}


def _range_dict(value) -> dict | None:
    r = fair.Range.of(value)
    return None if r is None else {"min": r.min, "ml": r.ml, "max": r.max}


def save_assessment(session: Session, actor, vendor_id: int, assessment_id: int | None = None, **fields) -> VendorAssessment:
    authorize(session, actor, "vendor.write")
    get_or_404(session, Vendor, vendor_id)
    a = get_or_404(session, VendorAssessment, assessment_id) if assessment_id else VendorAssessment(vendor_id=vendor_id, status="draft")
    if a.status == "approved":
        raise ValueError("Approved assessments are locked; start a new assessment instead.")
    for k in RANGE_FIELDS:
        if k in fields:
            fields[k] = _range_dict(fields[k])
    apply_fields(a, fields, ASSESSMENT_FIELDS)
    require_text(a.title, "Assessment title")
    session.add(a)
    session.flush()
    return a


def fair_inputs(a: VendorAssessment) -> fair.FairInputs:
    if not (a.tef and a.plm and a.tcap and a.control_strength):
        raise ValueError("TEF, threat capability, control strength and primary loss are needed to run FAIR.")
    return fair.FairInputs.from_dict({"tef": a.tef, "tcap": a.tcap, "cs": a.control_strength, "plm": a.plm, "slef": a.slef, "slm": a.slm})


def run_assessment(session: Session, actor, assessment_id: int, iterations: int = 10_000, seed: int | None = None) -> fair.FairResult:
    authorize(session, actor, "vendor.write")
    a = get_or_404(session, VendorAssessment, assessment_id)
    if a.status == "approved":
        raise ValueError("Approved assessments are locked.")
    res = fair.simulate(fair_inputs(a), iterations=iterations, seed=seed)
    a.result, a.run_at = res.to_dict(), utcnow()
    session.flush()
    return res


def submit_assessment(session: Session, actor, assessment_id: int) -> VendorAssessment:
    authorize(session, actor, "vendor.write")
    a = get_or_404(session, VendorAssessment, assessment_id)
    if a.status != "draft":
        raise ValueError("Only drafts can be submitted.")
    if a.result is None:
        raise ValueError("Run the FAIR simulation before submitting.")
    a.status = "in_review"
    session.flush()
    return a


def approve_assessment(session: Session, actor, assessment_id: int, conclusion: str) -> VendorAssessment:
    authorize(session, actor, "vendor.approve")
    a = get_or_404(session, VendorAssessment, assessment_id)
    if a.status != "in_review":
        raise ValueError("Only assessments in review can be approved.")
    if a.created_by_id == actor.id:
        raise ValueError("Segregation of duties: the author cannot approve their own assessment.")
    a.conclusion = require_text(conclusion, "Conclusion")
    a.status, a.approved_by_id, a.approved_at = "approved", actor.id, utcnow()
    v = a.vendor
    v.next_review_date = today() + timedelta(days=load_config().review_days(v.tier))
    session.flush()
    return a


def return_assessment(session: Session, actor, assessment_id: int) -> VendorAssessment:
    authorize(session, actor, "vendor.approve")
    a = get_or_404(session, VendorAssessment, assessment_id)
    if a.status != "in_review":
        raise ValueError("Only assessments in review can be returned.")
    a.status = "draft"
    session.flush()
    return a


def assessments_for(session: Session, vendor_id: int | None = None) -> list[VendorAssessment]:
    q = select(VendorAssessment).order_by(VendorAssessment.id.desc())
    if vendor_id:
        q = q.where(VendorAssessment.vendor_id == vendor_id)
    return list(session.scalars(q))
