from datetime import date

from fastapi import APIRouter, Depends
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.core.services import get_or_404
from keystone.tprm import service as tprm
from keystone.tprm.exposure.inventory import vendor_presence
from keystone.tprm.models import Vendor, VendorAssessment, VendorQuestionnaire

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(tags=["third parties"])
VENDOR = ("id", "name", "legal_name", "website", "description", "services", "category", "owner_id", "status", "data_sensitivity", "operational_criticality", "access_level", "processes_personal_data", "computed_tier", "tier_override", "tier_override_reason", "contract_start", "contract_end", "dpa_signed", "next_review_date", "notes", "offboarding")


def vendor_out(db, v: Vendor, detail=False) -> dict:
    cfg = tprm.load_config()
    a = tprm.latest_approved_assessment(db, v.id)
    d = ser(v, VENDOR, tier=v.tier, tier_label=cfg.tier_label(v.tier), last_assessment_at=a.approved_at if a else None, asset_ids=[x.id for x in v.assets], risk_ids=[x.id for x in v.risks])
    d["entra_presence"] = vendor_presence(db, v.id)
    return d


@router.get("/vendors")
def vendors(include_terminated: bool = False, user=Depends(perm("read")), db: Session = Depends(get_db)):
    vs = tprm.list_vendors(db, include_terminated)
    att = tprm.vendor_attention(db)
    return {"vendors": [vendor_out(db, v) for v in vs], "attention": {k: [x.id for x in v] for k, v in att.items()}, "tiers": tprm.load_config().tiers}


@router.get("/vendors/{vid}")
def vendor(vid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    v = get_or_404(db, Vendor, vid)
    d = vendor_out(db, v)
    d["questionnaires"] = [q_out(q) for q in tprm.questionnaires_for(db, vid)]
    d["assessments"] = [a_out(a) for a in tprm.assessments_for(db, vid)]
    return d


class VendorIn(In):
    name: str | None = None
    legal_name: str | None = None
    website: str | None = None
    description: str | None = None
    services: str | None = None
    category: str | None = None
    owner_id: int | None = None
    status: str | None = None
    data_sensitivity: str | None = None
    operational_criticality: str | None = None
    access_level: str | None = None
    processes_personal_data: bool | None = None
    tier_override: int | None = None
    tier_override_reason: str | None = None
    contract_start: date | None = None
    contract_end: date | None = None
    dpa_signed: bool | None = None
    next_review_date: date | None = None
    notes: str | None = None
    asset_ids: list[int] | None = None
    risk_ids: list[int] | None = None


@router.post("/vendors")
def create_vendor(body: VendorIn, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    return vendor_out(db, tprm.save_vendor(db, user, **body.model_dump(exclude_unset=True)))


@router.patch("/vendors/{vid}")
def update_vendor(vid: int, body: VendorIn, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    return vendor_out(db, tprm.save_vendor(db, user, vid, **body.model_dump(exclude_unset=True)))


@router.post("/vendors/{vid}/review")
def review_vendor(vid: int, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    return vendor_out(db, tprm.mark_vendor_reviewed(db, user, vid))


# ---- questionnaires -----------------------------------------------------------------------

def q_out(q: VendorQuestionnaire, detail=False) -> dict:
    d = ser(q, ("id", "vendor_id", "template_id", "status", "score", "due_date", "sent_at", "received_at", "reviewed_by_id", "reviewed_at", "review_notes"), template_name=f"{q.template.name} v{q.template.version}")
    if detail:
        score, findings = tprm.score_responses(q.template.questions, q.responses or {})
        d.update(questions=q.template.questions, responses=q.responses or {}, findings=findings)
    return d


@router.get("/questionnaire-templates")
def templates(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [ser(t, ("id", "name", "version", "description"), question_count=len(t.questions)) for t in tprm.templates(db)]


@router.get("/questionnaire-templates/{tid}")
def template(tid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    from keystone.tprm.models import QuestionnaireTemplate

    t = get_or_404(db, QuestionnaireTemplate, tid)
    return ser(t, ("id", "name", "version", "description", "questions", "active"), in_use=tprm.template_in_use(db, t.id), question_types=list(tprm.QUESTION_TYPES))


class TemplateIn(In):
    name: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=20)
    description: str | None = Field(None, max_length=4000)
    questions: list[dict] = Field(max_length=200)


@router.post("/questionnaire-templates")
def create_template(body: TemplateIn, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    t = tprm.save_template(db, user, name=body.name, version=body.version, description=body.description, questions=tprm.clean_questions(body.questions))
    return {"id": t.id}


class TemplatePatch(In):
    name: str | None = Field(None, min_length=1, max_length=200)
    version: str | None = Field(None, min_length=1, max_length=20)
    description: str | None = Field(None, max_length=4000)
    questions: list[dict] | None = Field(None, max_length=200)
    active: bool | None = None


@router.patch("/questionnaire-templates/{tid}")
def update_template(tid: int, body: TemplatePatch, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    t = tprm.update_template(db, user, tid, **body.model_dump(exclude_unset=True))
    return {"id": t.id}


class TemplateVersionIn(In):
    version: str = Field(min_length=1, max_length=20)
    questions: list[dict] | None = Field(None, max_length=200)


@router.post("/questionnaire-templates/{tid}/versions")
def new_template_version(tid: int, body: TemplateVersionIn, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    return {"id": tprm.new_template_version(db, user, tid, body.version, body.questions).id}


class OffboardingTickIn(In):
    item: str = Field(max_length=40)
    done: bool


@router.post("/vendors/{vid}/offboarding")
def vendor_offboarding(vid: int, body: OffboardingTickIn, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    return vendor_out(db, tprm.tick_vendor_offboarding(db, user, vid, body.item, body.done), True)


@router.get("/vendor-offboarding-items")
def vendor_offboarding_items(user=Depends(perm("read"))):
    return tprm.OFFBOARDING_ITEMS


@router.post("/questionnaire-templates/load-defaults")
def load_templates(user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    return [t.id for t in tprm.load_default_templates(db, user)]


@router.get("/questionnaires")
def questionnaires(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [q_out(q) for q in tprm.questionnaires_for(db)]


@router.get("/questionnaires/{qid}")
def questionnaire(qid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    return q_out(get_or_404(db, VendorQuestionnaire, qid), True)


class SendIn(In):
    vendor_id: int
    template_id: int
    due_date: date | None = None


@router.post("/questionnaires")
def send(body: SendIn, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    return q_out(tprm.send_questionnaire(db, user, body.vendor_id, body.template_id, body.due_date))


class ResponsesIn(In):
    responses: dict
    complete: bool = False


@router.post("/questionnaires/{qid}/responses")
def responses(qid: int, body: ResponsesIn, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    return q_out(tprm.record_responses(db, user, qid, body.responses, body.complete), True)


class NotesIn(In):
    notes: str


@router.post("/questionnaires/{qid}/review")
def review_q(qid: int, body: NotesIn, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    return q_out(tprm.review_questionnaire(db, user, qid, body.notes), True)


# ---- assessments ------------------------------------------------------------------------------

A = ("id", "vendor_id", "entra_tenant_id", "questionnaire_id", "title", "status", "scenario", "integration_depth", "tef", "tcap", "control_strength", "plm", "slef", "slm", "result", "run_at", "conclusion", "approved_by_id", "approved_at", "created_by_id")


def a_out(a: VendorAssessment) -> dict:
    return ser(a, A, vendor_name=a.vendor.name)


@router.get("/assessments")
def assessments(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return [a_out(a) for a in tprm.assessments_for(db)]


@router.get("/assessments/{aid}")
def assessment(aid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    from keystone.tprm.exposure import fair_mapping

    a = get_or_404(db, VendorAssessment, aid)
    d = a_out(a)
    d["suggestions"] = [ser(s, ("id", "field", "current_value", "suggested_value", "rule_ids", "reasons", "status", "decided_by", "decided_at")) for s in fair_mapping.suggestions_for(db, aid)]
    ex = fair_mapping.summarize(db, a.vendor_id, a.entra_tenant_id) if a.entra_tenant_id else None
    d["exposure"] = None if ex is None else {"apps": ex.app_names, "worst_level": ex.worst_level, "integration_depth": ex.integration_depth}
    return d


class AssessIn(In):
    vendor_id: int | None = None
    title: str | None = None
    scenario: str | None = None
    integration_depth: str | None = None
    entra_tenant_id: int | None = None
    questionnaire_id: int | None = None
    conclusion: str | None = None
    tef: dict | list | None = None
    tcap: dict | list | None = None
    control_strength: dict | list | None = None
    plm: dict | list | None = None
    slef: dict | list | None = None
    slm: dict | list | None = None


@router.post("/assessments")
def create_assessment(body: AssessIn, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    fields = body.model_dump(exclude_unset=True)
    vid = fields.pop("vendor_id", None)
    if not vid:
        raise ValueError("vendor_id is required")
    return a_out(tprm.save_assessment(db, user, vid, **fields))


@router.patch("/assessments/{aid}")
def update_assessment(aid: int, body: AssessIn, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    a = get_or_404(db, VendorAssessment, aid)
    fields = body.model_dump(exclude_unset=True)
    fields.pop("vendor_id", None)
    return a_out(tprm.save_assessment(db, user, a.vendor_id, aid, **fields))


@router.post("/assessments/{aid}/run")
def run(aid: int, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    tprm.run_assessment(db, user, aid)
    return a_out(get_or_404(db, VendorAssessment, aid))


@router.post("/assessments/{aid}/submit")
def submit(aid: int, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    return a_out(tprm.submit_assessment(db, user, aid))


class ConclusionIn(In):
    conclusion: str


@router.post("/assessments/{aid}/approve")
def approve(aid: int, body: ConclusionIn, user=Depends(perm("vendor.approve")), db: Session = Depends(get_db)):
    return a_out(tprm.approve_assessment(db, user, aid, body.conclusion))


@router.post("/assessments/{aid}/return")
def return_(aid: int, user=Depends(perm("vendor.approve")), db: Session = Depends(get_db)):
    return a_out(tprm.return_assessment(db, user, aid))


# ---- deleting records created in error (keystone/core/deletion.py: refused while anything depends on them)


@router.delete("/vendors/{vid}")
def delete_vendor(vid: int, user=Depends(perm("vendor.write")), db: Session = Depends(get_db)):
    from keystone.core.deletion import delete_record

    delete_record(db, user, "vendor", vid)
    return {"ok": True}
