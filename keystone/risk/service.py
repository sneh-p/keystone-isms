from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from functools import lru_cache

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.assets.models import Asset
from keystone.core.db import utcnow
from keystone.core.services import apply_fields, authorize, get_or_404, require_text, today
from keystone.core.settings import PROJECT_ROOT
from keystone.frameworks.models import CommonControl

from . import fair
from .models import ACTION_STATUSES, RISK_CATEGORIES, RISK_STATUSES, TREATMENT_OPTIONS, Risk, RiskAcceptance, TreatmentAction

LEVEL_ORDER = ["Low", "Medium", "High", "Critical"]
OPEN_STATUSES = ("identified", "assessed", "treatment", "monitoring", "accepted")


@dataclass(frozen=True)
class Matrix:
    likelihood: dict[int, str]
    impact: dict[int, str]
    levels: list[tuple[str, int]]
    appetite_max_level: str
    max_acceptance_days: int
    review_days: dict[str, int]

    def level(self, likelihood: int | None, impact: int | None) -> str | None:
        if not likelihood or not impact:
            return None
        score = likelihood * impact
        for name, minimum in self.levels:
            if score >= minimum:
                return name
        return self.levels[-1][0]

    def above_appetite(self, level: str | None) -> bool:
        return level is not None and LEVEL_ORDER.index(level) > LEVEL_ORDER.index(self.appetite_max_level)


@lru_cache(maxsize=4)
def load_matrix(path: str = str(PROJECT_ROOT / "config" / "risk_matrix.yaml")) -> Matrix:
    d = yaml.safe_load(open(path, encoding="utf-8"))
    levels = sorted(((x["level"], int(x["min"])) for x in d["levels"]), key=lambda x: -x[1])
    return Matrix(
        likelihood={int(k): v for k, v in d["likelihood"].items()},
        impact={int(k): v for k, v in d["impact"].items()},
        levels=levels,
        appetite_max_level=d["appetite_max_level"],
        max_acceptance_days=int(d["max_acceptance_days"]),
        review_days=d["review_days"],
    )


def score(likelihood: int | None, impact: int | None) -> int | None:
    return likelihood * impact if likelihood and impact else None


def inherent_level(r: Risk) -> str | None:
    return load_matrix().level(r.inherent_likelihood, r.inherent_impact)


def residual_level(r: Risk) -> str | None:
    return load_matrix().level(r.residual_likelihood, r.residual_impact)


def current_level(r: Risk) -> str | None:
    return residual_level(r) or inherent_level(r)


def active_acceptance(r: Risk, on: date | None = None) -> RiskAcceptance | None:
    on = on or today()
    for a in r.acceptances:
        if a.revoked_at is None and a.expires_on >= on:
            return a
    return None


EDITABLE = {"title", "description", "category", "threat", "vulnerability", "consequence", "owner_id", "inherent_likelihood", "inherent_impact", "residual_likelihood", "residual_impact", "treatment_option", "treatment_rationale", "review_date"}


def _validate(r: Risk) -> None:
    require_text(r.title, "Risk title")
    if r.category not in RISK_CATEGORIES:
        raise ValueError(f"category must be one of {RISK_CATEGORIES}")
    if r.treatment_option and r.treatment_option not in TREATMENT_OPTIONS:
        raise ValueError(f"treatment_option must be one of {TREATMENT_OPTIONS}")
    for f in ("inherent_likelihood", "inherent_impact", "residual_likelihood", "residual_impact"):
        v = getattr(r, f)
        if v is not None and not 1 <= int(v) <= 5:
            raise ValueError(f"{f} must be 1-5")
    if (r.residual_likelihood is None) != (r.residual_impact is None):
        raise ValueError("give both residual likelihood and impact, or neither")
    if (r.inherent_likelihood is None) != (r.inherent_impact is None):
        raise ValueError("give both inherent likelihood and impact, or neither")


def save_risk(session: Session, actor, risk_id: int | None = None, *, asset_ids: list[int] | None = None, control_ids: list[int] | None = None, **fields) -> Risk:
    authorize(session, actor, "risk.write")
    r = get_or_404(session, Risk, risk_id) if risk_id else Risk(category="operational", status="identified")
    apply_fields(r, fields, EDITABLE)
    _validate(r)
    if asset_ids is not None:
        r.assets = list(session.scalars(select(Asset).where(Asset.id.in_(asset_ids))))
    if control_ids is not None:
        r.controls = list(session.scalars(select(CommonControl).where(CommonControl.id.in_(control_ids))))
    if r.status == "identified" and r.inherent_likelihood:
        r.status = "assessed"
    level = current_level(r)
    acc = active_acceptance(r) if risk_id else None
    if acc is not None and level is not None and LEVEL_ORDER.index(level) > LEVEL_ORDER.index(acc.level_at_acceptance):
        # An acceptance covers the level that was accepted. A risk that has grown needs a new decision, so the
        # acceptance lapses (recorded as revoked by whoever raised the rating) and the risk goes back to assessed.
        acc.revoked_at, acc.revoked_by_id = utcnow(), actor.id
        r.status = "assessed"
    if r.review_date is None and level:
        r.review_date = today() + timedelta(days=load_matrix().review_days[level])
    session.add(r)
    session.flush()
    return r


def set_status(session: Session, actor, risk_id: int, status: str) -> Risk:
    """Move a risk through its lifecycle. Acceptance has its own function (accept_risk)."""
    authorize(session, actor, "risk.write")
    r = get_or_404(session, Risk, risk_id)
    if status not in RISK_STATUSES:
        raise ValueError(f"status must be one of {RISK_STATUSES}")
    if status == "accepted":
        raise ValueError("Use risk acceptance to accept a risk; it needs an approver and an expiry.")
    if status in ("treatment", "monitoring") and not r.inherent_likelihood:
        raise ValueError("Assess the inherent risk first.")
    if status == "treatment" and not r.treatment_option:
        raise ValueError("Choose a treatment option first.")
    if status == "monitoring" and r.treatment_option == "mitigate" and r.residual_likelihood is None:
        raise ValueError("Record the residual risk before moving to monitoring.")
    if status == "closed":
        open_actions = [a for a in r.actions if a.status in ("open", "in_progress")]
        if open_actions:
            raise ValueError(f"{len(open_actions)} treatment action(s) are still open.")
    r.status = status
    session.flush()
    return r


def accept_risk(session: Session, actor, risk_id: int, justification: str, expires_on: date | None = None) -> RiskAcceptance:
    """Formal acceptance. Requires risk.accept, and the approver must not be the risk owner."""
    authorize(session, actor, "risk.accept")
    r = get_or_404(session, Risk, risk_id)
    require_text(justification, "Acceptance justification")
    level = current_level(r)
    if level is None:
        raise ValueError("Assess the risk before accepting it.")
    if r.owner_id is not None and r.owner_id == actor.id:
        raise ValueError("Segregation of duties: the risk owner cannot approve acceptance of their own risk.")
    m = load_matrix()
    latest = today() + timedelta(days=m.max_acceptance_days)
    expires_on = expires_on or latest
    if expires_on <= today():
        raise ValueError("Acceptance expiry must be in the future.")
    if m.above_appetite(level) and expires_on > latest:
        raise ValueError(f"Risks above appetite can be accepted for at most {m.max_acceptance_days} days.")
    for a in r.acceptances:
        if a.revoked_at is None:
            a.revoked_at, a.revoked_by_id = utcnow(), actor.id
    acc = RiskAcceptance(risk=r, level_at_acceptance=level, justification=justification.strip(), accepted_by_id=actor.id, accepted_at=utcnow(), expires_on=expires_on)
    session.add(acc)
    r.status = "accepted"
    session.flush()
    return acc


def revoke_acceptance(session: Session, actor, acceptance_id: int) -> None:
    authorize(session, actor, "risk.accept")
    a = get_or_404(session, RiskAcceptance, acceptance_id)
    a.revoked_at, a.revoked_by_id = utcnow(), actor.id
    a.risk.status = "assessed"
    session.flush()


def mark_reviewed(session: Session, actor, risk_id: int) -> Risk:
    authorize(session, actor, "risk.write")
    r = get_or_404(session, Risk, risk_id)
    r.last_reviewed_at = utcnow()
    level = current_level(r) or "Medium"
    r.review_date = today() + timedelta(days=load_matrix().review_days[level])
    session.flush()
    return r


def save_action(session: Session, actor, risk_id: int, action_id: int | None = None, **fields) -> TreatmentAction:
    authorize(session, actor, "risk.write")
    get_or_404(session, Risk, risk_id)
    a = get_or_404(session, TreatmentAction, action_id) if action_id else TreatmentAction(risk_id=risk_id, status="open")
    apply_fields(a, fields, {"title", "description", "common_control_id", "owner_id", "due_date", "status"})
    require_text(a.title, "Action title")
    if a.status not in ACTION_STATUSES:
        raise ValueError(f"status must be one of {ACTION_STATUSES}")
    a.completed_at = utcnow() if a.status == "done" and a.completed_at is None else (a.completed_at if a.status == "done" else None)
    session.add(a)
    session.flush()
    return a


def run_fair(session: Session, actor, risk_id: int, inputs: dict, iterations: int = 10_000, seed: int | None = None) -> fair.FairResult:
    authorize(session, actor, "risk.write")
    r = get_or_404(session, Risk, risk_id)
    parsed = fair.FairInputs.from_dict(inputs)
    result = fair.simulate(parsed, iterations=iterations, seed=seed)
    r.fair_inputs = parsed.to_dict()
    r.fair_result = result.to_dict()
    r.fair_run_at = utcnow()
    session.flush()
    return result


def list_risks(session: Session, include_closed: bool = False) -> list[Risk]:
    q = select(Risk).order_by(Risk.id)
    if not include_closed:
        q = q.where(Risk.status != "closed")
    return list(session.scalars(q))


def heat_map(risks: list[Risk], kind: str = "inherent") -> list[list[int]]:
    """5x5 grid of counts: grid[impact-1][likelihood-1]."""
    grid = [[0] * 5 for _ in range(5)]
    for r in risks:
        if kind == "inherent":
            lk, im = r.inherent_likelihood, r.inherent_impact
        elif kind == "residual":
            lk, im = r.residual_likelihood, r.residual_impact
        else:  # current: residual where assessed, else inherent
            lk, im = (r.residual_likelihood, r.residual_impact) if r.residual_likelihood else (r.inherent_likelihood, r.inherent_impact)
        if lk and im:
            grid[im - 1][lk - 1] += 1
    return grid


def needs_attention(risks: list[Risk], on: date | None = None) -> dict[str, list[Risk]]:
    on = on or today()
    m = load_matrix()
    out: dict[str, list] = {"review_overdue": [], "above_appetite_untreated": [], "acceptance_expired": [], "actions_overdue": []}
    for r in risks:
        if r.status == "closed":
            continue
        if r.review_date and r.review_date < on:
            out["review_overdue"].append(r)
        if m.above_appetite(current_level(r)) and r.status in ("identified", "assessed") and not active_acceptance(r, on):
            out["above_appetite_untreated"].append(r)
        if r.status == "accepted" and not active_acceptance(r, on):
            out["acceptance_expired"].append(r)
        if any(a.status in ("open", "in_progress") and a.due_date and a.due_date < on for a in r.actions):
            out["actions_overdue"].append(r)
    return out


# ---- risk library (content/risk_library.yaml) ----------------------------------------------------------

def library() -> list[dict]:
    """Keystone-written risk scenarios with suggested ratings and treating controls."""
    import yaml

    with open(PROJECT_ROOT / "content" / "risk_library.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)["scenarios"]


def add_from_library(session: Session, actor, key: str, owner_id: int | None = None) -> Risk:
    """Create a risk from a library scenario; it then follows the normal assessment and treatment workflow."""
    authorize(session, actor, "risk.write")
    sc = next((s for s in library() if s["key"] == key), None)
    if sc is None:
        raise LookupError("Unknown library scenario")
    controls = list(session.scalars(select(CommonControl).where(CommonControl.code.in_(sc.get("controls", [])))))
    return save_risk(session, actor, title=sc["title"], category=sc["category"], threat=sc["threat"], vulnerability=sc["vulnerability"],
                     consequence=sc["consequence"], inherent_likelihood=sc["likelihood"], inherent_impact=sc["impact"], owner_id=owner_id,
                     control_ids=[c.id for c in controls])


def treatment_plan(session: Session, actor) -> tuple[list[str], list[list]]:
    """The risk treatment plan (ISO 27001 6.1.3 e, 8.3): every open risk with its owner, levels, chosen option, controls,
    treatment actions and any acceptance. One row per action, so the plan reads as a work list."""
    from keystone.core.auth import User

    authorize(session, actor, "read")
    names: dict[int | None, str] = {u.id: u.display_name for u in session.scalars(select(User))}
    headers = ["Risk", "Title", "Owner", "Inherent level", "Treatment", "Rationale", "Controls", "Action", "Action owner", "Due", "Action status",
               "Residual level", "Accepted until", "Next review"]
    rows: list[list] = []
    for r in list_risks(session):
        acc = active_acceptance(r)
        base = [r.ref, r.title, names.get(r.owner_id, ""), inherent_level(r) or "", (r.treatment_option or "").replace("_", " "), r.treatment_rationale or "",
                ", ".join(c.code for c in r.controls)]
        tail = [residual_level(r) or "", acc.expires_on if acc else None, r.review_date]
        actions = [a for a in r.actions if a.status != "cancelled"]
        if not actions:
            rows.append(base + ["", "", None, ""] + tail)
        for a in actions:
            rows.append(base + [a.title, names.get(a.owner_id, ""), a.due_date, a.status.replace("_", " ")] + tail)
    return headers, rows
