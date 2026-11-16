"""Setup wizard: turn a short company profile into a tailored starting ISMS.

Idempotent: existing frameworks, policies (by code) and open tasks (by template) are kept.
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.auth import User
from keystone.core.db import utcnow
from keystone.core.services import authorize, get_or_404, require_text
from keystone.core.settings import PROJECT_ROOT
from keystone.frameworks import loader
from keystone.frameworks.models import CommonControl, Framework
from keystone.org import service as org
from keystone.policies.models import PolicyDocument, PolicyVersion
from keystone.tasks import service as tasks

from .models import OnboardingProfile

TEMPLATE_DIR = PROJECT_ROOT / "content" / "policy_templates"
HOSTING = {"cloud_aws": "Amazon Web Services", "cloud_azure": "Microsoft Azure", "cloud_gcp": "Google Cloud", "m365": "Microsoft 365", "google_workspace": "Google Workspace", "on_prem": "on-premises servers"}
PERSONAL = {"customer_personal", "employee", "health", "payment_cards"}
SOFTWARE_CONTROLS = ["KC-TEC-04", "KC-TEC-25", "KC-TEC-26", "KC-TEC-27", "KC-TEC-28", "KC-TEC-29", "KC-TEC-30", "KC-TEC-31", "KC-TEC-33"]
PREMISES_CONTROLS = ["KC-PHY-01", "KC-PHY-02", "KC-PHY-03", "KC-PHY-04", "KC-PHY-06", "KC-PHY-08", "KC-PHY-11", "KC-PHY-12"]
SIZES = ("1-10", "11-50", "51-200", "201-1000", "1000+")


def parse_template(path: Path) -> tuple[dict, str]:
    text = path.read_text(encoding="utf-8")
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    if not m:
        raise ValueError(f"{path.name}: missing front matter")
    return yaml.safe_load(m.group(1)), m.group(2).strip() + "\n"


def policy_templates() -> list[tuple[dict, str]]:
    return [parse_template(p) for p in sorted(TEMPLATE_DIR.glob("POL-*.md"))]


def render(body: str, values: dict) -> str:
    return re.sub(r"\{\{\s*(\w+)\s*\}\}", lambda m: str(values.get(m.group(1), m.group(0))), body)


def tags_for(p: dict) -> set[str]:
    tags = set(p.get("hosting") or [])
    if p.get("develops_software"):
        tags.add("develops_software")
    if p.get("offices"):
        tags.add("offices")
    if PERSONAL & set(p.get("data_types") or []):
        tags.add("personal_data")
    return tags


def scope_statement(p: dict) -> str:
    hosting = [HOSTING[h] for h in p.get("hosting") or [] if h in HOSTING]
    where = p.get("locations") or "all locations where staff work"
    systems = (", ".join(hosting[:-1]) + " and " + hosting[-1]) if len(hosting) > 1 else (hosting[0] if hosting else "its IT systems")
    return f"The information security management system of {p['company_name']} covers the people, processes and information systems used to deliver its products and services, including {systems}, at {where}."


def validate(p: dict) -> None:
    require_text(p.get("company_name"), "Company name")
    if p.get("size") and p["size"] not in SIZES:
        raise ValueError(f"size must be one of {SIZES}")
    unknown = set(p.get("hosting") or []) - set(HOSTING)
    if unknown:
        raise ValueError(f"unknown hosting options: {sorted(unknown)}")
    if not p.get("frameworks"):
        raise ValueError("Choose at least one framework.")


def complete(session: Session, actor, profile: dict) -> dict:
    """Apply the wizard. Returns counts of what was created."""
    authorize(session, actor, "org.write")
    for perm in ("framework.write", "policy.write", "task.write", "control.write"):
        authorize(session, actor, perm)
    validate(profile)
    owner = get_or_404(session, User, profile["isms_owner_id"]) if profile.get("isms_owner_id") else actor
    out = {"frameworks_loaded": False, "policies_created": 0, "tasks_created": 0, "controls_marked_na": 0}

    if session.scalar(select(Framework).limit(1)) is None:
        loader.seed_content(session, actor)
        out["frameworks_loaded"] = True
    for fw in session.scalars(select(Framework)):
        fw.enabled = fw.code in profile["frameworks"]

    existing = org.get_org(session)
    fields = {"name": profile["company_name"], "legal_name": profile.get("legal_name") or None, "industry": profile.get("industry") or None,
              "description": profile.get("description") or (existing.description if existing else None)}
    if not existing or not (existing.scope_statement or "").strip():
        fields["scope_statement"] = scope_statement(profile)
        fields["scope_inclusions"] = ", ".join(HOSTING[h] for h in profile.get("hosting") or [] if h in HOSTING) or None
    org.save_org(session, actor, **fields)
    o = org.get_org(session)

    tags = tags_for(profile)
    values = {"company": profile["company_name"], "isms_owner": owner.display_name, "scope": o.scope_statement if o else None, "review_months": profile.get("review_months", 12), "year": date.today().year}
    codes = {c.code: c for c in session.scalars(select(CommonControl))}
    have = {d.code for d in session.scalars(select(PolicyDocument))}
    for meta, body in policy_templates():
        if meta["code"] in have or (meta.get("when") and meta["when"] not in tags):
            continue
        doc = PolicyDocument(code=meta["code"], title=meta["title"], doc_type=meta.get("type", "policy"), owner_id=owner.id, status="draft", review_interval_months=int(profile.get("review_months", 12)), requires_acknowledgement=bool(meta.get("acknowledge")))
        doc.controls = [codes[c] for c in meta.get("controls", []) if c in codes]
        session.add(doc)
        session.flush()
        session.add(PolicyVersion(document=doc, version_label="1.0", body=render(body, values), change_summary="Generated from the Keystone template during onboarding; review and adapt before approval.", status="draft", author_id=actor.id))
        out["policies_created"] += 1

    out["tasks_created"] = len(tasks.generate_from_templates(session, actor, tags, owner.id))

    def mark_na(code_list: list[str], why: str) -> None:
        for code in code_list:
            c = codes.get(code)
            if c and c.status == "not_started":
                c.status, c.na_justification = "not_applicable", why
                out["controls_marked_na"] += 1

    if not profile.get("develops_software"):
        mark_na(SOFTWARE_CONTROLS, f"{profile['company_name']} does not develop software (onboarding answer); revisit if this changes.")
    if not profile.get("offices"):
        mark_na(PREMISES_CONTROLS, f"{profile['company_name']} operates no company-controlled premises (onboarding answer); home working is covered by remote-working controls.")

    rec = session.scalar(select(OnboardingProfile)) or OnboardingProfile(profile={})
    rec.profile, rec.completed_at, rec.completed_by_id = profile, utcnow(), actor.id
    session.add(rec)
    session.flush()
    return out


def state(session: Session) -> dict:
    rec = session.scalar(select(OnboardingProfile))
    return {"completed": bool(rec and rec.completed_at), "profile": rec.profile if rec else None, "completed_at": rec.completed_at if rec else None, "org_exists": org.get_org(session) is not None}
