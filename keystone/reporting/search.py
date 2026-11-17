"""Record search for the command palette: references and titles across the main registers.

Staff with `read` only (employees use the portal and never reach this). The query is a bound LIKE parameter with its
wildcards escaped, so it matches literally; results are capped per register.
"""

from __future__ import annotations

import re

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from keystone.core.services import authorize

MIN_QUERY, MAX_QUERY, PER_KIND, LIMIT = 2, 100, 5, 30
REF_RE = re.compile(r"^([A-Za-z]{2,4})-0*(\d{1,9})$")


def _registers():
    from keystone.assets.models import Asset
    from keystone.audits.models import Audit
    from keystone.configcheck.models import ConfigTarget
    from keystone.continuity.models import BusinessProcess
    from keystone.frameworks.models import CommonControl
    from keystone.improvement.models import Nonconformity
    from keystone.incidents.models import Incident
    from keystone.policies.models import PolicyDocument
    from keystone.privacy.models import ProcessingActivity
    from keystone.risk.models import Risk
    from keystone.tasks.models import Task
    from keystone.tprm.models import Vendor

    # (kind, label, model, searchable columns, title column, page)
    return [
        ("risk", "Risk", Risk, (Risk.title,), "title", "/risks?open={id}"),
        ("control", "Control", CommonControl, (CommonControl.code, CommonControl.title), "title", "/controls?open={id}"),
        ("policy", "Policy", PolicyDocument, (PolicyDocument.code, PolicyDocument.title), "title", "/policies?open={id}"),
        ("task", "Task", Task, (Task.title,), "title", "/tasks?open={id}"),
        ("incident", "Incident", Incident, (Incident.title,), "title", "/incidents?open={id}"),
        ("vendor", "Vendor", Vendor, (Vendor.name, Vendor.legal_name), "name", "/vendors?open={id}"),
        ("asset", "Asset", Asset, (Asset.name,), "name", "/assets?open={id}"),
        ("nonconformity", "Nonconformity", Nonconformity, (Nonconformity.title,), "title", "/nonconformities?open={id}"),
        ("audit", "Audit", Audit, (Audit.title,), "title", "/audits?open={id}"),
        ("activity", "Processing activity", ProcessingActivity, (ProcessingActivity.name,), "name", "/privacy"),
        ("process", "Business process", BusinessProcess, (BusinessProcess.name,), "name", "/continuity"),
        ("config_target", "Host or firewall", ConfigTarget, (ConfigTarget.name, ConfigTarget.hostname), "name", "/configuration?target={id}"),
    ]


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def search(session: Session, actor, q: str) -> list[dict]:
    authorize(session, actor, "read")
    q = (q or "").strip()[:MAX_QUERY]
    if len(q) < MIN_QUERY:
        return []
    pattern = _like(q)
    ref = REF_RE.match(q)
    out: list[dict] = []
    for kind, label, model, cols, title_attr, page in _registers():
        hits = list(session.scalars(select(model).where(or_(*(c.ilike(pattern, escape="\\") for c in cols))).limit(PER_KIND)))
        if ref is not None:
            byid = session.get(model, int(ref.group(2)))
            if byid is not None and getattr(byid, "ref", "").upper().startswith(ref.group(1).upper()) and byid not in hits:
                hits.insert(0, byid)
        for rec in hits:
            title = getattr(rec, title_attr, None) or ""
            code = getattr(rec, "code", None)
            out.append({"kind": kind, "label": label, "ref": code or getattr(rec, "ref", f"#{rec.id}"), "title": str(title)[:200],
                        "page": page.format(id=rec.id)})
    exact = [r for r in out if q.lower() in (r["ref"].lower(), r["title"].lower())]
    rest = [r for r in out if r not in exact]
    return (exact + rest)[:LIMIT]
