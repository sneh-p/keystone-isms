"""Maturity tracking: score each NIST CSF 2.0 category from 0 (not done) to 4 (adaptive), now and as a target, once
or twice a year, and watch the trend. Categories come from Keystone's NIST CSF content, so this works whether or not
the framework is turned on."""

from __future__ import annotations

from datetime import date
from functools import lru_cache

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.services import authorize, get_or_404, require_text, today
from keystone.core.settings import PROJECT_ROOT

from .models import MaturityAssessment

TIERS = {0: "Not done", 1: "Partial (tier 1)", 2: "Risk-informed (tier 2)", 3: "Repeatable (tier 3)", 4: "Adaptive (tier 4)"}


@lru_cache(maxsize=1)
def categories() -> tuple[dict, ...]:
    """NIST CSF 2.0 functions with their categories: ({"ref": "GV", "title": ..., "categories": [{"ref": "GV.OC", "title": ...}]}, ...)."""
    data = yaml.safe_load((PROJECT_ROOT / "content" / "frameworks" / "nist_csf_2_0.yaml").read_text(encoding="utf-8"))
    reqs = data["requirements"]
    functions = [{"ref": r["ref"], "title": r["title"], "categories": []} for r in reqs if r.get("kind") == "function"]
    by_ref = {f["ref"]: f for f in functions}
    for r in reqs:
        if r.get("kind") == "category":
            by_ref[r["ref"].split(".")[0]]["categories"].append({"ref": r["ref"], "title": r["title"]})
    return tuple(functions)


def _refs() -> set[str]:
    return {c["ref"] for f in categories() for c in f["categories"]}


def clean_scores(scores: dict) -> dict:
    if not isinstance(scores, dict):
        raise ValueError("Scores expected.")
    known = _refs()
    out = {}
    for ref, v in scores.items():
        if ref not in known or not isinstance(v, dict) or set(v) - {"current", "target", "note"}:
            raise ValueError(f"Unknown category or field: {ref}")
        cur, tgt = v.get("current"), v.get("target")
        for x in (cur, tgt):
            if x is not None and (not isinstance(x, int) or isinstance(x, bool) or not 0 <= x <= 4):
                raise ValueError(f"{ref}: tiers go from 0 to 4.")
        note = (v.get("note") or "").strip()
        if len(note) > 1000:
            raise ValueError(f"{ref}: the note can be up to 1,000 characters.")
        out[ref] = {"current": cur, "target": tgt, "note": note or None}
    return out


def assessments(session: Session, actor) -> list[MaturityAssessment]:
    authorize(session, actor, "read")
    return list(session.scalars(select(MaturityAssessment).order_by(MaturityAssessment.assessed_on.desc(), MaturityAssessment.id.desc())))


def save(session: Session, actor, assessment_id: int | None = None, *, title: str | None = None, assessed_on: date | None = None, scores: dict | None = None,
         summary: str | None = None) -> MaturityAssessment:
    authorize(session, actor, "org.write")
    a = get_or_404(session, MaturityAssessment, assessment_id) if assessment_id else MaturityAssessment(status="draft", scores={}, assessed_on=today())
    if a.status == "final":
        raise ValueError("A final assessment can't change. Copy it into a new one.")
    if title is not None or a.id is None:
        a.title = require_text(title, "Title")[:200]
    if assessed_on is not None:
        if assessed_on > today():
            raise ValueError("The assessment date can't be in the future.")
        a.assessed_on = assessed_on
    if scores is not None:
        a.scores = {**(a.scores or {}), **clean_scores(scores)}
    if summary is not None:
        a.summary = summary.strip()[:4000] or None
    session.add(a)
    session.flush()
    return a


def finalise(session: Session, actor, assessment_id: int) -> MaturityAssessment:
    authorize(session, actor, "org.write")
    a = get_or_404(session, MaturityAssessment, assessment_id)
    missing = [r for r in _refs() if (a.scores or {}).get(r, {}).get("current") is None]
    if missing:
        raise ValueError(f"Score every category first ({len(missing)} left).")
    a.status = "final"
    session.flush()
    return a


def copy(session: Session, actor, assessment_id: int, title: str) -> MaturityAssessment:
    """Start the next assessment from an earlier one (scores and targets carried over)."""
    authorize(session, actor, "org.write")
    src = get_or_404(session, MaturityAssessment, assessment_id)
    a = MaturityAssessment(title=require_text(title, "Title")[:200], assessed_on=today(), scores=dict(src.scores or {}), status="draft")
    session.add(a)
    session.flush()
    return a


def delete(session: Session, actor, assessment_id: int) -> None:
    authorize(session, actor, "org.write")
    a = get_or_404(session, MaturityAssessment, assessment_id)
    if a.status == "final":
        raise ValueError("Final assessments are kept as a record.")
    session.delete(a)
    session.flush()


def by_function(a: MaturityAssessment) -> list[dict]:
    """Average current and target tier per function (categories without a score left out)."""
    out = []
    for f in categories():
        cur = [a.scores[c["ref"]]["current"] for c in f["categories"] if (a.scores or {}).get(c["ref"], {}).get("current") is not None]
        tgt = [a.scores[c["ref"]]["target"] for c in f["categories"] if (a.scores or {}).get(c["ref"], {}).get("target") is not None]
        out.append({"ref": f["ref"], "title": f["title"], "current": round(sum(cur) / len(cur), 1) if cur else None, "target": round(sum(tgt) / len(tgt), 1) if tgt else None})
    return out
