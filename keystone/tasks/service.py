"""Compliance tasks: assign, do, submit with evidence, review (SoD), recur."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from functools import lru_cache

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.controls.models import Evidence
from keystone.core.attachments import Attachment, attachments_for, save_attachment
from keystone.core.db import utcnow
from keystone.core.services import apply_fields, authorize, bulk_targets, get_or_404, require_active_user, require_text, today
from keystone.core.settings import PROJECT_ROOT
from keystone.frameworks.models import CommonControl

from .models import FREQUENCIES, TASK_STATUSES, Task

OPEN = ("todo", "in_progress", "in_review")


@lru_cache(maxsize=1)
def templates() -> list[dict]:
    return yaml.safe_load((PROJECT_ROOT / "content" / "task_templates.yaml").read_text(encoding="utf-8"))["tasks"]


def interval(frequency: str) -> int | None:
    if frequency not in FREQUENCIES:
        raise ValueError(f"frequency must be one of {list(FREQUENCIES)}")
    return FREQUENCIES[frequency]


FIELDS = {"title", "description", "frequency", "assignee_id", "due_date", "evidence_hint"}


def save_task(session: Session, actor, task_id: int | None = None, *, control_ids: list[int] | None = None, **fields) -> Task:
    authorize(session, actor, "task.write")
    t = get_or_404(session, Task, task_id) if task_id else Task(status="todo", frequency="once")
    if t.status in ("done", "not_relevant"):
        raise ValueError("Completed tasks are records and cannot be edited.")
    apply_fields(t, fields, FIELDS)
    require_text(t.title, "Task title")
    interval(t.frequency)
    if control_ids is not None:
        t.controls = list(session.scalars(select(CommonControl).where(CommonControl.id.in_(control_ids))))
    session.add(t)
    session.flush()
    return t


def bulk_update_tasks(session: Session, actor, ids: list[int], **fields) -> list[Task]:
    """Reassign and/or reschedule many open tasks at once; all-or-nothing, each change audited per task."""
    authorize(session, actor, "task.write")
    if not fields or set(fields) - {"assignee_id", "due_date"}:
        raise ValueError("Bulk changes can set the assignee and the due date only.")
    if "assignee_id" in fields:
        require_active_user(session, fields["assignee_id"])
    targets = bulk_targets(session, Task, ids)
    if any(t.status in ("done", "not_relevant") for t in targets):
        raise ValueError("Completed tasks are records and cannot be edited; deselect them.")
    for t in targets:
        save_task(session, actor, t.id, **fields)
    return targets


def start(session: Session, actor, task_id: int) -> Task:
    authorize(session, actor, "task.write")
    t = get_or_404(session, Task, task_id)
    if t.status not in ("todo", "in_progress"):
        raise ValueError("Only to-do tasks can be started.")
    t.status = "in_progress"
    session.flush()
    return t


def add_attachment(session: Session, actor, task_id: int, filename: str, data: bytes) -> Attachment:
    authorize(session, actor, "task.write")
    t = get_or_404(session, Task, task_id)
    if t.status not in OPEN:
        raise ValueError("Attach evidence before the task is approved.")
    return save_attachment(session, actor, filename, data, "Task", t.id)


def submit(session: Session, actor, task_id: int, notes: str | None) -> Task:
    authorize(session, actor, "task.write")
    t = get_or_404(session, Task, task_id)
    if t.status not in ("todo", "in_progress"):
        raise ValueError("Only open tasks can be submitted for review.")
    if not (notes or "").strip() and not attachments_for(session, "Task", t.id):
        raise ValueError("Add a note or attach evidence before submitting.")
    t.completion_notes = (notes or "").strip() or t.completion_notes
    t.status, t.submitted_by_id, t.submitted_at, t.review_comment = "in_review", actor.id, utcnow(), None
    session.flush()
    return t


def approve(session: Session, actor, task_id: int, comment: str | None = None) -> Task:
    """Reviewer approves: evidence is filed on every linked control and the next occurrence is scheduled."""
    authorize(session, actor, "task.approve")
    t = get_or_404(session, Task, task_id)
    if t.status != "in_review":
        raise ValueError("Only tasks in review can be approved.")
    if actor.id in (t.submitted_by_id, t.assignee_id):
        raise ValueError("Segregation of duties: someone other than the assignee or submitter must approve.")
    t.status, t.approved_by_id, t.approved_at, t.review_comment = "done", actor.id, utcnow(), comment
    days = interval(t.frequency)
    valid_until = today() + timedelta(days=days + 14) if days else None
    files = attachments_for(session, "Task", t.id)
    for c in t.controls:
        if files:
            for a in files:
                session.add(Evidence(common_control_id=c.id, title=f"{t.title} ({a.filename})", kind="file", attachment_id=a.id, description=t.completion_notes, collected_on=today(), valid_until=valid_until, reviewed_by_id=actor.id, reviewed_at=utcnow()))
        else:
            session.add(Evidence(common_control_id=c.id, title=t.title, kind="note", description=t.completion_notes, collected_on=today(), valid_until=valid_until, reviewed_by_id=actor.id, reviewed_at=utcnow()))
    if days:
        nxt = Task(title=t.title, description=t.description, template_key=t.template_key, evidence_hint=t.evidence_hint, frequency=t.frequency, assignee_id=t.assignee_id, due_date=today() + timedelta(days=days), status="todo", previous_task_id=t.id)
        nxt.controls = list(t.controls)
        session.add(nxt)
    session.flush()
    return t


def send_back(session: Session, actor, task_id: int, comment: str) -> Task:
    authorize(session, actor, "task.approve")
    t = get_or_404(session, Task, task_id)
    if t.status != "in_review":
        raise ValueError("Only tasks in review can be returned.")
    t.status, t.review_comment = "in_progress", require_text(comment, "Reason for returning")
    session.flush()
    return t


def mark_not_relevant(session: Session, actor, task_id: int, reason: str) -> Task:
    authorize(session, actor, "task.approve")
    t = get_or_404(session, Task, task_id)
    if t.status not in OPEN:
        raise ValueError("Only open tasks can be marked not relevant.")
    t.status, t.not_relevant_reason = "not_relevant", require_text(reason, "Reason")
    session.flush()
    return t


def list_tasks(session: Session, *, assignee_id: int | None = None, include_closed: bool = True, closed_limit: int | None = None) -> list[Task]:
    """Open tasks always; closed ones too unless excluded. `closed_limit` keeps only the most recent closed tasks."""
    base = select(Task)
    if assignee_id:
        base = base.where(Task.assignee_id == assignee_id)
    order = (Task.due_date.is_(None), Task.due_date, Task.id)
    if not include_closed:
        return list(session.scalars(base.where(Task.status.in_(OPEN)).order_by(*order)))
    if closed_limit is None:
        return list(session.scalars(base.order_by(*order)))
    open_tasks = list(session.scalars(base.where(Task.status.in_(OPEN))))
    closed = list(session.scalars(base.where(Task.status.not_in(OPEN)).order_by(Task.updated_at.desc(), Task.id.desc()).limit(closed_limit)))
    return sorted(open_tasks + closed, key=lambda t: (t.due_date is None, t.due_date or today(), t.id))


def overdue(t: Task, on: date | None = None) -> bool:
    return t.status in OPEN and t.due_date is not None and t.due_date < (on or today())


def generate_from_templates(session: Session, actor, tags: set[str], assignee_id: int | None = None, spread_days: int = 90) -> list[Task]:
    """Create one open task per applicable template that does not have an open task yet."""
    authorize(session, actor, "task.write")
    existing = {k for k in session.scalars(select(Task.template_key).where(Task.status.in_(OPEN), Task.template_key.is_not(None)))}
    codes = {c.code: c for c in session.scalars(select(CommonControl))}
    applicable = [t for t in templates() if (not t.get("when") or t["when"] in tags) and t["key"] not in existing]
    created = []
    for i, tpl in enumerate(applicable):
        task = Task(title=tpl["title"], template_key=tpl["key"], frequency=tpl["frequency"], evidence_hint=tpl.get("evidence"), description=tpl.get("description"), assignee_id=assignee_id, status="todo",
                    due_date=today() + timedelta(days=14 + int(spread_days * i / max(1, len(applicable)))))
        task.controls = [codes[c] for c in tpl["controls"] if c in codes]
        session.add(task)
        created.append(task)
    session.flush()
    return created


@dataclass
class Readiness:
    status: str  # ready | in_progress | not_started | not_applicable
    score: int  # 0-100
    checks: list[dict]


def control_readiness(session: Session, control: CommonControl, on: date | None = None) -> Readiness:
    """How ready a control is for audit: linked policies approved, tasks done on time, evidence current, checks passing."""
    from keystone.controls.service import evidence_for, evidence_state
    from keystone.policies.models import PolicyDocument, policy_controls

    on = on or today()
    if control.status == "not_applicable":
        return Readiness("not_applicable", 100, [])
    checks = []
    docs = list(session.scalars(select(PolicyDocument).join(policy_controls).where(policy_controls.c.common_control_id == control.id, PolicyDocument.status != "retired")))
    if docs:
        ok = [d for d in docs if d.status == "approved" and (d.next_review_date is None or d.next_review_date >= on)]
        checks.append({"kind": "policies", "label": f"{len(ok)}/{len(docs)} linked policies approved and in date", "ok": len(ok) == len(docs)})
    tasks = [t for t in session.scalars(select(Task).join(Task.controls).where(CommonControl.id == control.id)) if t.status != "not_relevant"]
    if tasks:
        latest: dict[str, Task] = {}
        for t in sorted(tasks, key=lambda x: x.id):
            latest[t.template_key or f"t{t.id}"] = t
        late = [t for t in latest.values() if overdue(t, on)]
        done = [t for t in tasks if t.status == "done"]
        # Tasks block readiness only when overdue; proof itself comes from the evidence check.
        checks.append({"kind": "tasks", "label": f"{len(done)} task(s) completed, {len(late)} overdue", "ok": not late})
    evs = [e for e in evidence_for(session, control.id) if evidence_state(e, on) in ("current", "expiring")]
    checks.append({"kind": "evidence", "label": f"{len(evs)} current evidence item(s)", "ok": bool(evs)})
    try:
        from keystone.integrations.service import latest_results_for_control

        results = latest_results_for_control(session, control.id)
        if results:
            failing = [r for r in results if r.result != "pass"]
            checks.append({"kind": "checks", "label": f"{len(results) - len(failing)}/{len(results)} automated checks passing", "ok": not failing})
    except ImportError:
        pass
    passed = sum(c["ok"] for c in checks)
    score = round(100 * passed / len(checks)) if checks else 0
    status = "ready" if checks and passed == len(checks) and control.status == "implemented" else ("not_started" if passed == 0 and control.status in ("not_started", "planned") else "in_progress")
    return Readiness(status, score, checks)
