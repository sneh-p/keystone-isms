"""Comments with @mentions, saved views, and the workload view.

Who may comment (decision 2026-11-16): any staff member who can read a record ("read"); employees can't. Comments
are append-only and audited. @username mentions notify that person if they can read the record (staff roles).
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime
from urllib.parse import parse_qsl, urlencode

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from keystone.core.auth import User, expired
from keystone.core.rbac import Role, has_permission
from keystone.core.services import authorize, get_or_404, require_text, today

from .models import Comment, SavedView

MAX_COMMENT = 5000
MENTION = re.compile(r"(?<![\w.@])@([a-z0-9][a-z0-9._-]{1,149})", re.I)


def _targets() -> dict[str, tuple[object, str]]:
    """Record types that take comments: model and the page that opens one."""
    from keystone.audits.models import Audit
    from keystone.frameworks.models import CommonControl
    from keystone.improvement.models import Nonconformity
    from keystone.incidents.models import Incident
    from keystone.policies.models import PolicyDocument
    from keystone.risk.models import Risk
    from keystone.tasks.models import Task
    from keystone.tprm.models import Vendor

    return {"risk": (Risk, "/risks?open={id}"), "control": (CommonControl, "/controls?open={id}"), "task": (Task, "/tasks?open={id}"),
            "incident": (Incident, "/incidents?open={id}"), "policy": (PolicyDocument, "/policies?open={id}"), "vendor": (Vendor, "/vendors?open={id}"),
            "nonconformity": (Nonconformity, "/nonconformities?open={id}"), "audit": (Audit, "/audits?open={id}")}


def _record(session: Session, kind: str, record_id: int):
    t = _targets().get(kind)
    if t is None:
        raise LookupError("Unknown record type")
    return get_or_404(session, t[0], record_id), t[1].format(id=record_id)


def _label(rec) -> str:
    code = getattr(rec, "code", None) or (rec.ref if hasattr(rec, "ref") and getattr(rec, "REF_PREFIX", None) else None)
    title = getattr(rec, "title", None) or getattr(rec, "name", "")
    return f"{code} {title}".strip() if code else title


def comments_for(session: Session, actor, kind: str, record_id: int) -> list[Comment]:
    authorize(session, actor, "read")
    _record(session, kind, record_id)
    return list(session.scalars(select(Comment).where(Comment.entity_type == kind, Comment.entity_id == record_id).order_by(Comment.id)))


def add_comment(session: Session, actor, kind: str, record_id: int, body: str) -> tuple[Comment, list[User]]:
    """Add a comment; returns it and the users who were notified of a mention."""
    authorize(session, actor, "read")
    rec, page = _record(session, kind, record_id)
    text = require_text(body, "Comment")
    if len(text) > MAX_COMMENT:
        raise ValueError(f"Comments are limited to {MAX_COMMENT} characters.")
    c = Comment(entity_type=kind, entity_id=record_id, body=text)
    session.add(c)
    session.flush()
    notified = []
    names = {m.lower() for m in MENTION.findall(text)}
    if names:
        from keystone.notifications.models import Notification

        for u in session.scalars(select(User).where(func.lower(User.username).in_(names), User.active.is_(True))):
            if u.id == actor.id or expired(u) or not has_permission(u, "read"):  # employees can't open the record
                continue
            session.add(Notification(user_id=u.id, key=f"mention:{c.id}", kind="mention", title=f"{actor.display_name} mentioned you on {_label(rec)}"[:500],
                                     page=page, created_at=datetime.now()))
            notified.append(u)
        session.flush()
    return c, notified


def mentionable(session: Session, actor) -> list[dict]:
    authorize(session, actor, "read")
    users = session.scalars(select(User).where(User.active.is_(True), User.role != Role.EMPLOYEE.value).order_by(User.display_name))
    return [{"username": u.username, "display_name": u.display_name} for u in users if not expired(u)]


# ---- saved views (each user's own) -------------------------------------------------------------------

PAGES = {"controls": {"domain", "status", "owner", "flag"}, "tasks": {"assignee", "framework", "control", "due"}}


def views(session: Session, actor, page: str) -> list[SavedView]:
    authorize(session, actor, "read")
    return list(session.scalars(select(SavedView).where(SavedView.user_id == actor.id, SavedView.page == page).order_by(SavedView.name)))


def save_view(session: Session, actor, page: str, name: str, query: str) -> SavedView:
    authorize(session, actor, "read")
    if page not in PAGES:
        raise ValueError("Views can be saved on Controls and Tasks.")
    name = require_text(name, "View name")[:80]
    pairs = [(k, v[:200]) for k, v in parse_qsl(query.lstrip("?"), keep_blank_values=False) if k in PAGES[page]]  # filters only
    if not pairs:
        raise ValueError("Choose at least one filter before saving a view.")
    if session.scalar(select(func.count(SavedView.id)).where(SavedView.user_id == actor.id)) >= 50:
        raise ValueError("You can keep up to 50 saved views.")
    v = session.scalar(select(SavedView).where(SavedView.user_id == actor.id, SavedView.page == page, SavedView.name == name))
    if v is None:
        v = SavedView(user_id=actor.id, page=page, name=name, query="")
        session.add(v)
    v.query = urlencode(pairs)
    session.flush()
    return v


def delete_view(session: Session, actor, view_id: int) -> None:
    authorize(session, actor, "read")
    v = session.get(SavedView, view_id)
    if v is None or v.user_id != actor.id:
        raise LookupError("View not found")
    session.delete(v)
    session.flush()


# ---- workload ------------------------------------------------------------------------------------------

def workload(session: Session, actor) -> list[dict]:
    """Per person: open tasks, overdue tasks, items needing them (routed attention), owned controls and risks."""
    authorize(session, actor, "read")
    from keystone.frameworks.models import CommonControl
    from keystone.reporting.routing import routed_items
    from keystone.risk.models import Risk
    from keystone.tasks import service as tsk

    on = today()
    open_tasks = [t for t in tsk.list_tasks(session, include_closed=False) if t.status in ("todo", "in_progress", "in_review")]
    tasks = Counter(t.assignee_id for t in open_tasks)
    overdue = Counter(t.assignee_id for t in open_tasks if tsk.overdue(t, on))
    due30 = Counter(t.assignee_id for t in open_tasks if t.due_date and 0 <= (t.due_date - on).days <= 30)
    routed = routed_items(session, on)
    controls = Counter(session.scalars(select(CommonControl.owner_id).where(CommonControl.owner_id.is_not(None), CommonControl.status != "not_applicable")))
    risks = Counter(session.scalars(select(Risk.owner_id).where(Risk.owner_id.is_not(None), Risk.status != "closed")))
    out = []
    for u in session.scalars(select(User).where(User.active.is_(True), User.role != Role.EMPLOYEE.value).order_by(User.display_name)):
        if expired(u):
            continue
        out.append({"user_id": u.id, "display_name": u.display_name, "role": u.role, "open_tasks": tasks[u.id], "overdue": overdue[u.id], "due_30": due30[u.id],
                    "needs_attention": len(routed.get(u.id, [])), "controls": controls[u.id], "risks": risks[u.id]})
    out.append({"user_id": None, "display_name": "Unassigned", "role": None, "open_tasks": tasks[None], "overdue": overdue[None], "due_30": due30[None],
                "needs_attention": 0, "controls": session.scalar(select(func.count(CommonControl.id)).where(CommonControl.owner_id.is_(None), CommonControl.status != "not_applicable")) or 0,
                "risks": session.scalar(select(func.count(Risk.id)).where(Risk.owner_id.is_(None), Risk.status != "closed")) or 0})
    return out
