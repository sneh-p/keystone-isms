"""Access review campaigns.

- Starting a campaign snapshots the accounts in scope: Keystone accounts (with their role) and, optionally, the
  accounts connected identity sources report (attack surface identities, with admin flag and last sign-in).
- Each item goes to the account holder's manager (from People), else the campaign owner. Nobody reviews their own
  access: such items go to the campaign owner, or to another access-review manager if the owner is the subject.
- Reviewers decide keep, revoke or change, with a comment for revoke and change.
- Revoking a Keystone account is applied by an administrator in one step (the account is deactivated and its
  sessions end). For other accounts, and for changes, Keystone opens a task for the campaign owner: it never changes
  anything in another system.
- A campaign is completed once every item is decided; completing files evidence on KC-ORG-18 and KC-TEC-02.
"""

from __future__ import annotations

from datetime import date, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from keystone.core import sessions
from keystone.core.auth import User, expired
from keystone.core.db import utcnow
from keystone.core.rbac import ROLE_LABELS, PermissionDenied, Role, has_permission
from keystone.core.services import authorize, get_or_404, require_text, today

from .models import DECISIONS, SOURCES, AccessReview, AccessReviewItem

EVIDENCE_CONTROLS = ("KC-ORG-18", "KC-TEC-02")


def _managers(session: Session) -> dict[int, int]:
    """Keystone user id -> their manager's Keystone user id, from the People register."""
    from keystone.people.models import Person

    people = {p.id: p for p in session.scalars(select(Person))}
    out = {}
    for p in people.values():
        m = people.get(p.manager_id) if p.manager_id else None
        if p.user_id and m and m.user_id:
            out[p.user_id] = m.user_id
    return out


def start(session: Session, actor, title: str, sources: list[str], due_date: date, owner_id: int | None = None) -> AccessReview:
    authorize(session, actor, "access_review.manage")
    if not sources or set(sources) - set(SOURCES):
        raise ValueError("Choose what to review: Keystone accounts, connected identities, or both.")
    if due_date <= today() or due_date > today() + timedelta(days=180):
        raise ValueError("The due date must be within the next six months.")
    owner = get_or_404(session, User, owner_id or actor.id)
    if not has_permission(owner, "access_review.manage"):
        raise ValueError("The campaign owner must be able to manage access reviews.")
    r = AccessReview(title=require_text(title, "Title")[:300], sources=sorted(set(sources)), owner_id=owner.id, due_date=due_date, status="open")
    session.add(r)
    session.flush()
    mgr = _managers(session)
    backups = [u.id for u in session.scalars(select(User).where(User.active.is_(True))) if not expired(u) and has_permission(u, "access_review.manage") and u.id != owner.id]

    def reviewer_for(subject_user_id: int | None) -> int:
        rid = mgr.get(subject_user_id) if subject_user_id else None
        rid = rid or owner.id
        if rid == subject_user_id:  # never your own access
            rid = owner.id if owner.id != subject_user_id else (backups[0] if backups else owner.id)
        return rid

    n = 0
    if "keystone" in r.sources:
        for u in session.scalars(select(User).where(User.active.is_(True)).order_by(User.display_name)):
            if expired(u):
                continue
            label = ROLE_LABELS.get(Role(u.role), u.role)
            last = f", last sign-in {u.last_login_at:%Y-%m-%d}" if u.last_login_at else ", never signed in"
            session.add(AccessReviewItem(review_id=r.id, source="keystone", subject=f"{u.display_name} ({u.username})"[:320], access=f"Keystone: {label}{last}"[:500],
                                         user_id=u.id, reviewer_id=reviewer_for(u.id)))
            n += 1
    if "identities" in r.sources:
        from keystone.asm.models import AsmIdentity

        for i in session.scalars(select(AsmIdentity).order_by(AsmIdentity.upn)):
            props = i.properties or {}
            if props.get("account_enabled") is False:
                continue
            bits = [i.source.title()]
            if props.get("is_admin"):
                bits.append("administrator")
            if props.get("is_guest"):
                bits.append("guest")
            days = props.get("last_sign_in_days")
            bits.append(f"last sign-in {days} days ago" if isinstance(days, int) else "sign-in unknown")
            session.add(AccessReviewItem(review_id=r.id, source="identities", subject=f"{i.display_name or i.upn} ({i.upn})"[:320], access=", ".join(bits)[:500],
                                         identity_id=i.id, user_id=None, reviewer_id=reviewer_for(i.user_id)))
            n += 1
    if n == 0:
        raise ValueError("Nothing to review in the chosen scope.")
    session.flush()
    return r


def reviews(session: Session, actor) -> list[dict]:
    authorize(session, actor, "read")
    out = []
    for r in session.scalars(select(AccessReview).order_by(AccessReview.id.desc())):
        counts = dict(session.execute(select(AccessReviewItem.decision, func.count()).where(AccessReviewItem.review_id == r.id).group_by(AccessReviewItem.decision)).all())
        total = sum(counts.values())
        out.append({"review": r, "total": total, "decided": total - counts.get(None, 0), "revoke": counts.get("revoke", 0), "change": counts.get("change", 0)})
    return out


def items(session: Session, actor, review_id: int, mine_only: bool = False) -> list[AccessReviewItem]:
    authorize(session, actor, "read")
    r = get_or_404(session, AccessReview, review_id)
    q = select(AccessReviewItem).where(AccessReviewItem.review_id == r.id).order_by(AccessReviewItem.decision.is_not(None), AccessReviewItem.subject)
    if mine_only:
        q = q.where(AccessReviewItem.reviewer_id == actor.id)
    return list(session.scalars(q))


def decide(session: Session, actor, item_id: int, decision: str, comment: str | None = None) -> AccessReviewItem:
    authorize(session, actor, "read")
    it = get_or_404(session, AccessReviewItem, item_id)
    r = get_or_404(session, AccessReview, it.review_id)
    if r.status != "open":
        raise ValueError("This campaign is closed.")
    if it.reviewer_id != actor.id:
        raise PermissionDenied("Only the assigned reviewer can decide this item.")
    if it.user_id == actor.id:
        raise PermissionDenied("Segregation of duties: you can't review your own access.")
    if decision not in DECISIONS:
        raise ValueError("Decide keep, revoke or change.")
    if decision != "keep" and not (comment or "").strip():
        raise ValueError("Say what should be revoked or changed.")
    it.decision, it.comment, it.decided_by_id, it.decided_at = decision, (comment or "").strip()[:2000] or None, actor.id, utcnow()
    session.flush()
    return it


def apply_revocation(session: Session, actor, item_id: int) -> AccessReviewItem:
    """Deactivate a Keystone account a reviewer said to revoke (users.manage)."""
    authorize(session, actor, "users.manage")
    it = get_or_404(session, AccessReviewItem, item_id)
    if it.decision != "revoke" or it.source != "keystone" or not it.user_id:
        raise ValueError("Only a decision to revoke a Keystone account can be applied here.")
    if it.user_id == actor.id:
        raise ValueError("You can't deactivate your own account.")
    u = get_or_404(session, User, it.user_id)
    u.active = False
    sessions.destroy_all_for(session, u.id)
    it.actioned_at = utcnow()
    session.flush()
    return it


def complete(session: Session, actor, review_id: int) -> AccessReview:
    """Close a fully decided campaign: tasks for follow-up actions outside Keystone, evidence on the controls."""
    from keystone.controls.models import Evidence
    from keystone.frameworks.models import CommonControl
    from keystone.tasks.models import Task

    authorize(session, actor, "access_review.manage")
    r = get_or_404(session, AccessReview, review_id)
    if r.status != "open":
        raise ValueError("The campaign is already completed.")
    its = list(session.scalars(select(AccessReviewItem).where(AccessReviewItem.review_id == r.id)))
    if any(i.decision is None for i in its):
        raise ValueError(f"{sum(1 for i in its if i.decision is None)} item(s) still need a decision.")
    follow = [i for i in its if i.decision in ("revoke", "change") and not i.actioned_at and not (i.source == "keystone" and i.decision == "revoke")]
    if follow:
        t = Task(title=f"Carry out access review {r.ref} decisions ({len(follow)})"[:300], status="todo", frequency="once", assignee_id=r.owner_id,
                 due_date=today() + timedelta(days=14),
                 description="\n".join(f"- {(i.decision or '').upper()}: {i.subject}: {i.comment or ''}" for i in follow)[:8000])
        session.add(t)
        session.flush()
        for i in follow:
            i.task_id = t.id
    r.status, r.completed_at = "completed", utcnow()
    from keystone.outbound.service import emit

    emit(session, "access_review.completed", title=f"Access review {r.ref} completed: {r.title}", ref=r.ref, page=f"/access-reviews?open={r.id}")
    summary = (f"{len(its)} account(s) reviewed: {sum(1 for i in its if i.decision == 'keep')} kept, {sum(1 for i in its if i.decision == 'revoke')} to revoke, "
               f"{sum(1 for i in its if i.decision == 'change')} to change. Completed {today()}.")
    for code in EVIDENCE_CONTROLS:
        c = session.scalar(select(CommonControl).where(CommonControl.code == code))
        if c is not None:
            session.add(Evidence(common_control_id=c.id, title=f"Access review {r.ref}: {r.title}"[:300], kind="note", description=summary,
                                 collected_on=today(), valid_until=today() + timedelta(days=400)))
    session.flush()
    return r


def pending_for(session: Session, user_id: int) -> list[AccessReviewItem]:
    return list(session.scalars(select(AccessReviewItem).join(AccessReview, AccessReview.id == AccessReviewItem.review_id)
                                .where(AccessReview.status == "open", AccessReviewItem.reviewer_id == user_id, AccessReviewItem.decision.is_(None))))
