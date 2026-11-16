"""Inbox for the signed-in user, digest preference, and SMTP settings (administrators)."""

from fastapi import APIRouter, Depends
from pydantic import Field
from sqlalchemy.orm import Session

from keystone.notifications import service as ntf

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(tags=["notifications"])

# Every role holds "portal" (employees included), so it is the permission for a user's own inbox; the service also
# filters by the user's id, and refuses other users' items as not found.
OUT = ("id", "kind", "title", "page", "due", "created_at", "read_at", "resolved_at")


@router.get("/portal/notifications")
def inbox(include_resolved: bool = False, user=Depends(perm("portal")), db: Session = Depends(get_db)):
    return {"items": [ser(n, OUT) for n in ntf.inbox(db, user, include_resolved)], "unread": ntf.unread_count(db, user),
            "email_digest": ntf.prefs(db, user).email_digest, "has_email": bool(user.email)}


class ReadIn(In):
    ids: list[int] | None = Field(default=None, max_length=500)


@router.post("/portal/notifications/read")
def mark_read(body: ReadIn, user=Depends(perm("portal")), db: Session = Depends(get_db)):
    return {"updated": ntf.mark_read(db, user, body.ids)}


class PrefsIn(In):
    email_digest: bool


@router.put("/portal/notifications/prefs")
def set_prefs(body: PrefsIn, user=Depends(perm("portal")), db: Session = Depends(get_db)):
    return {"email_digest": ntf.set_prefs(db, user, body.email_digest).email_digest}


@router.get("/settings/email")
def smtp_settings(user=Depends(perm("users.manage")), db: Session = Depends(get_db)):
    return ntf.smtp_view(ntf.smtp(db))


class SmtpIn(In):
    enabled: bool | None = None
    host: str | None = Field(default=None, max_length=253)
    port: int | None = None
    security: str | None = None
    username: str | None = Field(default=None, max_length=320)
    password: str | None = Field(default=None, max_length=500)  # write-only
    clear_password: bool | None = None
    from_address: str | None = Field(default=None, max_length=320)
    from_name: str | None = Field(default=None, max_length=100)
    digest_hour_utc: int | None = None


@router.put("/settings/email")
def update_smtp(body: SmtpIn, user=Depends(perm("users.manage")), db: Session = Depends(get_db)):
    return ntf.smtp_view(ntf.update_smtp(db, user, **body.model_dump(exclude_unset=True)))


class TestIn(In):
    to: str | None = Field(default=None, max_length=320)


@router.post("/settings/email/test")
def send_test(body: TestIn, user=Depends(perm("users.manage")), db: Session = Depends(get_db)):
    return {"sent_to": ntf.send_test(db, user, body.to)}


@router.get("/email-status")
def email_status(user=Depends(perm("read")), db: Session = Depends(get_db)):
    """Whether "Send by email" can work: email is on and links can be built from KEYSTONE_PUBLIC_URL."""
    from keystone.core.settings import get_settings

    s = ntf.smtp(db)
    return {"ready": bool(s.enabled and s.host and s.from_address and get_settings().public_url)}
