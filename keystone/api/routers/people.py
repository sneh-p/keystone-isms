"""People directory (admins), employee portal (everyone), invitation acceptance (public)."""

from datetime import date

from fastapi import APIRouter, Depends, File, Form, Header, Request, Response, UploadFile
from sqlalchemy.orm import Session

from keystone.core import auth, sessions
from keystone.core.services import get_or_404
from keystone.people import service as ppl
from keystone.people.models import DEVICE_CHECKS, OFFBOARDING_ITEMS, Person
from keystone.policies import service as pol

from ..deps import COOKIE, get_db, perm
from ..serialize import ser
from .common import In, public_link

router = APIRouter(tags=["people"])
PERSON = ("id", "full_name", "email", "job_title", "department", "employment_type", "manager_id", "start_date", "end_date", "status", "user_id", "offboarding")


@router.get("/people")
def people(include_offboarded: bool = False, user=Depends(perm("read")), db: Session = Depends(get_db)):
    rows = ppl.people_overview(db) if not include_offboarded else [(p, None) for p in ppl.list_people(db, True)]
    return {"people": [ser(p, PERSON, compliance=s.as_dict() if s else None) for p, s in rows], "offboarding_items": OFFBOARDING_ITEMS}


class PersonIn(In):
    full_name: str | None = None
    email: str | None = None
    job_title: str | None = None
    department: str | None = None
    employment_type: str | None = None
    manager_id: int | None = None
    start_date: date | None = None
    end_date: date | None = None


@router.post("/people")
def create(body: PersonIn, user=Depends(perm("people.write")), db: Session = Depends(get_db)):
    return ser(ppl.save_person(db, user, **body.model_dump(exclude_unset=True)), PERSON)


@router.patch("/people/{pid}")
def update(pid: int, body: PersonIn, user=Depends(perm("people.write")), db: Session = Depends(get_db)):
    return ser(ppl.save_person(db, user, pid, **body.model_dump(exclude_unset=True)), PERSON)


class InviteIn(In):
    send_email: bool = False


@router.post("/people/{pid}/invite")
def invite(pid: int, body: InviteIn | None = None, user=Depends(perm("people.write")), db: Session = Depends(get_db)):
    token = ppl.invite(db, user, pid)
    out = {**public_link(f"/invite#token={token}"), "expires_in_days": ppl.INVITE_DAYS, "emailed_to": None}
    if body and body.send_email:
        from keystone.notifications import service as ntf
        from keystone.org.service import get_org

        person = get_or_404(db, Person, pid)
        org = get_org(db)
        out["emailed_to"] = ntf.email_link(db, user, to=person.email, subject=f"Your {org.name if org else 'Keystone'} employee portal invitation",
                                           intro=f"Hello {person.full_name},\n\nYou've been invited to the employee portal, where you accept security policies, complete short training and confirm your device is secure. Open this link to set your password:",
                                           path=f"/invite#token={token}", closing=f"The link works once and expires in {ppl.INVITE_DAYS} days.", entity=("Person", pid))
    # SC-CRY-005: the token travels in the URL fragment, never in a path or query the server would log.
    return out


class LinkIn(In):
    user_id: int | None


@router.post("/people/{pid}/link")
def link(pid: int, body: LinkIn, user=Depends(perm("people.write")), db: Session = Depends(get_db)):
    return ser(ppl.link_user(db, user, pid, body.user_id), PERSON)


class StatusIn(In):
    status: str


@router.post("/people/{pid}/status")
def status(pid: int, body: StatusIn, user=Depends(perm("people.write")), db: Session = Depends(get_db)):
    return ser(ppl.set_status(db, user, pid, body.status), PERSON)


class TickIn(In):
    item: str
    done: bool = True


@router.post("/people/{pid}/offboarding")
def tick(pid: int, body: TickIn, user=Depends(perm("people.write")), db: Session = Depends(get_db)):
    return ser(ppl.tick_offboarding(db, user, pid, body.item, body.done), PERSON)


@router.post("/people/{pid}/offboarding/complete")
def complete(pid: int, user=Depends(perm("people.write")), db: Session = Depends(get_db)):
    return ser(ppl.complete_offboarding(db, user, pid), PERSON)


# ---- portal ----------------------------------------------------------------------------------

@router.get("/portal/policies/{vid}/document")
def portal_policy_document(vid: int, user=Depends(perm("portal")), db: Session = Depends(get_db)):
    from keystone.core.attachments import read_attachment

    a = pol.portal_document(db, user, vid)
    safe = a.filename.replace('"', "")
    return Response(read_attachment(a), media_type=a.content_type, headers={"Content-Disposition": f'attachment; filename="{safe}"', "X-Content-Type-Options": "nosniff"})


@router.get("/portal")
def portal(user=Depends(perm("portal")), db: Session = Depends(get_db)):
    from sqlalchemy import select

    person = db.scalar(select(Person).where(Person.user_id == user.id))
    return {
        "person": ser(person, ("full_name", "job_title", "department", "status")) if person else None,
        "status": ppl.status_for_user(db, user).as_dict(),
        "policies": [ser(v, ("id", "version_label", "body", "attachment_id"), code=v.document.code, title=v.document.title) for v in pol.pending_for(db, user)],
        "training": ppl.my_training(db, user),
        "devices": [ser(d, ("id", "device_name", "os", "checks", "attested_at"), compliant=ppl.device_compliant(d), issues=ppl.device_issues(d)) for d in ppl.my_devices(db, user)],
        "device_checks": DEVICE_CHECKS,
    }


@router.get("/portal/training/{key}")
def training_module(key: str, user=Depends(perm("portal"))):
    return ppl.public_module(ppl.module(key))


class QuizIn(In):
    answers: list[int]


@router.post("/portal/training/{key}")
def take_quiz(key: str, body: QuizIn, user=Depends(perm("portal")), db: Session = Depends(get_db)):
    c = ppl.submit_quiz(db, user, key, body.answers)
    return ser(c, ("score", "out_of", "passed", "completed_at"))


@router.post("/portal/devices")
async def attest(device_name: str = Form(..., max_length=200), os: str = Form(..., max_length=20), checks: str = Form(..., max_length=5_000), file: UploadFile | None = File(None), user=Depends(perm("portal")), db: Session = Depends(get_db)):
    import json

    d = ppl.attest_device(db, user, device_name=device_name, os=os, checks=json.loads(checks), filename=file.filename if file else None, data=await file.read() if file else None)
    return ser(d, ("id", "device_name", "os", "checks", "attested_at"), compliant=ppl.device_compliant(d))


# ---- public invitation acceptance ---------------------------------------------------------------

INVITE_HEADER = "X-Invite-Token"


def _invite_token(token: str | None) -> str:
    if not token or len(token) > 200:
        raise LookupError("This invitation link is not valid.")
    return token


@router.get("/public/invite")
def invite_info(token: str | None = Header(None, alias=INVITE_HEADER), db: Session = Depends(get_db)):
    return ppl.describe_invite(db, _invite_token(token))


class AcceptIn(In):
    password: str


@router.post("/public/invite")
def accept(body: AcceptIn, request: Request, response: Response, token: str | None = Header(None, alias=INVITE_HEADER), db: Session = Depends(get_db)):
    from .auth import _me, _set_cookie

    user = ppl.accept_invite(db, _invite_token(token), body.password)
    t, ws = sessions.create(db, user.id, request.client.host if request.client else None, request.headers.get("user-agent"))
    _set_cookie(request, response, t)
    return _me(user, ws)
