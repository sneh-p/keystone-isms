"""People directory (admins), employee portal (everyone), invitation acceptance (public)."""

from datetime import date

from fastapi import APIRouter, Depends, File, Form, Request, Response, UploadFile
from sqlalchemy.orm import Session

from keystone.core import auth, sessions
from keystone.core.services import get_or_404
from keystone.people import service as ppl
from keystone.people.models import DEVICE_CHECKS, OFFBOARDING_ITEMS, Person
from keystone.policies import service as pol

from ..deps import COOKIE, get_db, perm
from ..serialize import ser
from .common import In

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


@router.post("/people/{pid}/invite")
def invite(pid: int, request: Request, user=Depends(perm("people.write")), db: Session = Depends(get_db)):
    token = ppl.invite(db, user, pid)
    base = str(request.base_url).rstrip("/")
    return {"url": f"{base}/invite/{token}", "expires_in_days": ppl.INVITE_DAYS}


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

@router.get("/portal")
def portal(user=Depends(perm("portal")), db: Session = Depends(get_db)):
    from sqlalchemy import select

    person = db.scalar(select(Person).where(Person.user_id == user.id))
    return {
        "person": ser(person, ("full_name", "job_title", "department", "status")) if person else None,
        "status": ppl.status_for_user(db, user).as_dict(),
        "policies": [ser(v, ("id", "version_label", "body", "attachment_id"), code=v.document.code, title=v.document.title) for v in pol.pending_for(db, user)],
        "training": ppl.my_training(db, user),
        "devices": [ser(d, ("id", "device_name", "os", "checks", "attested_at"), compliant=ppl.device_compliant(d)) for d in ppl.my_devices(db, user)],
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
async def attest(device_name: str = Form(...), os: str = Form(...), checks: str = Form(...), file: UploadFile | None = File(None), user=Depends(perm("portal")), db: Session = Depends(get_db)):
    import json

    d = ppl.attest_device(db, user, device_name=device_name, os=os, checks=json.loads(checks), filename=file.filename if file else None, data=await file.read() if file else None)
    return ser(d, ("id", "device_name", "os", "checks", "attested_at"), compliant=ppl.device_compliant(d))


# ---- public invitation acceptance ---------------------------------------------------------------

@router.get("/public/invite/{token}")
def invite_info(token: str, db: Session = Depends(get_db)):
    return ppl.describe_invite(db, token)


class AcceptIn(In):
    password: str


@router.post("/public/invite/{token}")
def accept(token: str, body: AcceptIn, request: Request, response: Response, db: Session = Depends(get_db)):
    from .auth import _me, _set_cookie

    user = ppl.accept_invite(db, token, body.password)
    t, ws = sessions.create(db, user.id, request.client.host if request.client else None, request.headers.get("user-agent"))
    _set_cookie(request, response, t)
    return _me(user, ws)
