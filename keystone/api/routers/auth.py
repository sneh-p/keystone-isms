from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from keystone.core import auth, sessions
from keystone.core.rbac import ROLE_LABELS, ROLE_PERMISSIONS, Role
from keystone.core.settings import get_settings

from ..deps import COOKIE, current_session, current_user, get_db

router = APIRouter(prefix="/auth", tags=["auth"])


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginIn(Strict):
    username: str = Field(max_length=150)
    password: str = Field(max_length=500)


class BootstrapIn(Strict):
    username: str = Field(max_length=150)
    display_name: str = Field(max_length=200)
    password: str = Field(max_length=500)
    email: str | None = None


class PasswordIn(Strict):
    current: str
    new: str


def _me(user, ws) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "email": user.email,
        "role": user.role,
        "role_label": ROLE_LABELS[Role(user.role)],
        "permissions": sorted(ROLE_PERMISSIONS[Role(user.role)]),
        "must_change_password": user.must_change_password,
        "csrf_token": ws.csrf_token,
    }


def _set_cookie(request: Request, response: Response, token: str) -> None:
    secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(COOKIE, token, httponly=True, samesite="lax", secure=secure, path="/", max_age=sessions.ABSOLUTE_HOURS * 3600)


@router.get("/status")
def status(db: Session = Depends(get_db)):
    return {"needs_bootstrap": auth.needs_bootstrap(db), "session_timeout_minutes": get_settings().session_timeout_minutes}


@router.post("/bootstrap")
def bootstrap(body: BootstrapIn, request: Request, response: Response, db: Session = Depends(get_db)):
    if not auth.needs_bootstrap(db):
        raise HTTPException(409, "Setup has already been completed.")
    user = auth.create_user(db, None, username=body.username, display_name=body.display_name, password=body.password, email=body.email)
    token, ws = sessions.create(db, user.id, request.client.host if request.client else None, request.headers.get("user-agent"))
    _set_cookie(request, response, token)
    return _me(user, ws)


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    try:
        user = auth.authenticate(db, body.username, body.password)
    except auth.AuthError:
        db.commit()  # keep lockout counters and the failed-login audit entry
        raise
    token, ws = sessions.create(db, user.id, request.client.host if request.client else None, request.headers.get("user-agent"))
    _set_cookie(request, response, token)
    return _me(user, ws)


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db), _ws=Depends(current_session)):
    sessions.destroy(db, request.cookies.get(COOKIE))
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
def me(user=Depends(current_user), ws=Depends(current_session)):
    return _me(user, ws)


@router.post("/change-password")
def change_password(body: PasswordIn, request: Request, response: Response, user=Depends(current_user), db: Session = Depends(get_db)):
    auth.change_password(db, user, body.current, body.new)
    # SC-AUTHN-003: a password change ends every session, including this one, and issues a new session ID and
    # CSRF token (it can also lift the forced-change restriction, which is a privilege change).
    sessions.destroy_all_for(db, user.id)
    token, ws = sessions.create(db, user.id, request.client.host if request.client else None, request.headers.get("user-agent"))
    _set_cookie(request, response, token)
    return {"ok": True, **_me(user, ws)}
