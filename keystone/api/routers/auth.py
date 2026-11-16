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
    from keystone.sso import service as sso

    return {"needs_bootstrap": auth.needs_bootstrap(db), "session_timeout_minutes": get_settings().session_timeout_minutes, "sso": sso.enabled_providers(db)}


# ---- single sign-on (OIDC); design and controls in keystone/sso/service.py ------------------------------

OIDC_COOKIE = "ks_oidc"


def _secure(request: Request) -> bool:
    return request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"


@router.get("/oidc/{kind}/start")
def oidc_start(kind: str, request: Request, db: Session = Depends(get_db)):
    from fastapi.responses import RedirectResponse

    from keystone.sso import service as sso

    try:
        url, browser = sso.start(db, kind)
    except (sso.SsoError, LookupError):
        return RedirectResponse("/login#sso_error=not_configured", status_code=303)
    r = RedirectResponse(url, status_code=303)
    # Binds the login to this browser (login CSRF); Lax is sent on the provider's top-level redirect back.
    r.set_cookie(OIDC_COOKIE, browser, httponly=True, samesite="lax", secure=_secure(request), path="/api/auth/oidc", max_age=600)
    return r


@router.get("/oidc/{kind}/callback")
def oidc_callback(kind: str, request: Request, code: str | None = None, state: str | None = None, error: str | None = None, db: Session = Depends(get_db)):
    from fastapi.responses import RedirectResponse

    from keystone.core.audit import log_event
    from keystone.sso import service as sso

    try:
        user = sso.finish(db, kind, code=code, state=state, browser=request.cookies.get(OIDC_COOKIE), error=error)
    except (sso.SsoError, LookupError) as e:
        code_ = e.code if isinstance(e, sso.SsoError) else "not_configured"
        log_event(db, None, "login_failed", "User", None, f"SSO sign-in failed ({kind}): {code_}: {getattr(e, 'detail', '')}"[:500])
        db.commit()  # keep the failed-login audit entry and the used state
        r = RedirectResponse(f"/login#sso_error={code_}", status_code=303)
        r.delete_cookie(OIDC_COOKIE, path="/api/auth/oidc")
        return r
    token, _ws = sessions.create(db, user.id, request.client.host if request.client else None, request.headers.get("user-agent"))
    r = RedirectResponse("/", status_code=303)
    _set_cookie(request, r, token)
    r.delete_cookie(OIDC_COOKIE, path="/api/auth/oidc")
    return r


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
