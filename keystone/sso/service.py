"""OpenID Connect single sign-on with Microsoft Entra ID and Google (Authlib + joserfc).

Security design (docs/feature-security-designs.md, approved):
- Authorization code flow with PKCE (S256), state and nonce, bound to the browser by an HttpOnly cookie; login
  records are single-use and expire after 10 minutes.
- Provider endpoints are fixed in code (SC-SSRF-001): Google's are constants; Entra's are built from the tenant ID,
  which must be a GUID (path segment only). No discovery document or URL is taken from configuration.
- ID tokens are verified with the provider's JWKS, algorithms pinned to RS256, and iss, aud, exp, iat and nonce
  checked (SC-AUTHN-004). Entra tokens must come from the configured tenant (tid); Google emails must be verified.
- Accounts: a bound account is found by (issuer, subject) only. The first SSO sign-in binds an account an admin
  created, by its email. Optionally, people from approved domains get an account automatically with a basic role
  (employee or viewer). Nothing else signs in.
- The client secret is encrypted at rest, write-only, and sent only to the provider's fixed token endpoint.
"""

from __future__ import annotations

import hashlib
import re
import secrets as pysecrets
import time
from datetime import timedelta
from urllib.parse import urlencode

import httpx
from authlib.common.security import generate_token
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from keystone.core import secrets
from keystone.core.audit import log_event
from keystone.core.auth import SSO_ONLY_MARKER, User, expired
from keystone.core.db import utcnow
from keystone.core.rbac import Role
from keystone.core.services import authorize
from keystone.core.settings import get_settings

from .models import JIT_ROLES, PROVIDERS, OidcLogin, SsoProvider

LOGIN_TTL = timedelta(minutes=10)
GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
ALGORITHMS = ["RS256"]
LEEWAY = 60
HTTP_TIMEOUT = 15.0


class SsoError(Exception):
    """A failed SSO sign-in. `code` is safe to show; details go to the audit log only."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


def endpoints(p: SsoProvider) -> dict:
    if p.kind == "google":
        return {"issuer": "https://accounts.google.com", "authorize": "https://accounts.google.com/o/oauth2/v2/auth",
                "token": "https://oauth2.googleapis.com/token", "jwks": "https://www.googleapis.com/oauth2/v3/certs"}
    if p.kind == "entra":
        tid = p.tenant_id or ""
        if not GUID.match(tid):
            raise SsoError("not_configured", "Entra tenant ID missing or invalid")
        base = f"https://login.microsoftonline.com/{tid}"
        return {"issuer": f"{base}/v2.0", "authorize": f"{base}/oauth2/v2.0/authorize", "token": f"{base}/oauth2/v2.0/token",
                "jwks": f"{base}/discovery/v2.0/keys"}
    raise SsoError("not_configured", "unknown provider")


def redirect_uri(kind: str) -> str:
    base = get_settings().public_url
    if not base:
        raise SsoError("not_configured", "KEYSTONE_PUBLIC_URL is not set")
    return f"{base}/api/auth/oidc/{kind}/callback"


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _http() -> httpx.Client:
    return httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=False)


# ---- configuration (administrators) ------------------------------------------------------------------

def provider(session: Session, kind: str) -> SsoProvider:
    if kind not in PROVIDERS:
        raise LookupError("Unknown sign-in provider")
    p = session.scalar(select(SsoProvider).where(SsoProvider.kind == kind))
    if p is None:
        p = SsoProvider(kind=kind, enabled=False, allowed_domains=[], jit_enabled=False, jit_role="employee")
        session.add(p)
        session.flush()
    return p


def view(p: SsoProvider) -> dict:
    base = get_settings().public_url
    return {"kind": p.kind, "enabled": p.enabled, "client_id": p.client_id, "client_secret_set": bool(p.client_secret_enc), "tenant_id": p.tenant_id,
            "allowed_domains": p.allowed_domains or [], "jit_enabled": p.jit_enabled, "jit_role": p.jit_role,
            "redirect_uri": f"{base}/api/auth/oidc/{p.kind}/callback" if base else None, "public_url_set": bool(base)}


def update(session: Session, actor, kind: str, **fields) -> SsoProvider:
    authorize(session, actor, "users.manage")
    p = provider(session, kind)
    allowed = {"enabled", "client_id", "client_secret", "clear_secret", "tenant_id", "allowed_domains", "jit_enabled", "jit_role"}
    if set(fields) - allowed:
        raise ValueError(f"fields not editable here: {', '.join(sorted(set(fields) - allowed))}")
    if "client_id" in fields:
        cid = (fields["client_id"] or "").strip()
        if cid and not re.fullmatch(r"[A-Za-z0-9._-]{8,200}", cid):
            raise ValueError("The client ID looks wrong; paste it from the app registration.")
        p.client_id = cid or None
    if "tenant_id" in fields:
        tid = (fields["tenant_id"] or "").strip().lower()
        if tid and not GUID.match(tid):
            raise ValueError("Enter the tenant ID (a GUID), not a domain or 'common': only your organisation's tenant is trusted.")
        p.tenant_id = tid or None
    if "allowed_domains" in fields:
        domains = sorted({(d or "").strip().lower().lstrip("@") for d in fields["allowed_domains"] or [] if (d or "").strip()})
        bad = [d for d in domains if not DOMAIN.match(d)]
        if bad:
            raise ValueError(f"Not a domain: {', '.join(bad)}")
        if p.kind == "google" and any(d in ("gmail.com", "googlemail.com") for d in domains):
            raise ValueError("Personal Gmail can't be an approved domain; approve your Google Workspace domain.")
        p.allowed_domains = domains
    if "jit_role" in fields:
        if fields["jit_role"] not in JIT_ROLES:
            raise ValueError(f"Automatic accounts can only get a basic role: {', '.join(JIT_ROLES)}.")
        p.jit_role = fields["jit_role"]
    if "jit_enabled" in fields:
        p.jit_enabled = bool(fields["jit_enabled"])
    if fields.get("clear_secret"):
        p.client_secret_enc = None
    if fields.get("client_secret"):
        p.client_secret_enc = secrets.encrypt(fields["client_secret"])
    if "enabled" in fields:
        p.enabled = bool(fields["enabled"])
    if p.jit_enabled and not p.allowed_domains:
        raise ValueError("Automatic accounts need at least one approved domain.")
    if p.enabled:
        if not (p.client_id and p.client_secret_enc):
            raise ValueError("Set the client ID and secret before turning this sign-in on.")
        endpoints(p)  # Entra needs a valid tenant
        redirect_uri(p.kind)
    session.flush()
    return p


def enabled_providers(session: Session) -> list[str]:
    return [p.kind for p in session.scalars(select(SsoProvider).where(SsoProvider.enabled.is_(True)).order_by(SsoProvider.kind))]


# ---- login ---------------------------------------------------------------------------------------------

def start(session: Session, kind: str) -> tuple[str, str]:
    """Begin a login. Returns (authorization URL, browser binding value for the HttpOnly cookie)."""
    p = provider(session, kind)
    if not p.enabled:
        raise SsoError("not_configured", f"{kind} sign-in is off")
    ep = endpoints(p)
    state, nonce, verifier, browser = generate_token(43), generate_token(43), generate_token(64), pysecrets.token_urlsafe(32)
    session.execute(OidcLogin.__table__.delete().where(OidcLogin.created_at < utcnow() - LOGIN_TTL))
    session.add(OidcLogin(provider_kind=kind, state_hash=_h(state), browser_hash=_h(browser), nonce=nonce, code_verifier_enc=secrets.encrypt(verifier)))
    session.flush()
    params = {"client_id": p.client_id, "response_type": "code", "redirect_uri": redirect_uri(kind), "scope": "openid email profile",
              "state": state, "nonce": nonce, "code_challenge": create_s256_code_challenge(verifier), "code_challenge_method": "S256",
              "response_mode": "query", "prompt": "select_account"}
    return f"{ep['authorize']}?{urlencode(params)}", browser


_jwks_cache: dict[str, tuple[float, dict]] = {}


def _jwks(url: str, refresh: bool = False) -> KeySet:
    hit = _jwks_cache.get(url)
    if hit and not refresh and time.monotonic() - hit[0] < 3600:
        return KeySet.import_key_set(hit[1])
    with _http() as c:
        r = c.get(url)
    if r.status_code != 200:
        raise SsoError("provider_error", f"JWKS fetch failed ({r.status_code})")
    data = r.json()
    _jwks_cache[url] = (time.monotonic(), data)
    return KeySet.import_key_set(data)


def verify_id_token(id_token: str, p: SsoProvider, nonce: str) -> dict:
    ep = endpoints(p)
    try:
        try:
            token = jwt.decode(id_token, _jwks(ep["jwks"]), algorithms=ALGORITHMS)
        except (JoseError, ValueError):
            token = jwt.decode(id_token, _jwks(ep["jwks"], refresh=True), algorithms=ALGORITHMS)  # key rotation
        registry = jwt.JWTClaimsRegistry(leeway=LEEWAY, iss={"essential": True, "value": ep["issuer"]}, aud={"essential": True, "value": p.client_id},
                                         exp={"essential": True}, iat={"essential": True}, sub={"essential": True}, nonce={"essential": True, "value": nonce})
        registry.validate(token.claims)
    except (JoseError, ValueError) as e:
        raise SsoError("invalid_token", f"ID token rejected: {type(e).__name__}: {e}") from None
    if token.header.get("alg") not in ALGORITHMS:
        raise SsoError("invalid_token", "unexpected algorithm")
    claims = dict(token.claims)
    if p.kind == "entra" and claims.get("tid") != p.tenant_id:
        raise SsoError("wrong_tenant", "token from another Entra tenant")
    return claims


def _email(p: SsoProvider, claims: dict) -> str | None:
    if p.kind == "google":
        if claims.get("email_verified") is not True:
            return None
        return (claims.get("email") or "").strip().lower() or None
    # Entra, single tenant: the tenant controls these values.
    return (claims.get("email") or claims.get("preferred_username") or "").strip().lower() or None


def _domain_ok(p: SsoProvider, claims: dict, email: str | None) -> bool:
    if not email or "@" not in email:
        return False
    domain = email.rsplit("@", 1)[1]
    if domain not in (p.allowed_domains or []):
        return False
    return p.kind != "google" or (claims.get("hd") or "").lower() == domain  # Workspace accounts only


def resolve_user(session: Session, p: SsoProvider, claims: dict) -> User:
    iss, sub = claims["iss"], str(claims["sub"])
    user = session.scalar(select(User).where(User.sso_issuer == iss, User.sso_subject == sub))
    how = "bound account"
    email = _email(p, claims)
    if user is None and email:
        candidate = session.scalar(select(User).where(func.lower(User.email) == email, User.sso_subject.is_(None)))
        if candidate is not None:
            user, how = candidate, "first SSO sign-in (account activated)"
            user.sso_issuer, user.sso_subject = iss, sub
            if user.must_change_password:  # the temporary password is no longer needed or valid
                user.password_hash, user.must_change_password = SSO_ONLY_MARKER, False
    if user is None and p.jit_enabled and _domain_ok(p, claims, email):
        username = email
        if session.scalar(select(User).where(User.username == username)):
            raise SsoError("no_account", f"username {username} exists but is not linked")
        user = User(username=username, display_name=(claims.get("name") or email)[:200], email=email, role=Role(p.jit_role).value,
                    password_hash=SSO_ONLY_MARKER, must_change_password=False, sso_issuer=iss, sso_subject=sub)
        session.add(user)
        session.flush()
        how = f"account created automatically ({p.jit_role}, approved domain)"
        log_event(session, user, "create", "User", user.id, f"Account created at first SSO sign-in from an approved domain ({p.kind}, role {p.jit_role})")
    if user is None:
        raise SsoError("no_account", f"no Keystone account for this {p.kind} identity")
    if not user.active or expired(user):
        raise SsoError("no_account", "account disabled or expired")
    user.last_login_at = utcnow()
    session.flush()
    log_event(session, user, "login", "User", user.id, f"Signed in with {p.kind} SSO ({how})")
    return user


def finish(session: Session, kind: str, *, code: str | None, state: str | None, browser: str | None, error: str | None = None) -> User:
    """Complete a login from the provider's redirect. Raises SsoError; callers show only its code."""
    if error:
        raise SsoError("provider_error", f"provider returned error {error[:100]}")
    if not code or not state or not browser or len(code) > 4096 or len(state) > 200:
        raise SsoError("invalid_request", "missing code, state or browser binding")
    login = session.scalar(select(OidcLogin).where(OidcLogin.state_hash == _h(state)))
    if login is None or login.used_at or login.provider_kind != kind or login.created_at < utcnow() - LOGIN_TTL:
        raise SsoError("invalid_request", "unknown, used or expired state")
    login.used_at = utcnow()  # single use, even if the rest fails
    session.flush()
    if not pysecrets.compare_digest(login.browser_hash, _h(browser)):
        raise SsoError("invalid_request", "login started in a different browser")
    p = provider(session, kind)
    if not p.enabled:
        raise SsoError("not_configured", f"{kind} sign-in is off")
    ep = endpoints(p)
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(kind), "client_id": p.client_id,
            "client_secret": secrets.decrypt(p.client_secret_enc or ""), "code_verifier": secrets.decrypt(login.code_verifier_enc)}
    try:
        with _http() as c:
            r = c.post(ep["token"], data=form, headers={"Accept": "application/json"})
    except httpx.HTTPError as e:
        raise SsoError("provider_error", f"token request failed ({type(e).__name__})") from None
    if r.status_code != 200:
        raise SsoError("provider_error", f"token endpoint returned {r.status_code}")
    id_token = (r.json() or {}).get("id_token")
    if not id_token:
        raise SsoError("provider_error", "no ID token in the response")
    claims = verify_id_token(id_token, p, login.nonce)
    user = resolve_user(session, p, claims)
    login.user_id = user.id
    session.flush()
    return user
