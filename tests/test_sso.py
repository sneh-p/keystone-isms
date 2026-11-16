"""Single sign-on (OIDC) against a fake identity provider: real RSA keys, signed tokens, PKCE checked."""

import base64
import hashlib
import json
import time
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from joserfc import jwt
from joserfc.jwk import RSAKey
from sqlalchemy import select

from keystone.core import auth
from keystone.core.audit import AuditLog
from keystone.sso import service as sso

from .conftest import PASSWORD, api_login

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "keystone-client-id-123"
KEY = RSAKey.generate_key(2048, parameters={"kid": "k1"})
OTHER_KEY = RSAKey.generate_key(2048, parameters={"kid": "k1"})


class FakeIdP:
    """Token and JWKS endpoints. `claims` customises the next ID token; the PKCE verifier is checked."""

    def __init__(self):
        self.claims: dict = {}
        self.sign_with = KEY
        self.header = {"alg": "RS256", "kid": "k1"}
        self.challenges: dict[str, str] = {}  # nonce -> code_challenge
        self.last_form: dict = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/keys") or request.url.path.endswith("/certs"):
            return httpx.Response(200, json={"keys": [KEY.as_dict(private=False)]})
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        self.last_form = form
        nonce = form["code"]  # the tests use the nonce as the authorization code
        challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(b"=").decode()
        if self.challenges.get(nonce) != challenge or form.get("client_secret") != "s3cret-client":
            return httpx.Response(400, json={"error": "invalid_grant"})
        now = int(time.time())
        iss = ("https://accounts.google.com" if "googleapis" in request.url.host else f"https://{request.url.host}" if request.url.host.endswith(".okta.com")
               else f"https://login.microsoftonline.com/{TENANT}/v2.0")
        claims = {"iss": iss, "aud": CLIENT, "sub": "sub-1", "iat": now, "exp": now + 600, "nonce": nonce, "tid": TENANT,
                  "email": "dana@alpine.example", "name": "Dana Doe", **self.claims}
        claims = {k: v for k, v in claims.items() if v is not None}
        token = jwt.encode(self.header, claims, self.sign_with, algorithms=["RS256", "HS256"])
        return httpx.Response(200, json={"id_token": token, "access_token": "x", "token_type": "Bearer"})


@pytest.fixture
def idp(monkeypatch):
    fake = FakeIdP()
    monkeypatch.setattr(sso, "_http", lambda: httpx.Client(transport=httpx.MockTransport(fake.handler), timeout=5))
    sso._jwks_cache.clear()
    monkeypatch.setenv("KEYSTONE_PUBLIC_URL", "https://isms.example.com")
    return fake


def _configure(api, kind="entra", **extra):
    api_login(api, "admin")
    body = {"client_id": CLIENT, "client_secret": "s3cret-client", "enabled": True, **({"tenant_id": TENANT} if kind == "entra" else {}), **extra}
    r = api.put(f"/api/settings/sso/{kind}", json=body)
    assert r.status_code == 200, r.text
    api.cookies.clear()
    api.headers.pop("X-CSRF-Token", None)
    return r.json()


def _login(api, idp, kind="entra", tamper=None):
    """Run the browser flow. Returns the final redirect location."""
    r = api.get(f"/api/auth/oidc/{kind}/start", follow_redirects=False)
    assert r.status_code == 303
    loc = urlparse(r.headers["location"])
    q = {k: v[0] for k, v in parse_qs(loc.query).items()}
    assert q["code_challenge_method"] == "S256" and q["redirect_uri"] == f"https://isms.example.com/api/auth/oidc/{kind}/callback"
    idp.challenges[q["nonce"]] = q["code_challenge"]
    params = {"code": q["nonce"], "state": q["state"]}
    if tamper:
        tamper(params, q)
    r = api.get(f"/api/auth/oidc/{kind}/callback", params=params, follow_redirects=False)
    assert r.status_code == 303
    return r.headers["location"]


def _make_user(db, ready_users, **kw):
    with db.session_scope() as s:
        admin = s.get(auth.User, ready_users["admin"].id)
        return auth.create_user(s, admin, username=kw.pop("username", "dana"), display_name="Dana", password=None, sso_only=True, email=kw.pop("email", "dana@alpine.example"), **kw).id


def test_settings_validation(api, ready_users, idp):
    api_login(api, "admin")
    for bad in ({"tenant_id": "common"}, {"tenant_id": "alpine.example"}, {"jit_role": "admin"}, {"jit_enabled": True, "allowed_domains": []},
                {"allowed_domains": ["not a domain"]}, {"client_id": "x"}):
        assert api.put("/api/settings/sso/entra", json=bad).status_code == 400, bad
    assert api.put("/api/settings/sso/google", json={"allowed_domains": ["gmail.com"]}).status_code == 400
    assert api.put("/api/settings/sso/entra", json={"enabled": True}).status_code == 400  # no client yet
    r = api.put("/api/settings/sso/entra", json={"client_id": CLIENT, "client_secret": "s3cret-client", "tenant_id": TENANT, "enabled": True})
    assert r.status_code == 200 and r.json()["client_secret_set"] and "s3cret" not in r.text
    assert "s3cret" not in api.get("/api/settings/sso").text
    assert api.put("/api/settings/sso/github", json={}).status_code == 404  # unknown provider
    assert api.get("/api/auth/status").json()["sso"] == ["entra"]
    api_login(api, "viewer")
    assert api.get("/api/settings/sso").status_code == 403


def test_precreated_account_is_activated_then_found_by_subject(api, ready_users, db, idp):
    uid = _make_user(db, ready_users)
    _configure(api)
    assert _login(api, idp) == "/"
    me = api.get("/api/auth/me").json()
    assert me["id"] == uid
    with db.session_scope() as s:
        u = s.get(auth.User, uid)
        assert u.sso_subject == "sub-1" and u.sso_issuer.endswith(f"{TENANT}/v2.0")
        assert s.scalars(select(AuditLog).where(AuditLog.summary.like("Signed in with entra SSO (first SSO sign-in%"))).first()
    # Later sign-ins use the subject, even if the email changed at the provider.
    api.cookies.clear()
    idp.claims = {"email": "dana.renamed@alpine.example"}
    assert _login(api, idp) == "/" and api.get("/api/auth/me").json()["id"] == uid
    # An SSO-only account has no usable password.
    r = api.post("/api/auth/login", json={"username": "dana", "password": "anything-at-all-123"})
    assert r.status_code == 401


def test_temporary_password_stops_working_after_activation(api, ready_users, db, idp):
    with db.session_scope() as s:
        admin = s.get(auth.User, ready_users["admin"].id)
        auth.create_user(s, admin, username="erin", display_name="Erin", password=PASSWORD, email="erin@alpine.example")
    _configure(api)
    idp.claims = {"sub": "sub-erin", "email": "erin@alpine.example"}
    assert _login(api, idp) == "/"
    api.cookies.clear()
    assert api.post("/api/auth/login", json={"username": "erin", "password": PASSWORD}).status_code == 401


def test_unknown_people_need_an_approved_domain(api, ready_users, db, idp):
    _configure(api)
    idp.claims = {"sub": "sub-new", "email": "newbie@alpine.example", "name": "New Person"}
    assert _login(api, idp) == "/login#sso_error=no_account"
    _configure(api, allowed_domains=["alpine.example"], jit_enabled=True)
    assert _login(api, idp) == "/"
    me = api.get("/api/auth/me").json()
    assert me["role"] == "employee" and me["username"] == "newbie@alpine.example"  # basic role only
    api.cookies.clear()
    idp.claims = {"sub": "sub-out", "email": "x@elsewhere.example"}
    assert _login(api, idp) == "/login#sso_error=no_account"


def test_disabled_and_expired_accounts_are_refused(api, ready_users, db, idp):
    uid = _make_user(db, ready_users)
    _configure(api)
    with db.session_scope() as s:
        s.get(auth.User, uid).active = False
    assert _login(api, idp) == "/login#sso_error=no_account"
    with db.session_scope() as s:
        u = s.get(auth.User, uid)
        u.active, u.expires_at = True, datetime.now() - timedelta(days=1)
    assert _login(api, idp) == "/login#sso_error=no_account"


@pytest.mark.parametrize("change, code", [
    ({"tid": "99999999-2222-3333-4444-555555555555"}, "wrong_tenant"),
    ({"aud": "someone-else"}, "invalid_token"),
    ({"iss": "https://login.microsoftonline.com/common/v2.0"}, "invalid_token"),
    ({"exp": int(time.time()) - 3600, "iat": int(time.time()) - 7200}, "invalid_token"),
    ({"nonce": "replayed-nonce"}, "invalid_token"),
    ({"sub": None}, "invalid_token"),
])
def test_bad_id_tokens_are_rejected(api, ready_users, db, idp, change, code):
    _make_user(db, ready_users)
    _configure(api)
    idp.claims = change
    assert _login(api, idp) == f"/login#sso_error={code}"
    assert api.get("/api/auth/me").status_code == 401


def test_forged_signatures_and_algorithms(api, ready_users, db, idp):
    _make_user(db, ready_users)
    _configure(api)
    idp.sign_with = OTHER_KEY  # right kid, wrong key
    assert _login(api, idp) == "/login#sso_error=invalid_token"
    from joserfc.jwk import OctKey

    idp.sign_with, idp.header = OctKey.import_key(json.dumps(KEY.as_dict(private=False)).encode()[:64]), {"alg": "HS256", "kid": "k1"}
    assert _login(api, idp) == "/login#sso_error=invalid_token"  # HMAC with the public key as secret


def test_state_cookie_and_replay(api, ready_users, db, idp):
    _make_user(db, ready_users)
    _configure(api)
    # Different browser: the binding cookie is missing.
    assert _login(api, idp, tamper=lambda p, q: api.cookies.delete("ks_oidc", path="/api/auth/oidc")) == "/login#sso_error=invalid_request"
    # Forged state.
    assert _login(api, idp, tamper=lambda p, q: p.update(state="forged")) == "/login#sso_error=invalid_request"
    # Replay of a completed login.
    seen = {}
    assert _login(api, idp, tamper=lambda p, q: seen.update(p)) == "/"
    r = api.get("/api/auth/oidc/entra/callback", params=seen, follow_redirects=False)
    assert r.headers["location"] == "/login#sso_error=invalid_request"
    # Provider-reported error, and a disabled provider.
    r = api.get("/api/auth/oidc/entra/callback", params={"error": "access_denied"}, follow_redirects=False)
    assert r.headers["location"] == "/login#sso_error=provider_error"
    assert api.get("/api/auth/oidc/okta/start", follow_redirects=False).headers["location"] == "/login#sso_error=not_configured"


def test_google_requires_verified_email_and_workspace_domain(api, ready_users, db, idp):
    _make_user(db, ready_users)
    _configure(api, "google", allowed_domains=["alpine.example"], jit_enabled=True)
    idp.claims = {"email_verified": False, "tid": None}
    assert _login(api, idp, "google") == "/login#sso_error=no_account"  # unverified email can't claim the account
    idp.claims = {"sub": "g-2", "email": "pat@alpine.example", "email_verified": True, "hd": None, "tid": None}
    assert _login(api, idp, "google") == "/login#sso_error=no_account"  # personal account using the domain name
    idp.claims = {"sub": "g-3", "email": "pat@alpine.example", "email_verified": True, "hd": "alpine.example", "tid": None}
    assert _login(api, idp, "google") == "/"
    assert api.get("/api/auth/me").json()["role"] == "employee"
    idp.claims = {"sub": "sub-1", "email_verified": True, "tid": None}
    api.cookies.clear()
    assert _login(api, idp, "google") == "/" and api.get("/api/auth/me").json()["username"] == "dana"


def test_secret_never_logged(api, ready_users, db, idp):
    _make_user(db, ready_users)
    _configure(api)
    _login(api, idp)
    with db.session_scope() as s:
        assert all("s3cret" not in (a.summary + str(a.changes or "")) for a in s.scalars(select(AuditLog)))
    assert idp.last_form["client_secret"] == "s3cret-client"  # sent only to the provider's token endpoint


# ---- Okta (round 3) --------------------------------------------------------------------------------------------

def test_okta_sign_in_needs_a_verified_email_and_an_okta_hosted_domain(api, ready_users, db, idp):
    api_login(api, "admin")
    for bad in ("login.evil.example", "acme.okta.com.evil.example", "https://10.0.0.1"):
        r = api.put("/api/settings/sso/okta", json={"org_domain": bad})
        assert r.status_code == 400, bad
    api.cookies.clear()
    api.headers.pop("X-CSRF-Token", None)
    _configure(api, "okta", org_domain="https://acme.okta.com/")
    with db.session_scope() as s:
        from keystone.core import auth

        auth.create_user(s, s.get(auth.User, ready_users["admin"].id), username="dana", display_name="Dana Doe", password=PASSWORD, email="dana@alpine.example")
    idp.claims = {"email_verified": None}  # Okta didn't vouch for the address
    assert "error=" in _login(api, idp, "okta")
    api.cookies.clear()
    idp.claims = {"email_verified": True, "tid": None}
    assert _login(api, idp, "okta") == "/"
    assert idp.last_form["redirect_uri"] == "https://isms.example.com/api/auth/oidc/okta/callback"


def test_changing_the_okta_domain_drops_the_secret(api, ready_users, db, idp):
    _configure(api, "okta", org_domain="acme.okta.com")
    api_login(api, "admin")
    body = api.put("/api/settings/sso/okta", json={"org_domain": "other.okta.com", "enabled": False}).json()
    assert body["client_secret_set"] is False and body["org_domain"] == "other.okta.com"
