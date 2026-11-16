# Test cases for .semgrep/secure-coding.yml. Not imported or executed.
import os
import re
import ssl

import httpx
import jwt
from fastapi.responses import RedirectResponse
from sqlalchemy import text


def sql(session, title, sort):
    # ruleid: sc-inj-001-sql-string-building
    session.execute(text(f"SELECT * FROM risks WHERE title = '{title}'"))
    # ruleid: sc-inj-001-sql-string-building
    session.execute(text("SELECT * FROM risks ORDER BY " + sort))
    # ruleid: sc-inj-001-sql-string-building
    session.execute("SELECT * FROM risks WHERE id = %s" % title)
    # ok: sc-inj-001-sql-string-building
    session.execute(text("SELECT * FROM risks WHERE title = :t"), {"t": title})


def tls(url):
    # ruleid: sc-cry-004-tls-verification-disabled
    httpx.get(url, verify=False)
    # ruleid: sc-cry-004-tls-verification-disabled
    ctx = ssl._create_unverified_context()
    # ok: sc-cry-004-tls-verification-disabled
    httpx.get(url, timeout=10)
    return ctx


def redirect(request):
    # ruleid: sc-xss-005-open-redirect
    return RedirectResponse(request.query_params.get("next"))


def safe_redirect():
    # ok: sc-xss-005-open-redirect
    return RedirectResponse("/login")


def tokens(token, key):
    # ruleid: sc-authn-004-jwt-decode-unverified
    jwt.decode(token, options={"verify_signature": False})
    # ok: sc-authn-004-jwt-decode-unverified
    return jwt.decode(token, key, algorithms=["RS256"], audience="keystone")


def regex(user_value, text_in):
    # ruleid: sc-val-004-regex-from-input
    re.compile(user_value)
    # ruleid: sc-val-004-regex-from-input
    re.search(user_value, text_in)
    # ok: sc-val-004-regex-from-input
    re.compile(r"[a-z]+")
    # ok: sc-val-004-regex-from-input
    return re.search(re.escape(user_value), text_in)


def paths(upload, base):
    # ruleid: sc-file-001-path-from-input
    open(upload.filename, "wb")
    # ruleid: sc-file-001-path-from-input
    target = base / upload.filename
    # ok: sc-file-001-path-from-input
    other = base / "generated-name"
    return target, other, os
