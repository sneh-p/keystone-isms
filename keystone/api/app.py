"""Keystone ISMS web API + single-page app."""

from __future__ import annotations

import logging
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from keystone import __version__
from keystone.core import db as dbmod
from keystone.core.attachments import AttachmentRejected
from keystone.core.auth import AuthError, PasswordPolicyError
from keystone.core.rbac import PermissionDenied
from keystone.core.services import NotFound
from keystone.core.settings import PROJECT_ROOT
from keystone.core.workflow import InvalidTransition

WEB_DIST = PROJECT_ROOT / "web" / "dist"
_LOG = logging.getLogger(__name__)

def security_headers() -> dict[str, str]:
    # Who may embed Keystone in a frame. Default: only Keystone itself. Set
    # KEYSTONE_FRAME_ANCESTORS (CSP source list, e.g. "https://intranet.example") to allow a portal.
    ancestors = os.environ.get("KEYSTONE_FRAME_ANCESTORS", "").strip() or "'self'"
    headers = {
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "same-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        # frame-src blob: lets the document viewer show a PDF the app fetched itself; the viewer only ever creates
        # blobs with a type it sets (application/pdf), never one taken from the server or the file (SC-XSS).
        "Content-Security-Policy": f"default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-src 'self' blob:; object-src 'none'; frame-ancestors {ancestors}; base-uri 'self'; form-action 'self'",
    }
    if ancestors == "'self'":
        headers["X-Frame-Options"] = "SAMEORIGIN"
    return headers


def create_app(migrate: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_app: FastAPI):  # pragma: no cover - exercised by the running server
        if migrate:
            dbmod.configure()
            dbmod.migrate()
            from keystone.frameworks.loader import sync_bundled

            with dbmod.session_scope() as s:
                sync_bundled(s)  # new framework packs and controls for existing installations (added switched off)
        from keystone.scheduler import start_scheduler, stop_scheduler

        start_scheduler()
        yield
        stop_scheduler()

    # SC-CFG-005: interactive API docs are off unless explicitly enabled (KEYSTONE_API_DOCS=1).
    docs = os.environ.get("KEYSTONE_API_DOCS", "").strip() == "1"
    app = FastAPI(title="Keystone ISMS API", version=__version__, docs_url="/api/docs" if docs else None, openapi_url="/api/openapi.json" if docs else None, redoc_url=None, lifespan=lifespan)

    headers = security_headers()

    @app.middleware("http")
    async def _headers(request: Request, call_next):
        resp = await call_next(request)
        for k, v in headers.items():
            resp.headers.setdefault(k, v)
        if request.url.path.startswith("/api/"):
            resp.headers.setdefault("Cache-Control", "no-store")
        # SC-CFG-006: HSTS on every response served over HTTPS (directly or behind the TLS proxy).
        if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return resp

    def err(status: int):
        async def handler(_req: Request, exc: Exception):
            return JSONResponse({"detail": str(exc)}, status_code=status)

        return handler

    app.add_exception_handler(PermissionDenied, err(403))
    app.add_exception_handler(AuthError, err(401))
    app.add_exception_handler(NotFound, err(404))
    app.add_exception_handler(PasswordPolicyError, err(400))
    app.add_exception_handler(AttachmentRejected, err(400))
    app.add_exception_handler(InvalidTransition, err(400))
    app.add_exception_handler(ValueError, err(400))
    app.add_exception_handler(LookupError, err(404))

    async def unexpected(request: Request, exc: Exception):
        # SC-ERR-002: no stack traces or library details to the client; the request ID links to the log.
        request_id = secrets.token_hex(8)
        _LOG.error("unhandled error %s on %s %s", request_id, request.method, request.url.path, exc_info=exc)
        return JSONResponse({"detail": "Internal error. Quote this reference to your administrator.", "request_id": request_id}, status_code=500)

    app.add_exception_handler(Exception, unexpected)

    from .routers import ROUTERS

    for r in ROUTERS:
        app.include_router(r, prefix="/api")

    @app.get("/api/health", include_in_schema=False)
    def health():
        """Liveness for load balancers and the container health check: 503 when the database can't be reached.
        Details (jobs, backups) are for administrators only, under /api/system/health."""
        from sqlalchemy import text
        from sqlalchemy.exc import SQLAlchemyError

        from keystone.core import db

        try:
            with db.engine().connect() as conn:
                conn.execute(text("SELECT 1"))
        except SQLAlchemyError:
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return {"status": "ok", "version": __version__}

    _mount_spa(app)
    return app


def _mount_spa(app: FastAPI) -> None:
    """Serve the built React app; unknown non-API paths return index.html (client-side routing)."""
    assets = WEB_DIST / "assets"
    if assets.exists():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    def spa(path: str):
        if path.startswith("api/"):
            return JSONResponse({"detail": "Not found"}, status_code=404)
        candidate = (WEB_DIST / path).resolve()
        if path and candidate.is_file() and WEB_DIST.resolve() in candidate.parents:
            return FileResponse(candidate)
        index = WEB_DIST / "index.html"
        if index.exists():
            return FileResponse(index, headers={"Cache-Control": "no-cache"})
        return JSONResponse({"detail": "Web app not built. Run: cd web && npm install && npm run build"}, status_code=503)
