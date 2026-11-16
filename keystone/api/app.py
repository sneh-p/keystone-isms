"""Keystone ISMS web API + single-page app."""

from __future__ import annotations

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

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "SAMEORIGIN",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors *; base-uri 'self'; form-action 'self'",
}


def create_app(migrate: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_app: FastAPI):  # pragma: no cover - exercised by the running server
        if migrate:
            dbmod.configure()
            dbmod.migrate()
        from keystone.scheduler import start_scheduler, stop_scheduler

        start_scheduler()
        yield
        stop_scheduler()

    app = FastAPI(title="Keystone ISMS API", version=__version__, docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None, lifespan=lifespan)

    @app.middleware("http")
    async def _headers(request: Request, call_next):
        resp = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        if request.url.path.startswith("/api/"):
            resp.headers.setdefault("Cache-Control", "no-store")
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

    from .routers import ROUTERS

    for r in ROUTERS:
        app.include_router(r, prefix="/api")

    @app.get("/api/health", include_in_schema=False)
    def health():
        return {"status": "ok", "version": __version__}

    _mount_spa(app)
    return app


def _mount_spa(app: FastAPI) -> None:
    """Serve the built React app; unknown non-API paths return index.html (client-side routing)."""
    assets = WEB_DIST / "assets"
    if assets.exists():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
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
