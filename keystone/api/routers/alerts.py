"""The security alert inbox. `inbound_router` takes alerts from tools: no session; each source has its own token,
and every request is rate-limited and size-capped. The other routes are for people (incident handlers, and
integration managers for the sources)."""

import json
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import Field, ValidationError
from sqlalchemy.orm import Session

from keystone.alerts import service as al
from keystone.alerts.models import CLOSE_REASONS
from keystone.trust.service import rate_limit

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(tags=["alerts"])
inbound_router = APIRouter(prefix="/inbound", tags=["alerts (inbound)"])
MAX_ALERT_BYTES = 64 * 1024
SOURCE = ("id", "name", "kind", "enabled", "last_received_at", "received", "created_at")
ALERT = ("id", "source_id", "external_id", "title", "severity", "category", "host", "account", "description", "link", "first_seen", "last_seen", "count",
         "status", "asset_id", "owner_id", "incident_id", "close_reason", "note", "handled_by_id", "handled_at")

Severity = Literal["info", "low", "medium", "high", "critical"]
Category = Literal["phishing", "malware", "ransomware", "account_compromise", "data_breach", "unauthorised_access", "denial_of_service", "lost_or_stolen_device",
                   "misconfiguration", "vulnerability", "backup", "policy_violation", "physical", "other"]


class AlertIn(In):
    title: str = Field(min_length=1, max_length=300)
    severity: Severity
    category: Category = "other"
    external_id: str | None = Field(None, max_length=200)
    host: str | None = Field(None, max_length=253)
    account: str | None = Field(None, max_length=320)
    description: str | None = Field(None, max_length=8000)
    link: str | None = Field(None, max_length=2000, pattern=r"^https://")
    occurred_at: datetime | None = None


def _ip(request: Request) -> str:
    return request.client.host if request.client else "?"


async def _body(request: Request) -> AlertIn:
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_ALERT_BYTES:
        raise HTTPException(413, "Alert too large.")
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_ALERT_BYTES:
            raise HTTPException(413, "Alert too large.")
        chunks.append(chunk)
    try:
        return AlertIn.model_validate(json.loads(b"".join(chunks) or b"{}"))
    except (ValueError, ValidationError) as e:
        errors = e.errors(include_input=False, include_url=False) if isinstance(e, ValidationError) else "Invalid JSON."
        raise HTTPException(422, errors) from None


@inbound_router.post("/alerts")
async def receive_alert(request: Request, db: Session = Depends(get_db)):
    """An alert from a security tool. Authorization: Bearer <source token>."""
    try:
        rate_limit(f"alerts-ip:{_ip(request)}", limit=6000, window=3600)
        source = al.resolve_source(db, request.headers.get("authorization"))
        rate_limit(f"alerts-source:{source.id}", limit=1200, window=3600)
    except PermissionError:
        return JSONResponse({"detail": "Too many requests."}, status_code=429)
    except al.SourceRejected as e:
        return JSONResponse({"detail": str(e)}, status_code=401)
    body = await _body(request)
    a, new = al.receive(db, source, **body.model_dump())
    return {"id": a.id, "ref": a.ref, "new": new, "count": a.count}


# ---- sources (integration.manage) ------------------------------------------------------------------------------------

@router.get("/alert-sources")
def alert_sources(user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return {"sources": [ser(s, SOURCE) for s in al.sources(db, user)], "kinds": al.SOURCE_KINDS}


class SourceIn(In):
    name: str = Field(min_length=1, max_length=100)
    kind: Literal["edr", "siem", "email", "cloud", "identity", "backup", "other"]


@router.post("/alert-sources")
def create_alert_source(body: SourceIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    s, token = al.create_source(db, user, body.name, body.kind)
    return {**ser(s, SOURCE), "token": token}


@router.post("/alert-sources/{sid}/token")
def rotate_alert_source_token(sid: int, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    s, token = al.rotate_token(db, user, sid)
    return {**ser(s, SOURCE), "token": token}


class EnabledIn(In):
    enabled: bool


@router.put("/alert-sources/{sid}/enabled")
def enable_alert_source(sid: int, body: EnabledIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return ser(al.set_enabled(db, user, sid, body.enabled), SOURCE)


# ---- the inbox (incident.write) --------------------------------------------------------------------------------------

@router.get("/alerts")
def alerts(open_only: bool = False, user=Depends(perm("incident.write")), db: Session = Depends(get_db)):
    from keystone.alerts.models import AlertSource
    from keystone.core.auth import User

    names: dict[int | None, str] = {u.id: u.display_name for u in db.query(User).all()}
    sources = {s.id: s.name for s in db.query(AlertSource).all()}
    return {"alerts": [ser(a, ALERT, ref=a.ref, source=sources.get(a.source_id), owner=names.get(a.owner_id), handled_by=names.get(a.handled_by_id))
                       for a in al.alerts(db, user, open_only)], "close_reasons": CLOSE_REASONS}


@router.post("/alerts/{aid}/acknowledge")
def acknowledge_alert(aid: int, user=Depends(perm("incident.write")), db: Session = Depends(get_db)):
    return ser(al.acknowledge(db, user, aid), ALERT)


class AlertIncidentIn(In):
    severity: Literal["low", "medium", "high", "critical"] | None = None


@router.post("/alerts/{aid}/incident")
def alert_to_incident(aid: int, body: AlertIncidentIn, user=Depends(perm("incident.write")), db: Session = Depends(get_db)):
    i = al.to_incident(db, user, aid, body.severity)
    return {"incident_id": i.id, "ref": i.ref}


class AlertCloseIn(In):
    reason: Literal["benign", "false_positive", "resolved", "duplicate"]
    note: str = Field(min_length=1, max_length=4000)


@router.post("/alerts/{aid}/close")
def close_alert(aid: int, body: AlertCloseIn, user=Depends(perm("incident.write")), db: Session = Depends(get_db)):
    return ser(al.close(db, user, aid, body.reason, body.note), ALERT)
