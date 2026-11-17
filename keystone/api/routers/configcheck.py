"""Configuration baselines: overview, catalogue, baselines and rules, targets, firewall uploads, exceptions, agent
enrolment settings and downloads. The agent endpoints (enrol, report) are in `agent_router`: no session, rate-limited,
size-capped, and authenticated by the enrolment key or a per-device token."""

import hashlib
import json
from datetime import date
from typing import TypeVar

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from pydantic import Field, ValidationError
from sqlalchemy.orm import Session

from keystone.configcheck import catalogue as cat
from keystone.configcheck import parsers
from keystone.configcheck import service as cfg
from keystone.core.audit import log_event
from keystone.core.services import get_or_404
from keystone.core.settings import PROJECT_ROOT, get_settings
from keystone.trust.service import rate_limit

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(prefix="/config", tags=["configuration"])
agent_router = APIRouter(prefix="/agent/v1", tags=["configuration-agent"])

AGENTS_DIR = PROJECT_ROOT / "agents"
AGENT_FILES = {"windows": ("windows", "keystone-agent.ps1"), "linux": ("linux", "keystone-agent.sh")}
MAX_REPORT_BYTES = 256 * 1024
TARGET = ("id", "kind", "platform", "name", "hostname", "os_name", "os_version", "agent_version", "enrolled_at", "revoked_at", "last_ip",
          "source_filename", "source_sha256", "facts_at", "created_at")
RULE = ("id", "baseline_id", "key", "operator", "expected", "severity", "controls", "enabled")
BASELINE = ("id", "name", "platform", "description", "enabled", "is_default", "created_at", "updated_at")


def _setting_out(s: cat.Setting) -> dict:
    rec = None
    if s.recommended:
        op, exp, sev, ctl = s.recommended
        rec = {"operator": op, "expected": exp, "severity": sev, "controls": list(ctl)}
    return {"key": s.key, "type": s.type, "title": s.title, "description": s.description, "requires": s.requires, "choices": list(s.choices),
            "operators": list(cat.OPERATORS_BY_TYPE[s.type]), "recommended": rec}


@router.get("/catalogue")
def catalogue(user=Depends(perm("read"))):
    return {"platforms": [{"key": p, "label": cat.PLATFORM_LABEL[p], "kind": "agent" if p in cat.AGENT_PLATFORMS else "firewall",
                           "settings": [_setting_out(s) for s in cat.settings_for(p)]} for p in cat.PLATFORMS],
            "operators": cat.OPERATORS, "severities": list(cat.SEVERITIES)}


@router.get("/overview")
def overview(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return cfg.overview(db)


# ---- baselines and rules

def _title(platform: str, key: str) -> str:
    s = cat.setting(platform, key)
    return s.title if s else key


def _rule_out(r, platform: str) -> dict:
    s = cat.setting(platform, r.key)
    return ser(r, RULE, title=s.title if s else r.key, rule=cat.describe_expected(r.operator, r.expected))


@router.get("/baselines")
def baselines(user=Depends(perm("read")), db: Session = Depends(get_db)):
    out = []
    for b in cfg.baselines(db):
        rs = cfg.rules(db, b.id)
        out.append(ser(b, BASELINE, rules=len(rs), enabled_rules=sum(1 for r in rs if r.enabled)))
    return out


@router.get("/baselines/{bid}")
def baseline(bid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    from keystone.configcheck.models import ConfigBaseline

    b = get_or_404(db, ConfigBaseline, bid)
    return ser(b, BASELINE, rules=[_rule_out(r, b.platform) for r in cfg.rules(db, b.id)])


class BaselineIn(In):
    name: str = Field(min_length=1, max_length=200)
    platform: str = Field(max_length=20)
    description: str | None = Field(None, max_length=4000)
    recommended: bool = True
    is_default: bool | None = None


@router.post("/baselines")
def create_baseline(body: BaselineIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    b = cfg.create_baseline(db, user, **body.model_dump())
    return ser(b, BASELINE)


class BaselinePatch(In):
    name: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, max_length=4000)
    enabled: bool | None = None
    is_default: bool | None = None


@router.patch("/baselines/{bid}")
def update_baseline(bid: int, body: BaselinePatch, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return ser(cfg.update_baseline(db, user, bid, **body.model_dump(exclude_unset=True)), BASELINE)


@router.delete("/baselines/{bid}")
def delete_baseline(bid: int, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    cfg.delete_baseline(db, user, bid)
    return {"ok": True}


class RuleIn(In):
    key: str = Field(min_length=1, max_length=60)
    operator: str | None = Field(None, max_length=10)
    expected: bool | int | str | list[str] | None = None
    severity: str = Field("medium", max_length=10)
    controls: list[str] = Field(default_factory=list, max_length=20)
    enabled: bool = True


@router.post("/baselines/{bid}/rules")
def add_rule(bid: int, body: RuleIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    from keystone.configcheck.models import ConfigBaseline

    r = cfg.save_rule(db, user, baseline_id=bid, **body.model_dump())
    return _rule_out(r, get_or_404(db, ConfigBaseline, bid).platform)


class RulePatch(In):
    operator: str | None = Field(None, max_length=10)
    expected: bool | int | str | list[str] | None = None
    severity: str | None = Field(None, max_length=10)
    controls: list[str] | None = Field(None, max_length=20)
    enabled: bool | None = None


@router.patch("/rules/{rid}")
def update_rule(rid: int, body: RulePatch, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    from keystone.configcheck.models import ConfigBaseline

    r = cfg.save_rule(db, user, rule_id=rid, **body.model_dump(exclude_unset=True))
    return _rule_out(r, get_or_404(db, ConfigBaseline, r.baseline_id).platform)


@router.delete("/rules/{rid}")
def delete_rule(rid: int, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    cfg.delete_rule(db, user, rid)
    return {"ok": True}


# ---- targets

@router.get("/targets")
def targets(user=Depends(perm("read")), db: Session = Depends(get_db)):
    s = cfg.agent_settings(db)
    return [ser(t, TARGET, **cfg.summary(db, t, s)) for t in cfg.targets(db)]


@router.get("/targets/{tid}")
def target(tid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    from keystone.configcheck.models import ConfigRule, ConfigTarget

    t = get_or_404(db, ConfigTarget, tid)
    results = []
    for f in cfg.findings(db, t.id):
        r = db.get(ConfigRule, f.rule_id)
        if r is None:
            continue
        s = cat.setting(t.platform, r.key)
        results.append({"id": f.id, "rule_id": r.id, "key": r.key, "title": s.title if s else r.key, "description": s.description if s else "",
                        "severity": r.severity, "controls": r.controls, "rule": cat.describe_expected(r.operator, r.expected), "status": f.status,
                        "actual": f.actual, "detail": f.detail, "since": f.since, "evaluated_at": f.evaluated_at,
                        "exception_reason": f.exception_reason, "exception_until": f.exception_until})
    order = {"fail": 0, "unknown": 1, "excepted": 2, "pass": 3, "na": 4}
    sev = {s: i for i, s in enumerate(reversed(cat.SEVERITIES))}
    results.sort(key=lambda x: (order.get(str(x["status"]), 9), sev.get(str(x["severity"]), 9), str(x["title"])))
    facts = [{"key": k, "title": _title(t.platform, k), "value": v} for k, v in sorted((t.facts or {}).items())]
    hist = [ser(h, ("id", "at", "source", "baseline_id", "counts", "changes")) for h in cfg.history(db, t.id)]
    return ser(t, TARGET, **cfg.summary(db, t), results=results, facts=facts, history=hist)


class TargetPatch(In):
    name: str | None = Field(None, min_length=1, max_length=200)
    baseline_id: int | None = None
    clear_baseline: bool = False


@router.patch("/targets/{tid}")
def update_target(tid: int, body: TargetPatch, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return ser(cfg.update_target(db, user, tid, **body.model_dump(exclude_unset=True)), TARGET)


@router.post("/targets/{tid}/revoke")
def revoke_target(tid: int, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return ser(cfg.revoke_target(db, user, tid), TARGET)


@router.delete("/targets/{tid}")
def delete_target(tid: int, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    cfg.delete_target(db, user, tid)
    return {"ok": True}


@router.post("/firewalls")
async def upload_firewall(platform: str = Form(..., max_length=20), file: UploadFile = File(...), name: str | None = Form(None, max_length=200),
                          target_id: int | None = Form(None), user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    data = await file.read(parsers.MAX_BYTES + 1)  # SC-FILE-002: bounded read; the file is parsed in memory, never stored
    t, result, notes = cfg.upload_firewall(db, user, platform=platform, filename=file.filename or "config", data=data, target_id=target_id, name=name)
    return {"target": ser(t, TARGET), "result": result, "notes": notes}


class ExceptionIn(In):
    reason: str = Field(min_length=1, max_length=2000)
    until: date


@router.post("/findings/{fid}/exception")
def grant_exception(fid: int, body: ExceptionIn, user=Depends(perm("risk.accept")), db: Session = Depends(get_db)):
    f = cfg.grant_exception(db, user, fid, body.reason, body.until)
    return {"id": f.id, "status": f.status, "exception_until": f.exception_until}


@router.post("/findings/{fid}/exception/revoke")
def revoke_exception(fid: int, user=Depends(perm("risk.accept")), db: Session = Depends(get_db)):
    f = cfg.revoke_exception(db, user, fid)
    return {"id": f.id, "status": f.status}


# ---- agent settings and downloads (integration.manage)

def _server(request: Request) -> str:
    return get_settings().public_url or str(request.base_url).rstrip("/")


def _agent_file(platform: str) -> bytes:
    if platform not in AGENT_FILES:
        raise LookupError("Unknown agent.")
    folder, name = AGENT_FILES[platform]
    return (AGENTS_DIR / folder / name).read_bytes()


def _agent_view(db: Session, user, request: Request, key: str) -> dict:
    s = cfg.agent_settings(db)
    server = _server(request)
    files = {}
    for p, (_, name) in AGENT_FILES.items():
        data = _agent_file(p)
        files[p] = {"filename": name, "sha256": hashlib.sha256(data).hexdigest().upper(), "size": len(data)}
    return {"server": server, "https": server.startswith("https://"), "enrolment_key": key, "rotated_at": s.rotated_at, "report_hours": s.report_hours, "files": files,
            "install": {
                "windows": f'powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\keystone-agent.ps1 -Install -Server "{server}" -EnrolmentKey "{key}"',
                "linux": f'sudo KEYSTONE_ENROLMENT_KEY="{key}" sh ./keystone-agent.sh install --server "{server}"'},
            "uninstall": {"windows": "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\keystone-agent.ps1 -Uninstall",
                          "linux": "sudo sh ./keystone-agent.sh uninstall"}}


@router.get("/agent")
def agent(request: Request, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return _agent_view(db, user, request, cfg.enrolment_key(db, user))


@router.post("/agent/rotate")
def rotate(request: Request, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return _agent_view(db, user, request, cfg.rotate_enrolment_key(db, user))


class AgentSettingsIn(In):
    report_hours: int


@router.patch("/agent")
def agent_settings(body: AgentSettingsIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    s = cfg.set_report_hours(db, user, body.report_hours)
    return {"report_hours": s.report_hours}


@router.get("/agent/download/{platform}")
def download(platform: str, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    data = _agent_file(platform)
    name = AGENT_FILES[platform][1]
    log_event(db, user, "export", "ConfigAgent", None, f"Downloaded {name}")
    return Response(data, media_type="text/plain; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{name}"'})


# ---- agent endpoints: no session (reviewed design, docs/feature-security-designs.md)

def _ip(request: Request) -> str:
    return request.client.host if request.client else "?"


B = TypeVar("B", bound=In)


async def _body(request: Request, model: type[B]) -> B:
    """Read at most MAX_REPORT_BYTES (streamed, so an oversized body is refused without being held in memory)."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_REPORT_BYTES:
        raise HTTPException(413, "Report too large.")
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_REPORT_BYTES:
            raise HTTPException(413, "Report too large.")
        chunks.append(chunk)
    raw = b"".join(chunks)
    try:
        return model.model_validate(json.loads(raw or b"{}"))
    except (ValueError, ValidationError):
        raise HTTPException(422, "Invalid request body.") from None


class EnrolIn(In):
    enrolment_key: str = Field(min_length=1, max_length=100)
    hostname: str = Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9][A-Za-z0-9.\-_]*$")
    platform: str = Field(max_length=20)
    os_name: str | None = Field(None, max_length=200)
    os_version: str | None = Field(None, max_length=100)
    agent_version: str | None = Field(None, max_length=20)


class ReportIn(In):
    hostname: str | None = Field(None, max_length=253, pattern=r"^[A-Za-z0-9][A-Za-z0-9.\-_]*$")
    os_name: str | None = Field(None, max_length=200)
    os_version: str | None = Field(None, max_length=100)
    agent_version: str | None = Field(None, max_length=20)
    facts: dict[str, bool | int | str | list[str] | None] = Field(default_factory=dict, max_length=200)


def _rejected(e: cfg.AgentRejected) -> JSONResponse:
    return JSONResponse({"detail": e.detail}, status_code=e.status)


@agent_router.post("/enrol")
async def enrol(request: Request, db: Session = Depends(get_db)):
    try:
        rate_limit(f"agent-enrol:{_ip(request)}", limit=30, window=3600)
    except PermissionError:
        return JSONResponse({"detail": "Too many requests."}, status_code=429)
    body = await _body(request, EnrolIn)
    try:
        t, token = cfg.enrol(db, key=body.enrolment_key, hostname=body.hostname, platform=body.platform, os_name=body.os_name, os_version=body.os_version,
                             agent_version=body.agent_version, ip=_ip(request))
    except cfg.AgentRejected as e:
        return _rejected(e)
    return {"device_id": t.id, "token": token, "report_hours": cfg.agent_settings(db).report_hours}


@agent_router.post("/report")
async def report(request: Request, db: Session = Depends(get_db)):
    ip = _ip(request)
    try:
        rate_limit(f"agent-ip:{ip}", limit=6000, window=3600)
        t = cfg.resolve_device(db, request.headers.get("authorization"))
        rate_limit(f"agent-device:{t.id}", limit=30, window=3600)
    except PermissionError:
        return JSONResponse({"detail": "Too many requests."}, status_code=429)
    except cfg.AgentRejected as e:
        return _rejected(e)
    body = await _body(request, ReportIn)
    return cfg.report(db, t, facts=body.facts, hostname=body.hostname, os_name=body.os_name, os_version=body.os_version, agent_version=body.agent_version, ip=ip)
