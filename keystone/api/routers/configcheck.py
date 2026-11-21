"""Configuration baselines: overview, catalogue, custom checks, baselines and rules, targets, firewall uploads,
exceptions, reports, agent enrolment settings and downloads. The agent endpoints (enrol, checks, report) are in
`agent_router`: no session, rate-limited, size-capped, and authenticated by the enrolment key or a per-device token."""

import hashlib
import json
from datetime import date
from typing import Any, TypeVar

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import Field, ValidationError
from sqlalchemy.orm import Session

from keystone.configcheck import agents as agt
from keystone.configcheck import catalogue as cat
from keystone.configcheck import custom, parsers
from keystone.configcheck import service as cfg
from keystone.configcheck.models import ConfigBaseline, ConfigCustomCheck, ConfigRule, ConfigTarget
from keystone.core.audit import log_event
from keystone.core.services import get_or_404
from keystone.core.settings import get_settings
from keystone.trust.service import rate_limit

from ..deps import get_db, perm
from ..serialize import ser
from .common import In

router = APIRouter(prefix="/config", tags=["configuration"])
agent_router = APIRouter(prefix="/agent/v1", tags=["configuration-agent"])

MAX_REPORT_BYTES = 1024 * 1024  # room for an installed-software list of up to 5000 entries
TARGET = ("id", "kind", "platform", "name", "hostname", "os_name", "os_version", "agent_version", "enrolled_at", "revoked_at", "last_ip",
          "source_filename", "source_sha256", "facts_at", "created_at", "tags", "asset_id", "custom_checks", "last_seen_at", "agent_sha256", "device_id",
          "software_at", "os_release")
RULE = ("id", "baseline_id", "key", "operator", "expected", "severity", "controls", "enabled", "applies_to_tags", "remediation")
BASELINE = ("id", "name", "platform", "description", "enabled", "is_default", "scope", "created_at", "updated_at")
CHECK = ("id", "platform", "slug", "title", "description", "remediation", "probe", "params", "value_type", "default_value", "recommended", "library_key",
         "created_at", "updated_at")


def _setting_out(s: cat.Setting) -> dict:
    rec = None
    if s.recommended:
        op, exp, sev, ctl = s.recommended
        rec = {"operator": op, "expected": exp, "severity": sev, "controls": list(ctl)}
    return {"key": s.key, "type": s.type, "title": s.title, "description": s.description, "requires": s.requires, "choices": list(s.choices),
            "operators": list(cat.OPERATORS_BY_TYPE[s.type]), "recommended": rec, "custom": s.key.startswith(custom.CUSTOM_PREFIX)}


@router.get("/catalogue")
def catalogue(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return {"platforms": [{"key": p, "label": cat.PLATFORM_LABEL[p], "kind": "agent" if p in cat.AGENT_PLATFORMS else "firewall",
                           "settings": [_setting_out(s) for s in cfg.settings_map(db, p).values()]} for p in cat.PLATFORMS],
            "operators": cat.OPERATORS, "severities": list(cat.SEVERITIES)}


@router.get("/overview")
def overview(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return cfg.overview(db)


# ---- custom checks

def _check_out(db: Session, c: ConfigCustomCheck) -> dict:
    used = sorted({get_or_404(db, ConfigBaseline, r.baseline_id).name for r in cfg._rules_using(db, c)})
    return ser(c, CHECK, key=custom.CUSTOM_PREFIX + c.slug, used_by=used)


@router.get("/custom-checks")
def custom_checks(user=Depends(perm("read")), db: Session = Depends(get_db)):
    checks = cfg.custom_checks(db)
    added = {(c.platform, c.slug) for c in checks}
    return {"checks": [_check_out(db, c) for c in checks], "probes": custom.probes_out(),
            "library": [{**e, "added": (e["platform"], e["slug"]) in added} for e in custom.library()]}


class CustomCheckIn(In):
    platform: str | None = Field(None, max_length=20)
    slug: str | None = Field(None, max_length=41)
    title: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, max_length=4000)
    remediation: str | None = Field(None, max_length=4000)
    probe: str | None = Field(None, max_length=40)
    params: dict[str, str] | None = Field(None, max_length=10)
    value_type: str | None = Field(None, max_length=10)
    default_value: int | str | None = None
    recommended: dict[str, Any] | None = None


@router.post("/custom-checks")
def create_custom_check(body: CustomCheckIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return _check_out(db, cfg.save_custom_check(db, user, **body.model_dump()))


@router.patch("/custom-checks/{cid}")
def update_custom_check(cid: int, body: CustomCheckIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return _check_out(db, cfg.save_custom_check(db, user, cid, **body.model_dump(exclude_unset=True)))


@router.delete("/custom-checks/{cid}")
def delete_custom_check(cid: int, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    cfg.delete_custom_check(db, user, cid)
    return {"ok": True}


@router.post("/custom-checks/library/{key}")
def add_library_check(key: str, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    if not custom.SLUG_RE.match(key):
        raise LookupError("No such library check.")
    return _check_out(db, cfg.add_from_library(db, user, key))


# ---- baselines and rules

def _rule_out(r: ConfigRule, settings: dict[str, cat.Setting]) -> dict:
    s = settings.get(r.key)
    rec = s.recommended if s else None
    recommended, is_recommended = None, False
    if rec is not None:
        recommended = cat.describe_expected(rec[0], rec[1])
        is_recommended = (r.operator, r.expected, r.severity) == (rec[0], rec[1], rec[2])
    return ser(r, RULE, title=s.title if s else r.key, custom=r.key.startswith(custom.CUSTOM_PREFIX), rule=cat.describe_expected(r.operator, r.expected),
               recommended=recommended, is_recommended=is_recommended)


@router.get("/baselines")
def baselines(user=Depends(perm("read")), db: Session = Depends(get_db)):
    out = []
    for b in cfg.baselines(db):
        rs = cfg.rules(db, b.id)
        out.append(ser(b, BASELINE, rules=len(rs), enabled_rules=sum(1 for r in rs if r.enabled)))
    return out


@router.get("/baselines/{bid}")
def baseline(bid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    b = get_or_404(db, ConfigBaseline, bid)
    settings = cfg.settings_map(db, b.platform)
    return ser(b, BASELINE, rules=[_rule_out(r, settings) for r in cfg.rules(db, b.id)])


class ScopeIn(In):
    tags: list[str] = Field(default_factory=list, max_length=20)
    names: list[str] = Field(default_factory=list, max_length=20)


class BaselineIn(In):
    name: str = Field(min_length=1, max_length=200)
    platform: str = Field(max_length=20)
    description: str | None = Field(None, max_length=4000)
    recommended: bool = True
    is_default: bool | None = None
    scope: ScopeIn | None = None


@router.post("/baselines")
def create_baseline(body: BaselineIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    data = body.model_dump()
    b = cfg.create_baseline(db, user, **data)
    return ser(b, BASELINE)


class BaselinePatch(In):
    name: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, max_length=4000)
    enabled: bool | None = None
    is_default: bool | None = None
    scope: ScopeIn | None = None
    clear_scope: bool = False


@router.patch("/baselines/{bid}")
def update_baseline(bid: int, body: BaselinePatch, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return ser(cfg.update_baseline(db, user, bid, **body.model_dump(exclude_unset=True)), BASELINE)


class CloneIn(In):
    name: str | None = Field(None, max_length=200)


@router.post("/baselines/{bid}/clone")
def clone_baseline(bid: int, body: CloneIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return ser(cfg.clone_baseline(db, user, bid, body.name), BASELINE)


@router.get("/baselines/{bid}/export")
def export_baseline(bid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    data = cfg.export_baseline(db, user, bid)
    log_event(db, user, "export", "ConfigBaseline", bid, f"Exported baseline {data['baseline']['name']}")
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in data["baseline"]["name"])[:60] or "baseline"
    return Response(json.dumps(data, indent=2, default=str), media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{safe}.json"'})


class ImportIn(In):
    format: str = Field(max_length=60)
    version: int
    baseline: dict[str, Any]
    rules: list[dict[str, Any]] = Field(default_factory=list, max_length=200)
    custom_checks: list[dict[str, Any]] = Field(default_factory=list, max_length=100)


@router.post("/baselines/import")
def import_baseline(body: ImportIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    b, notes = cfg.import_baseline(db, user, body.model_dump())
    return {"baseline": ser(b, BASELINE), "notes": notes}


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
    applies_to_tags: list[str] | None = Field(None, max_length=20)
    remediation: str | None = Field(None, max_length=4000)


@router.post("/baselines/{bid}/rules")
def add_rule(bid: int, body: RuleIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    r = cfg.save_rule(db, user, baseline_id=bid, **body.model_dump())
    return _rule_out(r, cfg.settings_map(db, get_or_404(db, ConfigBaseline, bid).platform))


class RulePatch(In):
    operator: str | None = Field(None, max_length=10)
    expected: bool | int | str | list[str] | None = None
    severity: str | None = Field(None, max_length=10)
    controls: list[str] | None = Field(None, max_length=20)
    enabled: bool | None = None
    applies_to_tags: list[str] | None = Field(None, max_length=20)
    remediation: str | None = Field(None, max_length=4000)


@router.patch("/rules/{rid}")
def update_rule(rid: int, body: RulePatch, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    r = cfg.save_rule(db, user, rule_id=rid, **body.model_dump(exclude_unset=True))
    return _rule_out(r, cfg.settings_map(db, get_or_404(db, ConfigBaseline, r.baseline_id).platform))


@router.post("/rules/{rid}/reset")
def reset_rule(rid: int, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    r = cfg.reset_rule(db, user, rid)
    return _rule_out(r, cfg.settings_map(db, get_or_404(db, ConfigBaseline, r.baseline_id).platform))


@router.delete("/rules/{rid}")
def delete_rule(rid: int, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    cfg.delete_rule(db, user, rid)
    return {"ok": True}


class BulkExceptionIn(In):
    reason: str = Field(min_length=1, max_length=2000)
    until: date
    target_ids: list[int] | None = Field(None, max_length=5000)


@router.post("/rules/{rid}/exceptions")
def grant_exceptions(rid: int, body: BulkExceptionIn, user=Depends(perm("risk.accept")), db: Session = Depends(get_db)):
    return {"excepted": cfg.grant_exceptions(db, user, rid, body.target_ids, body.reason, body.until)}


# ---- targets

@router.get("/targets")
def targets(user=Depends(perm("read")), db: Session = Depends(get_db)):
    s = cfg.agent_settings(db)
    files = {p: agt.agent_file(p) for p in agt.AGENT_FILES}
    return [ser(t, TARGET, **cfg.summary(db, t, s), agent=agt.state(db, t, files)) for t in cfg.targets(db)]


@router.get("/software")
def software(q: str | None = Query(None, max_length=100), limit: int = Query(200, ge=1, le=1000), user=Depends(perm("read")), db: Session = Depends(get_db)):
    return cfg.software_search(db, user, q, limit)


@router.get("/coverage")
def coverage(user=Depends(perm("read")), db: Session = Depends(get_db)):
    return agt.coverage(db)


@router.get("/targets/{tid}")
def target(tid: int, user=Depends(perm("read")), db: Session = Depends(get_db)):
    from keystone.assets.models import Asset

    t = get_or_404(db, ConfigTarget, tid)
    settings = cfg.settings_map(db, t.platform)
    checks = {custom.CUSTOM_PREFIX + c.slug: c for c in cfg.custom_checks(db, t.platform)}
    results = []
    for f in cfg.findings(db, t.id):
        r = db.get(ConfigRule, f.rule_id)
        if r is None:
            continue
        s = settings.get(r.key)
        b = db.get(ConfigBaseline, r.baseline_id)
        remediation = r.remediation or getattr(checks.get(r.key), "remediation", None)
        results.append({"id": f.id, "rule_id": r.id, "key": r.key, "title": s.title if s else r.key, "description": s.description if s else "",
                        "baseline": b.name if b else "", "baseline_id": r.baseline_id, "custom": r.key in checks,
                        "severity": r.severity, "controls": r.controls, "rule": cat.describe_expected(r.operator, r.expected), "status": f.status,
                        "actual": f.actual, "detail": f.detail, "since": f.since, "evaluated_at": f.evaluated_at, "remediation": remediation,
                        "exception_reason": f.exception_reason, "exception_until": f.exception_until})
    order = {"fail": 0, "unknown": 1, "excepted": 2, "pass": 3, "na": 4}
    sev = {s: i for i, s in enumerate(reversed(cat.SEVERITIES))}
    results.sort(key=lambda x: (order.get(str(x["status"]), 9), sev.get(str(x["severity"]), 9), str(x["title"])))
    facts = [{"key": k, "title": settings[k].title if k in settings else k, "value": v} for k, v in sorted((t.facts or {}).items())]
    hist = [ser(h, ("id", "at", "source", "baseline_id", "counts", "changes")) for h in cfg.history(db, t.id)]
    asset = db.get(Asset, t.asset_id) if t.asset_id else None
    suggestions = [] if asset else [{"id": a.id, "name": a.name} for a in cfg.suggest_assets(db, t)]
    return ser(t, TARGET, **cfg.summary(db, t), agent=agt.state(db, t), results=results, facts=facts, history=hist, check_errors=t.check_errors or {}, software=t.software or [],
               asset={"id": asset.id, "name": asset.name} if asset else None, asset_suggestions=suggestions)


class TargetPatch(In):
    name: str | None = Field(None, min_length=1, max_length=200)
    baseline_id: int | None = None
    clear_baseline: bool = False
    tags: list[str] | None = Field(None, max_length=20)
    asset_id: int | None = None
    clear_asset: bool = False


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


@router.get("/report.xlsx")
def report_xlsx(baseline_id: int | None = Query(None), target_id: int | None = Query(None), user=Depends(perm("read")), db: Session = Depends(get_db)):
    from keystone.reporting.exports import xlsx

    headers, rows = cfg.compliance_rows(db, user, baseline_id, target_id)
    data = xlsx({"Results": (headers, rows)}, title="Configuration compliance")
    log_event(db, user, "export", "ConfigReport", None, f"Configuration compliance report ({len(rows)} result(s))")
    return Response(data, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": 'attachment; filename="configuration-compliance.xlsx"'})


# ---- agent settings and downloads (integration.manage)

def _server(request: Request) -> str:
    return get_settings().public_url or str(request.base_url).rstrip("/")


PIN_HINT = {"linux": "--pin sha256//BASE64", "macos": "--pin sha256//BASE64", "windows": "-Pin sha256//BASE64"}


def _agent_view(db: Session, user, request: Request, key: str) -> dict:
    s = cfg.agent_settings(db)
    server = _server(request)
    current = agt.record_releases(db)
    sha = {p: f.sha256 for p, f in current.items()}
    files = {p: {"filename": agt.DOWNLOAD_NAMES[p], "sha256": f.sha256.upper(), "size": len(f.data), "version": f.version, "signed": f.signed} for p, f in current.items()}
    left = None if s.enrollment_max_uses is None else max(0, s.enrollment_max_uses - (s.enrollment_uses or 0))
    return {"server": server, "https": server.startswith("https://"), "enrolment_key": key, "rotated_at": s.rotated_at, "report_hours": s.report_hours, "files": files,
            "limits": {"expires_at": s.enrollment_expires_at, "days": s.enrollment_days, "max_uses": s.enrollment_max_uses, "uses": s.enrollment_uses or 0, "uses_left": left,
                       "expired": bool(s.enrollment_expires_at and s.enrollment_expires_at < cfg.utcnow()), "used_up": left == 0},
            "install": {
                "windows": f'powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\keystone-agent.ps1 -Install -Server "{server}" -EnrolmentKey "{key}"',
                "linux": f'sudo KEYSTONE_ENROLMENT_KEY="{key}" sh ./keystone-agent.sh install --server "{server}"',
                "macos": f'sudo KEYSTONE_ENROLMENT_KEY="{key}" sh ./keystone-agent-macos.sh install --server "{server}"'},
            "options": {"windows": f"-Tags web,dmz  ·  -NoCustomChecks  ·  -NoSoftware  ·  -Hours 8  ·  {PIN_HINT['windows']}",
                        "linux": f"--tags web,dmz  ·  --no-custom-checks  ·  --no-software  ·  --hours 8  ·  {PIN_HINT['linux']}",
                        "macos": f"--tags web,dmz  ·  --no-custom-checks  ·  --no-software  ·  --hours 8  ·  {PIN_HINT['macos']}"},
            "verify": {"windows": f"(Get-FileHash .\\keystone-agent.ps1 -Algorithm SHA256).Hash -eq '{sha['windows'].upper()}'",
                       "linux": f"echo '{sha['linux']}  keystone-agent.sh' | sha256sum -c -",
                       "macos": f"echo '{sha['macos']}  keystone-agent-macos.sh' | shasum -a 256 -c -"},
            "uninstall": {"windows": "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\keystone-agent.ps1 -Uninstall",
                          "linux": "sudo sh ./keystone-agent.sh uninstall", "macos": "sudo sh ./keystone-agent-macos.sh uninstall"}}


@router.get("/agent")
def agent(request: Request, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return _agent_view(db, user, request, cfg.enrolment_key(db, user))


@router.post("/agent/rotate")
def rotate(request: Request, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    return _agent_view(db, user, request, cfg.rotate_enrolment_key(db, user))


class AgentSettingsIn(In):
    report_hours: int | None = None
    key_days: int | None = Field(None, ge=1, le=cfg.MAX_KEY_DAYS)
    key_max_uses: int | None = Field(None, ge=1, le=cfg.MAX_KEY_USES)
    set_key_limits: bool = False  # true: apply key_days and key_max_uses (None in either removes that limit)


@router.patch("/agent")
def agent_settings(request: Request, body: AgentSettingsIn, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    if body.report_hours is not None:
        cfg.set_report_hours(db, user, body.report_hours)
    if body.set_key_limits:
        cfg.set_enrolment_limits(db, user, days=body.key_days, max_uses=body.key_max_uses)
    return _agent_view(db, user, request, cfg.enrolment_key(db, user))


@router.get("/agent/download/{platform}")
def download(platform: str, user=Depends(perm("integration.manage")), db: Session = Depends(get_db)):
    f = agt.agent_file(platform)
    agt.record_releases(db)
    name = agt.DOWNLOAD_NAMES[platform]
    log_event(db, user, "export", "ConfigAgent", None, f"Downloaded {name} {f.version}{' (signed)' if f.signed else ''}, SHA-256 {f.sha256}")
    return Response(f.data, media_type="text/plain; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{name}"'})


# ---- agent endpoints: no session (reviewed design, docs/feature-security-designs.md §5b)

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
    tags: list[str] | None = Field(None, max_length=20)


class CheckinIn(In):
    agent_version: str | None = Field(None, max_length=20)
    agent_sha256: str | None = Field(None, max_length=64)


class ReportIn(In):
    hostname: str | None = Field(None, max_length=253, pattern=r"^[A-Za-z0-9][A-Za-z0-9.\-_]*$")
    os_name: str | None = Field(None, max_length=200)
    os_version: str | None = Field(None, max_length=100)
    agent_version: str | None = Field(None, max_length=20)
    facts: dict[str, bool | int | str | list[str] | None] = Field(default_factory=dict, max_length=200)
    check_errors: dict[str, str] = Field(default_factory=dict, max_length=100)
    custom_checks: str | None = Field(None, max_length=10)
    agent_sha256: str | None = Field(None, max_length=64)
    software: list[list[str]] | None = Field(None, max_length=cfg.MAX_SOFTWARE)
    os_release: dict[str, str] | None = Field(None, max_length=2)


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
                             agent_version=body.agent_version, ip=_ip(request), tags=body.tags)
    except cfg.AgentRejected as e:
        return _rejected(e)
    return {"device_id": t.id, "token": token, "report_hours": cfg.agent_settings(db).report_hours}


def _device(request: Request, db: Session, bucket: str, limit: int) -> ConfigTarget:
    rate_limit(f"agent-ip:{_ip(request)}", limit=6000, window=3600)
    t = cfg.resolve_device(db, request.headers.get("authorization"))
    rate_limit(f"agent-{bucket}:{t.id}", limit=limit, window=3600)
    return t


@agent_router.get("/checks")
def checks(request: Request, fmt: str = Query("json", alias="format", pattern="^(json|lines)$"), db: Session = Depends(get_db)):
    """The custom check definitions for this device's platform: read-only probes the agent evaluates itself (each agent
    re-validates every definition and refuses anything outside its own limits)."""
    try:
        t = _device(request, db, "checks", 30)
    except PermissionError:
        return JSONResponse({"detail": "Too many requests."}, status_code=429)
    except cfg.AgentRejected as e:
        return _rejected(e)
    items = cfg.checks_for_device(db, t)
    if fmt == "lines":
        return PlainTextResponse(custom.wire_lines(items))
    return {"checks": [custom.wire(c) for c in items]}


@agent_router.post("/checkin")
async def checkin(request: Request, db: Session = Depends(get_db)):
    """Hourly sign of life from agents 1.2+, between reports. Answers whether a full report is due."""
    try:
        t = _device(request, db, "checkin", 12)
    except PermissionError:
        return JSONResponse({"detail": "Too many requests."}, status_code=429)
    except cfg.AgentRejected as e:
        return _rejected(e)
    body = await _body(request, CheckinIn)
    return cfg.checkin(db, t, agent_version=body.agent_version, agent_sha256=body.agent_sha256, ip=_ip(request))


@agent_router.post("/report")
async def report(request: Request, db: Session = Depends(get_db)):
    try:
        t = _device(request, db, "device", 30)
    except PermissionError:
        return JSONResponse({"detail": "Too many requests."}, status_code=429)
    except cfg.AgentRejected as e:
        return _rejected(e)
    body = await _body(request, ReportIn)
    return cfg.report(db, t, facts=body.facts, hostname=body.hostname, os_name=body.os_name, os_version=body.os_version, agent_version=body.agent_version,
                      ip=_ip(request), check_errors=body.check_errors, custom_checks_state=body.custom_checks, agent_sha256=body.agent_sha256,
                      software=body.software, os_release=body.os_release)
