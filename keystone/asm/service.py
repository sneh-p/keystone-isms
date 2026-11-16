"""Attack surface: what the screens read, and the CSV device import."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.services import authorize, get_or_404

from . import baselines as bl
from .ingest import ingest, recompute
from .models import AsmDevice, AsmFinding, AsmIdentity, AsmSetting, AsmSourceRecord, AsmVulnerability, Baseline
from .vocabulary import PROPERTIES, DeviceObs, Inventory, device_type_from


def _sources(session: Session) -> list[dict]:
    from keystone.integrations import service as integ
    from keystone.integrations.models import Integration
    from keystone.integrations.providers.base import InventoryProvider

    out = []
    for i in session.scalars(select(Integration).order_by(Integration.name)):
        p = integ.PROVIDERS.get(i.provider)
        if isinstance(p, InventoryProvider):
            out.append({"id": i.id, "name": i.name, "provider": p.name, "categories": list(p.categories or (p.category,)), "enabled": i.enabled,
                        "last_run_at": i.last_run_at, "last_status": i.last_status, "last_error": i.last_error})
    return out


def overview(session: Session, actor) -> dict:
    authorize(session, actor, "read")
    devices = [d for d in session.scalars(select(AsmDevice).where(AsmDevice.retired.is_(False)))]
    managed = [d for d in devices if d.device_type in ("workstation", "server")]

    def cov(prop):
        n = sum(1 for d in managed if (d.properties.get(prop) or {}).get("value") is True)
        return {"covered": n, "total": len(managed), "pct": round(100 * n / len(managed), 1) if managed else None}

    findings = list(session.scalars(select(AsmFinding).where(AsmFinding.status == "open")))
    blist = list(session.scalars(select(Baseline).order_by(Baseline.name)))
    sev = {b.id: b.severity for b in blist}
    by_sev = Counter(sev.get(f.baseline_id, "low") for f in findings)
    per_b: defaultdict[int, dict[str, int]] = defaultdict(lambda: {"open": 0, "excepted": 0})
    for f in session.scalars(select(AsmFinding).where(AsmFinding.status.in_(("open", "excepted")))):
        per_b[f.baseline_id][f.status if f.status == "excepted" else "open"] += 1
    rows = []
    cache = {e: bl._entities(session, e) for e in ("device", "identity", "setting")}
    for b in blist:
        in_scope = sum(1 for e in cache[b.entity] if bl._in_scope(b, e)) if b.enabled else 0
        o, x = per_b[b.id]["open"], per_b[b.id]["excepted"]
        rows.append({"id": b.id, "name": b.name, "entity": b.entity, "severity": b.severity, "enabled": b.enabled, "rule": bl.describe(b),
                     "in_scope": in_scope, "open": o, "excepted": x, "pct": round(100 * (in_scope - o) / in_scope, 1) if in_scope else None})
    identities = list(session.scalars(select(AsmIdentity)))
    enabled_ids = [i for i in identities if i.properties.get("account_enabled") is not False]
    mfa_known = [i for i in enabled_ids if "mfa_registered" in i.properties]
    vulns = Counter(v.severity for v in session.scalars(select(AsmVulnerability).where(AsmVulnerability.state == "open")))
    return {
        "devices": len(devices), "by_type": dict(Counter(d.device_type for d in devices)),
        "coverage": {k: cov(f"covered_by_{k}") for k in ("edr", "rmm", "vuln", "mdm")},
        "findings": {s: by_sev.get(s, 0) for s in ("critical", "high", "medium", "low")}, "findings_total": len(findings),
        "baselines": rows, "identities": len(identities),
        "mfa": {"registered": sum(1 for i in mfa_known if i.properties.get("mfa_registered")), "known": len(mfa_known)},
        "vulnerabilities": {s: vulns.get(s, 0) for s in ("critical", "high", "medium", "low")},
        "sources": _sources(session),
    }


def _value(d: AsmDevice, k: str):
    v = (d.properties or {}).get(k)
    return v.get("value") if isinstance(v, dict) else None


def devices(session: Session, actor, include_retired: bool = False) -> list[dict]:
    authorize(session, actor, "read")
    q = select(AsmDevice).order_by(AsmDevice.name)
    if not include_retired:
        q = q.where(AsmDevice.retired.is_(False))
    open_by_device = Counter(f.entity_id for f in session.scalars(select(AsmFinding).where(AsmFinding.status == "open", AsmFinding.entity_type == "device")))
    cats: dict[int, set] = defaultdict(set)
    for r in session.scalars(select(AsmSourceRecord)):
        cats[r.device_id].add(r.category)
    return [{"id": d.id, "name": d.name, "hostname": d.hostname, "serial": d.serial, "os": " ".join(x for x in (d.os, d.os_version) if x) or None,
             "device_type": d.device_type, "owner_email": d.owner_email, "owner_user_id": d.owner_user_id, "last_seen": d.last_seen, "retired": d.retired,
             "sources": sorted(cats.get(d.id, set())), "open_findings": open_by_device.get(d.id, 0),
             "edr": _value(d, "covered_by_edr"), "encrypted": _value(d, "disk_encrypted"), "critical_vulns": _value(d, "critical_vulns")} for d in session.scalars(q)]


def device(session: Session, actor, device_id: int) -> dict:
    authorize(session, actor, "read")
    d = get_or_404(session, AsmDevice, device_id)
    from keystone.integrations.models import Integration

    names: dict[int | None, str] = {i.id: i.name for i in session.scalars(select(Integration))}
    recs = list(session.scalars(select(AsmSourceRecord).where(AsmSourceRecord.device_id == d.id)))
    vulns = list(session.scalars(select(AsmVulnerability).where(AsmVulnerability.device_id == d.id, AsmVulnerability.state == "open").order_by(AsmVulnerability.severity, AsmVulnerability.first_seen).limit(500)))
    return {
        "id": d.id, "name": d.name, "hostname": d.hostname, "serial": d.serial, "aad_device_id": d.aad_device_id, "os": d.os, "os_version": d.os_version,
        "device_type": d.device_type, "owner_email": d.owner_email, "owner_user_id": d.owner_user_id, "first_seen": d.first_seen, "last_seen": d.last_seen, "retired": d.retired,
        "properties": [{"key": k, "label": PROPERTIES[k][2], **v} for k, v in sorted((d.properties or {}).items()) if k in PROPERTIES],
        "sources": [{"name": names.get(r.integration_id, "CSV import"), "category": r.category, "last_seen": r.last_seen, "collected_at": r.collected_at} for r in recs],
        "vulnerabilities": [{"id": v.id, "cve": v.cve, "title": v.title, "severity": v.severity, "cvss": v.cvss, "exploitable": v.exploitable, "first_seen": v.first_seen,
                             "source": names.get(v.integration_id, "")} for v in vulns],
        "findings": findings(session, actor, entity_type="device", entity_id=d.id, status=None),
    }


def identities(session: Session, actor) -> list[dict]:
    authorize(session, actor, "read")
    open_by = Counter(f.entity_id for f in session.scalars(select(AsmFinding).where(AsmFinding.status == "open", AsmFinding.entity_type == "identity")))
    return [{"id": i.id, "upn": i.upn, "display_name": i.display_name, "source": i.source, "user_id": i.user_id, **{k: i.properties.get(k) for k in ("mfa_registered", "is_admin", "account_enabled", "is_guest", "last_sign_in_days")},
             "open_findings": open_by.get(i.id, 0)} for i in session.scalars(select(AsmIdentity).order_by(AsmIdentity.upn))]


def settings(session: Session, actor) -> list[dict]:
    authorize(session, actor, "read")
    return [{"id": s.id, "key": s.key, "title": s.title, "category": s.category, "compliant": s.compliant, "detail": s.detail} for s in session.scalars(select(AsmSetting).order_by(AsmSetting.category, AsmSetting.title))]


def findings(session: Session, actor, *, status: str | None = "open", severity: str | None = None, baseline_id: int | None = None, entity_type: str | None = None, entity_id: int | None = None, limit: int = 2000) -> list[dict]:
    authorize(session, actor, "read")
    q = select(AsmFinding)
    if status:
        q = q.where(AsmFinding.status == status)
    if baseline_id:
        q = q.where(AsmFinding.baseline_id == baseline_id)
    if entity_type:
        q = q.where(AsmFinding.entity_type == entity_type)
    if entity_id:
        q = q.where(AsmFinding.entity_id == entity_id)
    bmap = {b.id: b for b in session.scalars(select(Baseline))}
    names: dict[str, dict[int, tuple[str, int | None]]] = {"device": {d.id: (d.name, d.owner_user_id) for d in session.scalars(select(AsmDevice))},
             "identity": {i.id: (i.upn, i.user_id) for i in session.scalars(select(AsmIdentity))},
             "setting": {s.id: (s.title, None) for s in session.scalars(select(AsmSetting))}}
    none_found: dict[int, tuple[str, int | None]] = {}
    out: list[dict] = []
    for f in session.scalars(q.order_by(AsmFinding.first_seen.desc()).limit(limit)):
        b = bmap.get(f.baseline_id)
        if b is None or (severity and b.severity != severity):
            continue
        label, owner = names.get(f.entity_type, none_found).get(f.entity_id, ("(removed)", None))
        out.append({"id": f.id, "baseline_id": b.id, "baseline": b.name, "severity": b.severity, "rule": bl.describe(b), "controls": b.controls,
                    "entity_type": f.entity_type, "entity_id": f.entity_id, "entity": label, "owner_user_id": owner, "status": f.status, "no_data": f.no_data,
                    "detail": f.detail, "first_seen": f.first_seen, "last_seen": f.last_seen, "resolved_at": f.resolved_at,
                    "exception_reason": f.exception_reason, "exception_by_id": f.exception_by_id, "exception_until": f.exception_until})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    out.sort(key=lambda x: (order.get(str(x["severity"]), 9), str(x["entity"])))
    return out


def baselines_list(session: Session, actor) -> list[Baseline]:
    authorize(session, actor, "read")
    return list(session.scalars(select(Baseline).order_by(Baseline.name)))


def vocabulary() -> list[dict]:
    return [{"key": k, "entity": e, "type": t, "label": label} for k, (e, t, label) in PROPERTIES.items()]


# ---- CSV import of devices (reporting/imports register "devices") -------------------------------------------

def import_device(session: Session, actor, *, name: str, hostname: str | None = None, serial: str | None = None, os: str | None = None, device_type: str | None = None,
                  owner_email: str | None = None, last_seen=None, **props) -> AsmDevice:
    """One CSV row: a device from a tool without an API. Uses the same matching as the connectors."""
    authorize(session, actor, "integration.manage")
    key = (serial or hostname or name or "").strip().lower()
    if not key:
        raise ValueError("Give the device a name, host name or serial number.")
    seen = datetime.combine(last_seen, datetime.min.time()) if last_seen else None
    obs = DeviceObs(external_id=f"csv:{key}"[:200], name=name, category="manual", hostname=hostname or name, serial=serial, os=os,
                    device_type=device_type or device_type_from(os), owner_email=owner_email, last_seen=seen, props={k: v for k, v in props.items() if v is not None})
    ingest(session, None, "CSV import", "csv", Inventory(devices=[obs]), recompute_after=False)
    return session.scalar(select(AsmSourceRecord).where(AsmSourceRecord.external_id == obs.external_id, AsmSourceRecord.integration_id.is_(None)))


def after_import(session: Session, actor) -> None:
    recompute(session)
    bl.evaluate(session, actor)
