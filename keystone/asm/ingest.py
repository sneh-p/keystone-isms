"""Ingest what a connector found: match devices across tools, merge properties, and work out coverage.

Matching order: the tool's own record id (seen before) -> serial number -> Entra device id -> host name (only when
exactly one device has it). Records are retired only when the source fully listed that kind of record in this run.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from keystone.core.auth import User
from keystone.core.db import utcnow

from .models import AsmDevice, AsmIdentity, AsmSetting, AsmSourceRecord, AsmVulnerability
from .vocabulary import PROPERTIES, Inventory, device_type_from, norm_hostname, norm_serial

MAX_DEVICES = 100_000
MAX_VULNS = 500_000


def _clean_props(props: dict) -> dict:
    """Keep only known device properties with values of the right type."""
    out = {}
    for k, v in (props or {}).items():
        spec = PROPERTIES.get(k)
        if spec is None or spec[0] != "device" or v is None:
            continue
        if spec[1] == "bool" and isinstance(v, bool):
            out[k] = v
        elif spec[1] == "int" and isinstance(v, (int, float)) and not isinstance(v, bool):
            out[k] = int(v)
    return out


def ingest(session: Session, integration_id: int | None, source_label: str, source_key: str, inv: Inventory, recompute_after: bool = True) -> dict:
    """Apply one connector run. Returns counts for the run summary."""
    if len(inv.devices) > MAX_DEVICES or len(inv.vulns) > MAX_VULNS:
        raise ValueError("The source returned more records than Keystone accepts in one run.")
    now = utcnow()
    devices = list(session.scalars(select(AsmDevice).where(AsmDevice.retired.is_(False))))
    by_serial = {d.serial: d for d in devices if d.serial}
    by_aad = {d.aad_device_id: d for d in devices if d.aad_device_id}
    by_host: dict[str, list[AsmDevice]] = defaultdict(list)
    for d in devices:
        if d.hostname:
            by_host[d.hostname].append(d)
    # integration_id None (CSV import) compares as IS NULL, so imported devices are matched on later imports too.
    existing = {r.external_id: r for r in session.scalars(select(AsmSourceRecord).where(AsmSourceRecord.integration_id == integration_id))}
    ext_to_device: dict[str, AsmDevice] = {}
    created = 0
    for o in inv.devices:
        serial, aad, host = norm_serial(o.serial), (o.aad_device_id or "").lower() or None, norm_hostname(o.hostname or o.name)
        rec = existing.get(o.external_id)
        dev = session.get(AsmDevice, rec.device_id) if rec else None
        if dev is None or dev.retired:
            dev = (by_serial.get(serial) if serial else None) or (by_aad.get(aad) if aad else None) or (by_host[host][0] if host and len(by_host.get(host, [])) == 1 else None)
        if dev is None:
            dev = AsmDevice(name=(o.name or host or o.external_id)[:255], first_seen=now, properties={}, device_type=o.device_type or device_type_from(o.os))
            session.add(dev)
            session.flush()
            created += 1
            devices.append(dev)
        dev.retired = False
        dev.serial = dev.serial or serial
        dev.aad_device_id = dev.aad_device_id or aad
        dev.hostname = dev.hostname or host
        dev.os = o.os or dev.os
        dev.os_version = o.os_version or dev.os_version
        if o.device_type in ("workstation", "server", "mobile"):
            dev.device_type = o.device_type
        dev.owner_email = (o.owner_email or "").strip().lower() or dev.owner_email
        if o.last_seen and (dev.last_seen is None or o.last_seen > dev.last_seen):
            dev.last_seen = o.last_seen
        for idx, key in ((by_serial, dev.serial), (by_aad, dev.aad_device_id)):
            if key:
                idx[key] = dev
        if dev.hostname and dev not in by_host[dev.hostname]:
            by_host[dev.hostname].append(dev)
        if rec is None:
            rec = AsmSourceRecord(integration_id=integration_id, external_id=o.external_id[:200], device_id=dev.id, category=o.category)
            session.add(rec)
            existing[o.external_id] = rec
        rec.device_id, rec.category, rec.properties, rec.last_seen, rec.collected_at = dev.id, o.category, _clean_props(o.props), o.last_seen, now
        ext_to_device[o.external_id] = dev
    seen_ext = {o.external_id for o in inv.devices}
    retired_records = 0
    if integration_id and "devices" in inv.complete:
        for ext, rec in list(existing.items()):
            if ext not in seen_ext:
                session.delete(rec)
                retired_records += 1
    session.flush()

    # Vulnerabilities (keyed per source, device and the tool's vulnerability id)
    vulns_open = 0
    if inv.vulns:
        current = {(v.device_id, v.vuln_key): v for v in session.scalars(select(AsmVulnerability).where(AsmVulnerability.integration_id == integration_id))}
        seen = set()
        for v in inv.vulns:
            dev = ext_to_device.get(v.device_external_id)
            if dev is None:
                continue
            k = (dev.id, v.key[:120])
            seen.add(k)
            row = current.get(k)
            if row is None:
                row = AsmVulnerability(integration_id=integration_id, device_id=dev.id, vuln_key=v.key[:120])
                session.add(row)
                current[k] = row
            row.cve, row.title, row.severity, row.cvss, row.exploitable = (v.cve or None) and v.cve[:200], (v.title or v.key)[:500], v.severity, v.cvss, bool(v.exploitable)
            row.first_seen = row.first_seen or v.first_seen or now.date()
            row.last_seen, row.state = v.last_seen or now.date(), "open"
            vulns_open += 1
        if "vulns" in inv.complete:
            for k, row in current.items():
                if k not in seen and row.state == "open":
                    row.state = "fixed"
    elif "vulns" in inv.complete:
        for row in session.scalars(select(AsmVulnerability).where(AsmVulnerability.integration_id == integration_id, AsmVulnerability.state == "open")):
            row.state = "fixed"

    # Identities
    if inv.identities or "identities" in inv.complete:
        current_ids = {i.upn: i for i in session.scalars(select(AsmIdentity).where(AsmIdentity.integration_id == integration_id))}
        seen_upn = set()
        for i in inv.identities:
            upn = i.upn.strip().lower()[:320]
            seen_upn.add(upn)
            row = current_ids.get(upn)
            if row is None:
                row = AsmIdentity(source=source_key, integration_id=integration_id, upn=upn)
                session.add(row)
                current_ids[upn] = row
            props = {k: v for k, v in (i.props or {}).items() if PROPERTIES.get(k, ("",))[0] == "identity" and v is not None}
            row.display_name, row.properties, row.collected_at = (i.display_name or "")[:255] or None, props, now
        if "identities" in inv.complete:
            for upn, row in current_ids.items():
                if upn not in seen_upn:
                    session.delete(row)

    # Settings
    if inv.settings or "settings" in inv.complete:
        current_set = {s.key: s for s in session.scalars(select(AsmSetting).where(AsmSetting.integration_id == integration_id))}
        seen_keys = set()
        for s in inv.settings:
            seen_keys.add(s.key[:200])
            row = current_set.get(s.key[:200])
            if row is None:
                row = AsmSetting(integration_id=integration_id, key=s.key[:200], title=s.title[:500])
                session.add(row)
                current_set[s.key[:200]] = row
            row.title, row.category, row.compliant, row.detail, row.collected_at = s.title[:500], s.category, s.compliant, (s.detail or "")[:4000] or None, now
        if "settings" in inv.complete:
            for k, row in current_set.items():
                if k not in seen_keys:
                    session.delete(row)
    session.flush()
    if recompute_after:
        recompute(session)
    return {"devices": len(inv.devices), "new_devices": created, "retired_records": retired_records, "vulnerabilities": vulns_open,
            "identities": len(inv.identities), "settings": len(inv.settings)}


def recompute(session: Session, on: date | None = None) -> None:
    """Merge each device's properties from its source records and work out coverage, freshness and vulnerability
    figures; link devices and identities to Keystone users by email."""
    on = on or utcnow().date()
    labels = _source_labels(session)
    records: dict[int, list[AsmSourceRecord]] = defaultdict(list)
    for r in session.scalars(select(AsmSourceRecord).order_by(AsmSourceRecord.collected_at)):
        records[r.device_id].append(r)
    vulns: dict[int, list[AsmVulnerability]] = defaultdict(list)
    for v in session.scalars(select(AsmVulnerability).where(AsmVulnerability.state == "open")):
        vulns[v.device_id].append(v)
    users = {(u.email or "").lower(): u.id for u in session.scalars(select(User).where(User.email.is_not(None)))}
    for d in session.scalars(select(AsmDevice)):
        recs = records.get(d.id, [])
        if not recs:
            d.retired = True
            continue
        merged: dict = {}
        for r in recs:  # oldest first, so the most recent report of a property wins
            src = labels.get(r.integration_id, "CSV import")
            for k, v in (r.properties or {}).items():
                merged[k] = {"value": v, "source": src, "at": r.collected_at.isoformat(timespec="minutes")}
        cats = {r.category for r in recs}

        def derived(k, v):
            merged[k] = {"value": v, "source": "Keystone", "at": None}

        for cat, prop in (("edr", "covered_by_edr"), ("rmm", "covered_by_rmm"), ("vuln", "covered_by_vuln"), ("mdm", "covered_by_mdm")):
            derived(prop, cat in cats)
        if d.last_seen:
            derived("last_seen_days", max(0, (on - d.last_seen.date()).days))
        if "vuln" in cats or vulns.get(d.id):
            open_v = vulns.get(d.id, [])
            crit = [v for v in open_v if v.severity == "critical"]
            high = [v for v in open_v if v.severity == "high"]
            derived("critical_vulns", len(crit))
            derived("high_vulns", len(high))
            derived("exploitable_vulns", sum(1 for v in open_v if v.exploitable and v.severity in ("critical", "high")))
            derived("oldest_critical_vuln_days", max([(on - v.first_seen).days for v in crit if v.first_seen] or [0]))
            derived("oldest_high_vuln_days", max([(on - v.first_seen).days for v in high if v.first_seen] or [0]))
        d.properties = merged
        d.owner_user_id = users.get(d.owner_email or "") if d.owner_email else None
    for i in session.scalars(select(AsmIdentity)):
        i.user_id = users.get(i.upn)
    session.flush()


def _source_labels(session: Session) -> dict[int | None, str]:
    from keystone.integrations.models import Integration

    return {i.id: i.name for i in session.scalars(select(Integration))} | {None: "CSV import"}


def device_count(session: Session) -> int:
    return session.scalar(select(func.count(AsmDevice.id)).where(AsmDevice.retired.is_(False))) or 0


def staleness(d: AsmDevice, now: datetime | None = None) -> int | None:
    now = now or utcnow()
    return (now - d.last_seen).days if d.last_seen else None
