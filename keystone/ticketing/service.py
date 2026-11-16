"""Create tickets from Keystone records, sync their status back, and (optionally) open tickets automatically.

What leaves Keystone: a title and a short description built here from the record (never free text from the request),
plus a link back to the record. Incidents send only their reference, title and severity: details stay in Keystone.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core import secrets as crypto
from keystone.core.audit import log_event
from keystone.core.db import utcnow
from keystone.core.services import authorize, get_or_404
from keystone.core.settings import get_settings
from keystone.integrations.http import ConnectorError
from keystone.integrations.models import Integration
from keystone.integrations.providers.ticketing import Ticket, TicketProvider

from .models import TicketLink

MAX_AUTO_PER_RUN = 25
MAX_SYNC_PER_RUN = 500


@dataclass(frozen=True)
class Kind:
    model: str  # import path "module:Class"
    permission: str  # needed to raise a ticket for this kind of record
    page: str


KINDS: dict[str, Kind] = {
    "task": Kind("keystone.tasks.models:Task", "task.write", "/tasks?open={id}"),
    "nonconformity": Kind("keystone.improvement.models:Nonconformity", "nc.write", "/nonconformities?open={id}"),
    "incident": Kind("keystone.incidents.models:Incident", "incident.write", "/incidents?open={id}"),
    "risk": Kind("keystone.risk.models:Risk", "risk.write", "/risks?open={id}"),
    "asm_finding": Kind("keystone.asm.models:AsmFinding", "control.write", "/attack-surface?tab=findings&finding={id}"),
    "vulnerability": Kind("keystone.asm.models:AsmVulnerability", "control.write", "/attack-surface?tab=vulnerabilities"),
}


def _model(kind: str):
    from importlib import import_module

    if kind not in KINDS:
        raise LookupError("Unknown record type")
    mod, cls = KINDS[kind].model.split(":")
    return getattr(import_module(mod), cls)


def _link(path: str) -> str:
    base = get_settings().public_url
    return f"{base}{path}" if base else f"(in Keystone: {path})"


def build(session: Session, kind: str, record) -> Ticket:
    """Title and description for a record. Kept short and factual."""
    page = _link(KINDS[kind].page.format(id=record.id))
    if kind == "vulnerability":
        from keystone.asm.models import AsmDevice

        d = session.get(AsmDevice, record.device_id)
        dev = d.name if d else "unknown device"
        lines = [f"Vulnerability on {dev}: {record.title}", f"CVE: {record.cve or 'none'}", f"Severity: {record.severity}",
                 f"Priority: {record.priority or 'not set'}{' (known exploited, CISA KEV)' if record.kev else ''}",
                 f"Fix by: {record.fix_by.isoformat() if record.fix_by else 'not set'}", f"Keystone: {page}"]
        return Ticket(f"[{record.priority or record.severity.upper()}] {record.title} on {dev}", "\n".join(lines))
    if kind == "asm_finding":
        from keystone.asm.models import Baseline

        b = session.get(Baseline, record.baseline_id)
        what = b.name if b else "baseline"
        lines = [f"Attack surface finding: {what}", f"Severity: {b.severity if b else 'unknown'}", f"Detail: {record.detail or ('no tool reports this' if record.no_data else '')}",
                 f"Since: {record.first_seen:%Y-%m-%d}", f"Keystone: {page}"]
        return Ticket(f"[{(b.severity if b else 'finding').upper()}] {what} (finding {record.id})", "\n".join(lines))
    if kind == "incident":
        return Ticket(f"[{record.severity.upper()}] Incident {record.ref}: {record.title}", f"Incident {record.ref}, severity {record.severity}, status {record.status}.\nDetails are kept in Keystone: {page}")
    title = getattr(record, "title", None) or f"{kind} {record.id}"
    desc = (getattr(record, "description", None) or "").strip()
    due = getattr(record, "due_date", None)
    lines = [f"{kind.replace('_', ' ').title()} {getattr(record, 'ref', record.id)}: {title}"]
    if desc:
        lines.append(desc[:2000])
    if due:
        lines.append(f"Due: {due.isoformat()}")
    lines.append(f"Keystone: {page}")
    return Ticket(f"{getattr(record, 'ref', '')} {title}".strip()[:250], "\n".join(lines))


def _system(session: Session, integration_id: int) -> tuple[Integration, TicketProvider, dict]:
    from keystone.integrations.service import provider

    i = get_or_404(session, Integration, integration_id)
    p = provider(i.provider)
    if not isinstance(p, TicketProvider):
        raise ValueError("That integration isn't a ticketing system.")
    if not i.enabled:
        raise ValueError(f"{i.name} is paused.")
    secrets = json.loads(crypto.decrypt(i.secret_enc)) if i.secret_enc else {}
    return i, p, secrets


def systems(session: Session, actor) -> list[dict]:
    from keystone.integrations.service import PROVIDERS

    authorize(session, actor, "read")
    return [{"id": i.id, "name": i.name, "provider": i.provider} for i in session.scalars(select(Integration).where(Integration.enabled.is_(True)).order_by(Integration.name))
            if isinstance(PROVIDERS.get(i.provider), TicketProvider)]


def links(session: Session, actor, kind: str, record_ids: list[int]) -> list[dict]:
    authorize(session, actor, "read")
    if kind not in KINDS:
        raise LookupError("Unknown record type")
    names = {i.id: i.name for i in session.scalars(select(Integration))}
    rows = session.scalars(select(TicketLink).where(TicketLink.record_type == kind, TicketLink.record_id.in_(record_ids[:1000])))
    return [{"id": t.id, "record_id": t.record_id, "system": names.get(t.integration_id), "key": t.external_key, "url": t.url, "state": t.state,
             "automatic": t.automatic, "created_at": t.created_at, "closed_at": t.closed_at} for t in rows]


def _create(session: Session, actor, i: Integration, p: TicketProvider, secrets: dict, kind: str, record, automatic: bool = False) -> TicketLink:
    existing = session.scalar(select(TicketLink).where(TicketLink.integration_id == i.id, TicketLink.record_type == kind, TicketLink.record_id == record.id))
    if existing is not None:
        raise ValueError(f"This record already has ticket {existing.external_key} in {i.name}.")
    t = build(session, kind, record)
    created = p.create(p.api(i.config or {}, secrets), p.base(i.config or {}), i.config or {}, t)
    link = TicketLink(integration_id=i.id, record_type=kind, record_id=record.id, external_id=created.external_id[:64], external_key=created.key[:64],
                      url=created.url[:500] if created.url else None, automatic=automatic)
    session.add(link)
    session.flush()
    log_event(session, actor, "ticket_created", "TicketLink", link.id, f"{i.name} {created.key} for {kind} {record.id}" + (" (automatic)" if automatic else ""))
    return link


def create_ticket(session: Session, actor, integration_id: int, kind: str, record_id: int) -> TicketLink:
    if kind not in KINDS:
        raise LookupError("Unknown record type")
    authorize(session, actor, KINDS[kind].permission)
    record = get_or_404(session, _model(kind), record_id)
    i, p, secrets = _system(session, integration_id)
    return _create(session, actor, i, p, secrets, kind, record)


def sync(session: Session, i: Integration, p: TicketProvider, secrets: dict) -> dict:
    """Read the status of open tickets, mark closed ones and tell whoever raised them, then open automatic tickets."""
    from keystone.notifications.models import Notification

    out = {"checked": 0, "closed": 0, "created": 0, "errors": 0}
    api, base, cfg = p.api(i.config or {}, secrets), p.base(i.config or {}), i.config or {}
    now = utcnow()
    for link in list(session.scalars(select(TicketLink).where(TicketLink.integration_id == i.id, TicketLink.state == "open").order_by(TicketLink.last_synced_at.is_not(None), TicketLink.last_synced_at).limit(MAX_SYNC_PER_RUN))):
        try:
            closed = p.is_closed(api, base, cfg, link.external_id)
        except ConnectorError:
            out["errors"] += 1
            continue
        link.last_synced_at = now
        out["checked"] += 1
        if closed:
            link.state, link.closed_at = "closed", now
            out["closed"] += 1
            if link.created_by_id:
                session.add(Notification(user_id=link.created_by_id, key=f"ticket:{link.id}:closed", kind="ticket", title=f"{i.name} {link.external_key} was closed",
                                         page=KINDS[link.record_type].page.format(id=link.record_id)[:200], created_at=now))
    mode = cfg.get("auto_create") or ""
    if mode:
        from keystone.asm.models import AsmVulnerability

        wanted = ("P1",) if mode == "known_exploited" else ("P1", "P2")
        linked = set(session.scalars(select(TicketLink.record_id).where(TicketLink.integration_id == i.id, TicketLink.record_type == "vulnerability")))
        for v in session.scalars(select(AsmVulnerability).where(AsmVulnerability.state == "open", AsmVulnerability.priority.in_(wanted)).order_by(AsmVulnerability.fix_by)):
            if out["created"] >= MAX_AUTO_PER_RUN:
                break
            if v.id in linked:
                continue
            _create(session, None, i, p, secrets, "vulnerability", v, automatic=True)
            out["created"] += 1
    session.flush()
    return out


def describe_sync(out: dict) -> str:
    s = f"Checked {out['checked']} open ticket(s): {out['closed']} closed since last run"
    if out["created"]:
        s += f"; opened {out['created']} automatically"
    if out["errors"]:
        s += f"; {out['errors']} couldn't be read"
    return s

