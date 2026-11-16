"""CSV import for registers (assets, risks, vendors, people).

Design (SC-FILE, SC-VAL-001): the browser parses the CSV and sends the rows as JSON, so the server never receives or
parses a file. Rows are bounded at the API boundary, mapped through a fixed column list per register (unknown
columns are refused, no mass assignment), converted with strict types, and saved through the register's own
service, so every business rule, permission check and audit entry applies exactly as for a manual edit.
A preview runs the same import in a separate transaction that is always rolled back.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from typing import Callable

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from keystone.core import db as dbmod
from keystone.core.auth import User
from keystone.core.services import authorize

MAX_ROWS = 1000


@dataclass(frozen=True)
class Column:
    name: str
    kind: str = "text"  # text | int | bool | date | user | choice
    required: bool = False
    choices: tuple[str, ...] = ()
    field: str | None = None  # service field, when it differs from the column name
    help: str = ""

    def as_dict(self) -> dict:
        return {"name": self.name, "kind": self.kind, "required": self.required, "choices": list(self.choices), "help": self.help}


@dataclass(frozen=True)
class Register:
    label: str
    permission: str
    save: Callable
    columns: tuple[Column, ...]
    describe: Callable[[dict], str] = field(default=lambda v: "")
    after: Callable | None = None  # run once after all rows (e.g. re-evaluate baselines)


def all_registers() -> dict[str, Register]:
    from keystone.assets.models import ASSET_STATUSES, ASSET_TYPES, CLASSIFICATIONS
    from keystone.assets.service import save_asset
    from keystone.people.service import save_person
    from keystone.risk.models import RISK_CATEGORIES, TREATMENT_OPTIONS
    from keystone.risk.service import save_risk
    from keystone.tprm.models import ACCESS_LEVELS, CRITICALITY, SENSITIVITY, VENDOR_STATUSES
    from keystone.tprm.service import save_vendor
    from keystone.asm import service as asm

    owner = Column("owner", "user", field="owner_id", help="Username or email of a Keystone user")
    cia = "1 (low) to 5 (high)"
    return {
        "assets": Register("Assets", "asset.write", save_asset, (
            Column("name", required=True), Column("asset_type", "choice", choices=ASSET_TYPES), Column("description"), owner,
            Column("custodian"), Column("location"), Column("classification", "choice", choices=CLASSIFICATIONS),
            Column("confidentiality", "int", help=cia), Column("integrity", "int", help=cia), Column("availability", "int", help=cia),
            Column("contains_personal_data", "bool", help="yes or no"), Column("status", "choice", choices=ASSET_STATUSES), Column("tags"),
        ), lambda v: v.get("name", "")),
        "risks": Register("Risks", "risk.write", save_risk, (
            Column("title", required=True), Column("description"), Column("category", "choice", choices=RISK_CATEGORIES), owner,
            Column("threat"), Column("vulnerability"), Column("consequence"),
            Column("inherent_likelihood", "int", help="1-5"), Column("inherent_impact", "int", help="1-5"),
            Column("residual_likelihood", "int", help="1-5"), Column("residual_impact", "int", help="1-5"),
            Column("treatment_option", "choice", choices=TREATMENT_OPTIONS), Column("treatment_rationale"), Column("review_date", "date", help="YYYY-MM-DD"),
        ), lambda v: v.get("title", "")),
        "vendors": Register("Vendors", "vendor.write", save_vendor, (
            Column("name", required=True), Column("legal_name"), Column("website"), Column("description"), Column("services"), Column("category"), owner,
            Column("status", "choice", choices=VENDOR_STATUSES), Column("data_sensitivity", "choice", choices=SENSITIVITY),
            Column("operational_criticality", "choice", choices=CRITICALITY), Column("access_level", "choice", choices=ACCESS_LEVELS),
            Column("processes_personal_data", "bool", help="yes or no"), Column("dpa_signed", "bool", help="yes or no"),
            Column("contract_start", "date", help="YYYY-MM-DD"), Column("contract_end", "date", help="YYYY-MM-DD"), Column("notes"),
        ), lambda v: v.get("name", "")),
        "people": Register("People", "people.write", save_person, (
            Column("full_name", required=True), Column("email", required=True), Column("job_title"), Column("department"),
            Column("employment_type", "choice", choices=("employee", "contractor")), Column("manager", "user", field="manager_id", help="Username or email of a Keystone user"),
            Column("start_date", "date", help="YYYY-MM-DD"), Column("end_date", "date", help="YYYY-MM-DD"),
        ), lambda v: f"{v.get('full_name', '')} <{v.get('email', '')}>"),
        "devices": Register("Devices (attack surface)", "integration.manage", asm.import_device, (
            Column("name", required=True), Column("hostname"), Column("serial"), Column("os", help="e.g. Windows 11"),
            Column("device_type", "choice", choices=("workstation", "server", "mobile", "other")), Column("owner_email", help="email of the person who uses it"),
            Column("last_seen", "date", help="YYYY-MM-DD"), Column("disk_encrypted", "bool", help="yes or no"), Column("edr_active", "bool", help="yes or no"),
            Column("av_up_to_date", "bool", help="yes or no"), Column("firewall_on", "bool", help="yes or no"), Column("patches_pending", "int", help="number of security patches pending"),
        ), lambda v: v.get("name", ""), asm.after_import),
    }


def register(name: str) -> Register:
    regs = all_registers()
    if name not in regs:
        raise LookupError("Unknown register")
    return regs[name]


def spec(name: str) -> dict:
    r = register(name)
    return {"register": name, "label": r.label, "max_rows": MAX_ROWS, "columns": [c.as_dict() for c in r.columns]}


def _norm(header: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", header.strip().lower()).strip("_")


_TRUE, _FALSE = {"yes", "y", "true", "1"}, {"no", "n", "false", "0"}


def _user_id(session: Session, value: str) -> int:
    v = value.strip().lower()
    u = session.scalar(select(User).where(or_(func.lower(User.username) == v, func.lower(User.email) == v)))
    if u is None or not u.active:
        raise ValueError(f"no active user {value!r}")
    return u.id


def _convert(session: Session, col: Column, raw: str):
    v = raw.strip()
    if col.kind == "int":
        if not re.fullmatch(r"-?\d{1,6}", v):
            raise ValueError(f"{col.name}: expected a whole number, got {raw!r}")
        return int(v)
    if col.kind == "bool":
        if v.lower() in _TRUE:
            return True
        if v.lower() in _FALSE:
            return False
        raise ValueError(f"{col.name}: expected yes or no, got {raw!r}")
    if col.kind == "date":
        try:
            return date.fromisoformat(v)
        except ValueError:
            raise ValueError(f"{col.name}: expected a date as YYYY-MM-DD, got {raw!r}") from None
    if col.kind == "choice":
        c = _norm(v)
        if c not in col.choices:
            raise ValueError(f"{col.name}: {raw!r} is not one of {', '.join(col.choices)}")
        return c
    if col.kind == "user":
        try:
            return _user_id(session, v)
        except ValueError as e:
            raise ValueError(f"{col.name}: {e}") from None
    return v


def check_headers(name: str, headers: list[str]) -> list[str]:
    """Problems with the header row: unknown, duplicate or missing required columns."""
    r = register(name)
    known = {c.name for c in r.columns}
    normed = [_norm(h) for h in headers]
    problems = [f"Unknown column {h!r}" for h, n in zip(headers, normed) if n not in known]
    problems += [f"Column {n!r} appears more than once" for n in sorted({n for n in normed if normed.count(n) > 1})]
    problems += [f"Required column {c.name!r} is missing" for c in r.columns if c.required and c.name not in normed]
    return problems


def run(session: Session, actor, name: str, rows: list[dict[str, str | None]]) -> dict:
    """Import rows through the register's service. Returns per-row results; nothing is rolled back here."""
    r = register(name)
    authorize(session, actor, r.permission)
    if not rows:
        raise ValueError("The file has no data rows.")
    if len(rows) > MAX_ROWS:
        raise ValueError(f"Import at most {MAX_ROWS} rows at a time.")
    headers = list(rows[0].keys())
    problems = check_headers(name, headers)
    if problems:
        return {"header_errors": problems, "rows": [], "ok": 0, "errors": 0}
    cols = {c.name: c for c in r.columns}
    out, ok = [], 0
    for i, row in enumerate(rows, start=2):  # row 1 is the header in the user's file
        values: dict = {}
        errors: list[str] = []
        for key, raw in row.items():
            col = cols.get(_norm(key))
            if col is None:
                errors.append(f"Unknown column {key!r}")
                continue
            if raw is None or not raw.strip():
                if col.required:
                    errors.append(f"{col.name} is required")
                continue
            try:
                values[col.field or col.name] = _convert(session, col, raw)
            except ValueError as e:
                errors.append(str(e))
        if not errors:
            try:
                r.save(session, actor, **values)
                ok += 1
            except (ValueError, LookupError) as e:
                errors.append(str(e))
            except IntegrityError:
                # The transaction can't continue after a database constraint failure; report and stop.
                out.append({"row": i, "label": r.describe({k: str(v) for k, v in row.items() if v}), "errors": ["conflicts with an existing record"]})
                out += [{"row": j, "label": "", "errors": ["not checked: an earlier row failed"]} for j in range(i + 1, len(rows) + 2)]
                return {"header_errors": [], "rows": out, "ok": ok, "errors": sum(1 for x in out if x["errors"])}
        out.append({"row": i, "label": r.describe({_norm(k): v for k, v in row.items() if v}), "errors": errors})
    if r.after and ok:
        r.after(session, actor)
    return {"header_errors": [], "rows": out, "ok": ok, "errors": sum(1 for x in out if x["errors"])}


def preview(actor, name: str, rows: list[dict[str, str | None]]) -> dict:
    """Run the import in its own transaction and always roll it back: real validation, nothing saved."""
    with dbmod.rollback_scope(actor) as s:
        return run(s, actor, name, rows)


def commit(session: Session, actor, name: str, rows: list[dict[str, str | None]]) -> dict:
    """All or nothing: any row error aborts the whole import (the caller's transaction is rolled back)."""
    result = run(session, actor, name, rows)
    if result["header_errors"] or result["errors"]:
        first = result["header_errors"][:1] or [f"row {x['row']}: {'; '.join(x['errors'])}" for x in result["rows"] if x["errors"]][:1]
        raise ValueError(f"Nothing was imported. {result['errors'] or len(result['header_errors'])} problem(s), first: {first[0]}. Preview the file and fix it.")
    return result
