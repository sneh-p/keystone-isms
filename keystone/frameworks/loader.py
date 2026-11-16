"""Load framework packs, common controls and the crosswalk from content/frameworks/*.yaml.

Loading is idempotent (upsert by code/ref), so content updates can be re-applied.
Restricted-licence packs are checked so that official text cannot be shipped by accident.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from keystone.core.services import authorize
from keystone.core.settings import PROJECT_ROOT

from .models import CommonControl, ControlMapping, Framework, Requirement

CONTENT_DIR = PROJECT_ROOT / "content" / "frameworks"
PACK_FILES = ["iso27001_2022.yaml", "nist_csf_2_0.yaml", "soc2_tsc.yaml", "cis_v8_1.yaml",
              # round 3
              "nis2.yaml", "dora.yaml", "gdpr.yaml", "iso27701_2019.yaml", "iso42001_2023.yaml", "pci_dss_4_0_1.yaml",
              "cyber_essentials.yaml", "essential_eight.yaml"]
RESTRICTED_LICENSES = {"proprietary", "cc_by_nc_nd"}
MAX_SUMMARY_CHARS = 160


class ContentError(ValueError):
    pass


def read_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def check_pack(doc: dict, name: str = "pack") -> None:
    fw = doc.get("framework") or {}
    for key in ("code", "name", "version", "license", "text_level"):
        if not fw.get(key):
            raise ContentError(f"{name}: framework.{key} is required")
    reqs = doc.get("requirements") or []
    refs = [r["ref"] for r in reqs]
    if len(refs) != len(set(refs)):
        raise ContentError(f"{name}: duplicate requirement refs")
    known = set(refs)
    for r in reqs:
        if r.get("parent") and r["parent"] not in known:
            raise ContentError(f"{name}: {r['ref']} has unknown parent {r['parent']}")
        if "licensed_text" in r:
            raise ContentError(f"{name}: licensed_text must never be stored in content files")
    if fw["license"] in RESTRICTED_LICENSES:
        if fw["text_level"] != "summary":
            raise ContentError(f"{name}: restricted-licence packs must use text_level: summary")
        for r in reqs:
            for field in ("title", "description"):
                if len(str(r.get(field) or "")) > MAX_SUMMARY_CHARS:
                    raise ContentError(f"{name}: {r['ref']}.{field} is longer than {MAX_SUMMARY_CHARS} chars; restricted packs may only hold short own-words summaries")


def load_pack(session: Session, actor, doc: dict) -> Framework:
    authorize(session, actor, "framework.write")
    return _load_pack(session, doc)


def _load_pack(session: Session, doc: dict) -> Framework:
    check_pack(doc, doc.get("framework", {}).get("code", "pack"))
    meta = doc["framework"]
    fw = session.scalar(select(Framework).where(Framework.code == meta["code"]))
    if fw is None:
        fw = Framework(code=meta["code"])
        session.add(fw)
    for key in ("name", "version", "publisher", "license", "text_level", "source_url", "notice"):
        setattr(fw, key, meta.get(key))
    session.flush()
    existing = {r.ref: r for r in session.scalars(select(Requirement).where(Requirement.framework_id == fw.id))}
    parents = {r.get("parent") for r in doc["requirements"] if r.get("parent")}
    for order, item in enumerate(doc["requirements"]):
        req = existing.get(item["ref"]) or Requirement(framework_id=fw.id, ref=item["ref"])
        req.parent_ref = item.get("parent")
        req.kind = item["kind"]
        req.title = item["title"]
        req.description = item.get("description")
        req.sort_order = order
        req.is_leaf = item["ref"] not in parents
        session.add(req)
    session.flush()
    return fw


def _requirement_index(session: Session) -> dict[tuple[str, str], Requirement]:
    rows = session.execute(select(Framework.code, Requirement).join(Requirement, Requirement.framework_id == Framework.id))
    return {(code, req.ref): req for code, req in rows}


def load_controls(session: Session, actor, controls_doc: dict, crosswalk_doc: dict) -> int:
    authorize(session, actor, "framework.write")
    return _load_controls(session, controls_doc, crosswalk_doc)


def _load_controls(session: Session, controls_doc: dict, crosswalk_doc: dict) -> int:
    index = _requirement_index(session)
    by_code: dict[str, CommonControl] = {c.code: c for c in session.scalars(select(CommonControl))}
    wanted: dict[str, set[int]] = {}

    def want(code: str, fw_code: str, ref: str) -> None:
        req = index.get((fw_code, str(ref)))
        if req is None:
            raise ContentError(f"{code}: unknown requirement {fw_code} {ref}")
        if not req.is_leaf:
            raise ContentError(f"{code}: {fw_code} {ref} is a grouping, map to its children")
        wanted.setdefault(code, set()).add(req.id)

    for item in controls_doc["controls"]:
        ctl = by_code.get(item["code"]) or CommonControl(code=item["code"])
        ctl.domain, ctl.title, ctl.description = item["domain"], item["title"], item.get("description")
        session.add(ctl)
        by_code[ctl.code] = ctl
        for ref in item.get("iso", []):
            want(ctl.code, "ISO27001_2022", ref)
    for fw_code, mapping in crosswalk_doc.items():
        for ref, codes in mapping.items():
            for code in codes:
                if code not in by_code:
                    raise ContentError(f"crosswalk {fw_code} {ref}: unknown control {code}")
                want(code, fw_code, ref)
    session.flush()

    existing = {(m.common_control_id, m.requirement_id): m for m in session.scalars(select(ControlMapping))}
    count = 0
    for code, req_ids in wanted.items():
        ctl = by_code[code]
        for rid in req_ids:
            if (ctl.id, rid) not in existing:
                session.add(ControlMapping(common_control_id=ctl.id, requirement_id=rid, source="keystone"))
            count += 1
    # Remove Keystone-sourced mappings that were dropped from the content (user mappings are kept).
    for (cid, rid), m in existing.items():
        code = next((c for c, obj in by_code.items() if obj.id == cid), None)
        if m.source == "keystone" and (code is None or rid not in wanted.get(code, set())):
            session.delete(m)
    session.flush()
    return count


def seed_content(session: Session, actor, content_dir: Path = CONTENT_DIR) -> dict:
    """Load all bundled packs, controls and crosswalk. Safe to run repeatedly."""
    out = {}
    for name in PACK_FILES:
        fw = load_pack(session, actor, read_yaml(content_dir / name))
        out[fw.code] = len(fw.requirements)
    out["mappings"] = load_controls(session, actor, read_yaml(content_dir / "common_controls.yaml"), read_yaml(content_dir / "crosswalk.yaml"))
    return out


def sync_bundled(session: Session, content_dir: Path = CONTENT_DIR) -> list[str]:
    """At start-up: bring an onboarded installation up to the bundled content. Packs it doesn't have yet are added
    switched off (an administrator turns them on under Frameworks), new common controls and mappings are added, and
    nothing the organisation chose or wrote is changed. A fresh installation is left for onboarding. Returns the codes
    of packs added."""
    have = set(session.scalars(select(Framework.code)))
    if not have:
        return []
    added = []
    for name in PACK_FILES:
        doc = read_yaml(content_dir / name)
        code = doc["framework"]["code"]
        if code in have:
            continue
        fw = _load_pack(session, doc)
        fw.enabled = False
        added.append(code)
    known_controls = set(session.scalars(select(CommonControl.code)))
    controls_doc = read_yaml(content_dir / "common_controls.yaml")
    if added or {c["code"] for c in controls_doc["controls"]} - known_controls:
        _load_controls(session, controls_doc, read_yaml(content_dir / "crosswalk.yaml"))
    session.flush()
    return added


def import_licensed_text(session: Session, actor, framework_code: str, rows: list[dict]) -> dict:
    """Store official requirement text from the organisation's licensed copy.

    rows: [{"ref": "A.5.1", "text": "..."}]. Unknown refs are reported, not created.
    """
    authorize(session, actor, "framework.write")
    fw = session.scalar(select(Framework).where(Framework.code == framework_code))
    if fw is None:
        raise ContentError(f"framework {framework_code} is not loaded")
    reqs = {r.ref: r for r in fw.requirements}
    updated, unknown = 0, []
    for row in rows:
        ref, text = str(row.get("ref", "")).strip(), (row.get("text") or "").strip()
        if not ref or not text:
            continue
        if ref not in reqs:
            unknown.append(ref)
            continue
        reqs[ref].licensed_text = text
        updated += 1
    session.flush()
    return {"updated": updated, "unknown_refs": unknown}


def parse_licensed_file(name: str, data: bytes) -> list[dict]:
    """Accept CSV (ref,text) or YAML/JSON list of {ref, text}."""
    import csv
    import io
    import json

    text = data.decode("utf-8-sig")
    if name.lower().endswith(".csv"):
        return [{"ref": r.get("ref"), "text": r.get("text")} for r in csv.DictReader(io.StringIO(text))]
    if name.lower().endswith(".json"):
        return json.loads(text)
    return yaml.safe_load(text)
