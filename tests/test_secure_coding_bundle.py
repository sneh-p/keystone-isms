"""The secure coding standard bundle (.knowledge/secure-coding/) stays well-formed (OKF v0.2)."""

import re
import warnings
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

BUNDLE = Path(__file__).resolve().parents[1] / ".knowledge" / "secure-coding"
RESERVED = {"index.md", "log.md"}
CONCEPTS = sorted(p for p in BUNDLE.glob("*.md") if p.name not in RESERVED)


def frontmatter(path: Path) -> tuple[dict, str]:
    text = path.read_text(encoding="utf-8")
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    assert m, f"{path.name}: missing YAML frontmatter"
    return yaml.safe_load(m.group(1)) or {}, m.group(2)


def test_expected_files_present():
    names = {p.name for p in BUNDLE.glob("*.md")}
    expected = {"index.md", "log.md", "policy.md", "agent-conduct.md", "verification.md", "exceptions.md", "input-validation.md",
                "injection.md", "output-encoding-xss.md", "authentication.md", "authorization.md", "secrets.md", "cryptography.md",
                "dependencies.md", "errors-and-logging.md", "outbound-requests.md", "files-and-paths.md", "http-and-config.md", "llm-features.md"}
    assert names == expected


def test_only_root_index_declares_okf_version():
    meta, _ = frontmatter(BUNDLE / "index.md")
    assert meta == {"okf_version": "0.2"}
    for p in CONCEPTS:
        assert "okf_version" not in frontmatter(p)[0], p.name


@pytest.mark.parametrize("path", CONCEPTS, ids=lambda p: p.name)
def test_concept_trust_fields(path):
    meta, _ = frontmatter(path)
    assert meta.get("type"), "type is the only required OKF field"
    assert meta.get("status") in ("draft", "stable", "deprecated")
    assert "by" in meta.get("generated", {}) and "at" in meta.get("generated", {})
    if meta["status"] == "stable":  # human sign-off is what makes a concept stable
        verified = meta.get("verified") or []
        entries = verified if isinstance(verified, list) else [verified]
        assert any(isinstance(v, dict) and str(v.get("by", "")).startswith("human:") and v.get("at") for v in entries), f"{path.name}: stable needs a human verified entry"
    if meta.get("rule_prefix"):
        assert isinstance(meta.get("applies_to"), list) and meta["applies_to"], "applies_to globs tell the agent when to load it"
        assert isinstance(meta.get("load_when"), list) and meta["load_when"]


def test_links_resolve_from_bundle_root():
    for p in BUNDLE.glob("*.md"):
        _, body = frontmatter(p) if p.name != "log.md" else ({}, p.read_text(encoding="utf-8"))
        for target in re.findall(r"\]\((/[^)#\s]+)", body):
            assert (BUNDLE / target.lstrip("/")).is_file(), f"{p.name}: broken link {target}"


def test_rule_ids_unique_and_prefixed():
    seen: dict[str, str] = {}
    for p in CONCEPTS:
        meta, body = frontmatter(p)
        prefixes = [x.strip() for x in str(meta.get("rule_prefix", "")).split(",") if x.strip()]
        for rid in re.findall(r"^### (SC-[A-Z]+-\d{3})", body, re.M):
            assert rid not in seen, f"{rid} defined in {seen.get(rid)} and {p.name}"
            seen[rid] = p.name
            assert any(rid.startswith(pre + "-") for pre in prefixes), f"{rid} does not match rule_prefix of {p.name}"
    assert len(seen) >= 60


def test_cited_rule_ids_exist():
    defined = set()
    for p in CONCEPTS:
        defined |= set(re.findall(r"^### (SC-[A-Z]+-\d{3})", frontmatter(p)[1], re.M))
    root = BUNDLE.parents[1]
    for f in [*BUNDLE.glob("*.md"), root / "AGENTS.md", root / "ruff.toml", root / "web" / "eslint.config.js", root / ".semgrep" / "rules" / "secure-coding.yml"]:
        for rid in set(re.findall(r"SC-[A-Z]+-\d{3}", f.read_text(encoding="utf-8"))):
            assert rid in defined or rid == "SC-AREA-NNN", f"{f.name} cites unknown rule {rid}"


def test_stale_concepts_are_flagged():
    """A stale concept is still binding (AGENTS.md); it is flagged for AppSec review, not a blocker."""
    now = datetime.now(timezone.utc)
    for p in CONCEPTS:
        meta, _ = frontmatter(p)
        if meta.get("stale_after"):
            stale = meta["stale_after"] if isinstance(meta["stale_after"], datetime) else datetime.fromisoformat(str(meta["stale_after"]).replace("Z", "+00:00"))
            if stale.replace(tzinfo=stale.tzinfo or timezone.utc) <= now:
                warnings.warn(f"{p.name} is past stale_after ({stale:%Y-%m-%d}): AppSec should review it", stacklevel=1)
