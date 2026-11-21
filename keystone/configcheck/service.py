"""Configuration baselines: rules per platform, evaluation of hosts and firewalls, drift history, exceptions,
evidence and alerts; custom checks; agent enrolment and reports; firewall configuration uploads.

Results are pass, fail, unknown (the value wasn't reported or couldn't be read: never shown as passing), na (a
prerequisite setting is off, e.g. SSH settings without an SSH server) or excepted (a failing rule with an approved,
time-limited exception).

Which baselines apply to a target: the one pinned to it, or else the platform's default; plus every enabled baseline
whose scope (tags, host-name patterns) matches it. A rule can further be limited to targets with certain tags.

Agents (agents/windows, agents/linux) are report-only. They read the built-in settings and, unless the host opted out
at install, the custom checks defined here (read-only probes, see custom.py); Keystone never sends them commands. Each
agent exchanges the organisation's enrolment key for its own device token, which is stored here only as a SHA-256 hash
and can only fetch check definitions for, and post reports about, that one device.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets as pysecrets
from collections import Counter
from datetime import date, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from keystone.core import secrets as crypto
from keystone.core.audit import log_event
from keystone.core.auth import User, expired
from keystone.core.db import utcnow
from keystone.core.rbac import Role
from keystone.core.services import authorize, get_or_404, require_text, today

from . import catalogue as cat
from . import custom, parsers
from .models import ConfigAgentSettings, ConfigBaseline, ConfigCustomCheck, ConfigFinding, ConfigRule, ConfigSnapshot, ConfigTarget

DEVICE_PREFIX = "kagt_"
ENROLMENT_PREFIX = "kenr_"
MAX_TARGETS = 5000
MAX_RULES = 200
MAX_EXCEPTION_DAYS = 366
SNAPSHOTS_KEPT = 500
STALE_FACTOR = 3  # an agent is stale after missing three reports in a row
FIREWALL_STALE_DAYS = 90  # an uploaded configuration older than this is shown as out of date
TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
NAME_PATTERN_RE = re.compile(r"^[A-Za-z0-9*?._-]{1,100}$")
MAX_TAGS = 20
CHECK_ERRORS = ("refused", "missing", "unsupported", "error", "disabled")
ERROR_TEXT = {
    "refused": "Refused by the agent: the probe or its path isn't allowed on this host.",
    "missing": "Not found on the host (and the check has no default value).",
    "unsupported": "This agent version doesn't support the probe. Update the agent.",
    "error": "The agent couldn't read this value.",
    "disabled": "Custom checks are turned off on this host (installed with --no-custom-checks).",
}
EXPORT_FORMAT = "keystone-config-baseline"


# ---- helpers ------------------------------------------------------------------------------------------------------------

def _count(session: Session, query) -> int:
    return int(session.scalar(query) or 0)


def _check_platform(platform: str) -> str:
    if platform not in cat.PLATFORMS:
        raise ValueError(f"Platform must be one of {', '.join(cat.PLATFORMS)}.")
    return platform


def glob_match(text: str, pattern: str) -> bool:
    """Case-insensitive wildcard match (* and ? only), without building a regular expression from the pattern."""
    t, p = text.lower(), pattern.lower()
    ti = pi = 0
    star, mark = -1, 0
    while ti < len(t):
        if pi < len(p) and (p[pi] == "?" or p[pi] == t[ti]):
            ti, pi = ti + 1, pi + 1
        elif pi < len(p) and p[pi] == "*":
            star, mark, pi = pi, ti, pi + 1
        elif star != -1:
            pi, mark = star + 1, mark + 1
            ti = mark
        else:
            return False
    while pi < len(p) and p[pi] == "*":
        pi += 1
    return pi == len(p)


def clean_tags(tags, label: str = "Tags") -> list[str]:
    if tags is None:
        return []
    if not isinstance(tags, list) or len(tags) > MAX_TAGS:
        raise ValueError(f"{label}: at most {MAX_TAGS}.")
    out = []
    for t in tags:
        v = str(t).strip().lower()
        if not TAG_RE.match(v):
            raise ValueError(f"{label}: {v[:40]!r} isn't a tag (lower-case letters, digits, - and _; up to 40).")
        if v not in out:
            out.append(v)
    return out


def clean_scope(scope) -> dict | None:
    if not scope:
        return None
    if not isinstance(scope, dict) or set(scope) - {"tags", "names"}:
        raise ValueError("A scope has tags and host-name patterns.")
    tags = clean_tags(scope.get("tags") or [], "Scope tags")
    names = scope.get("names") or []
    if not isinstance(names, list) or len(names) > MAX_TAGS:
        raise ValueError(f"At most {MAX_TAGS} host-name patterns.")
    names = [str(n).strip() for n in names if str(n).strip()]
    for n in names:
        if not NAME_PATTERN_RE.match(n):
            raise ValueError(f"{n[:40]!r} isn't a host-name pattern (letters, digits, . - _ and the wildcards * and ?).")
    return {"tags": tags, "names": names} if (tags or names) else None


def _known_controls(session: Session, codes: list[str], drop_unknown: bool = False) -> list[str]:
    from keystone.frameworks.models import CommonControl

    known = set(session.scalars(select(CommonControl.code).where(CommonControl.code.in_(codes)))) if codes else set()
    unknown = [c for c in codes if c not in known]
    if unknown and not drop_unknown:
        raise ValueError(f"Unknown control code(s): {', '.join(unknown[:5])}.")
    return [c for c in codes if c in known]


# ---- settings: the catalogue plus custom checks -------------------------------------------------------------------------

def custom_checks(session: Session, platform: str | None = None) -> list[ConfigCustomCheck]:
    q = select(ConfigCustomCheck).order_by(ConfigCustomCheck.platform, ConfigCustomCheck.title)
    if platform:
        q = q.where(ConfigCustomCheck.platform == platform)
    return list(session.scalars(q))


def settings_map(session: Session, platform: str) -> dict[str, cat.Setting]:
    out = {s.key: s for s in cat.settings_for(platform)}
    for c in custom_checks(session, platform):
        out[custom.CUSTOM_PREFIX + c.slug] = custom.as_setting(c)
    return out


def _title(settings: dict[str, cat.Setting], key: str) -> str:
    s = settings.get(key)
    return s.title if s else key


def validate_rule(s: cat.Setting | None, platform: str, key: str, operator: str, expected, severity: str, controls: list[str]) -> tuple[str, object, str, list[str]]:
    if s is None:
        raise ValueError(f"{key!r} is not a {cat.PLATFORM_LABEL.get(platform, platform)} setting.")
    if operator not in cat.OPERATORS_BY_TYPE[s.type]:
        raise ValueError(f"For {s.title} use: {', '.join(cat.OPERATORS[o] for o in cat.OPERATORS_BY_TYPE[s.type])}.")
    if severity not in cat.SEVERITIES:
        raise ValueError(f"Severity must be one of {', '.join(cat.SEVERITIES)}.")
    if operator in ("is_true", "is_false", "empty"):
        expected = None
    elif operator in ("in", "not_in"):
        if not isinstance(expected, list) or not expected or len(expected) > 20:
            raise ValueError("Give between 1 and 20 values.")
        expected = [str(x).strip().lower()[:200] for x in expected if str(x).strip()]
        if not expected:
            raise ValueError("Give at least one value.")
    elif s.type == "int":
        try:
            expected = int(expected)
        except (TypeError, ValueError):
            raise ValueError("Enter a whole number to compare with.") from None
        if not -1 <= expected <= s.max_int:
            raise ValueError(f"The number must be between -1 and {s.max_int}.")
    else:
        if expected is None or not str(expected).strip():
            raise ValueError("Enter the value to compare with.")
        expected = str(expected).strip()[:200]
        if s.choices:
            expected = expected.lower()
    controls = [c.strip() for c in (controls or []) if isinstance(c, str) and c.strip()][:20]  # checked by _known_controls
    return operator, expected, severity, controls


# ---- custom checks (integration.manage) ---------------------------------------------------------------------------------

def save_custom_check(session: Session, actor, check_id: int | None = None, *, platform: str | None = None, slug: str | None = None, title: str | None = None,
                      description: str | None = None, remediation: str | None = None, probe: str | None = None, params: dict | None = None,
                      value_type: str | None = None, default_value=None, recommended: dict | None = None, library_key: str | None = None) -> ConfigCustomCheck:
    authorize(session, actor, "integration.manage")
    if check_id is not None:
        c = get_or_404(session, ConfigCustomCheck, check_id)
        if platform is not None and platform != c.platform:
            raise ValueError("A custom check's platform can't change. Create a new one instead.")
        if slug is not None and slug != c.slug:
            raise ValueError("A custom check's key can't change, because rules and reports use it.")
    else:
        platform = _check_platform(platform or "")
        slug = (slug or "").strip().lower()
        if not custom.SLUG_RE.match(slug):
            raise ValueError("Key: lower-case letters, digits and _, starting with a letter (2 to 41 characters).")
        if session.scalar(select(ConfigCustomCheck.id).where(ConfigCustomCheck.platform == platform, ConfigCustomCheck.slug == slug)):
            raise ValueError(f"There is already a {cat.PLATFORM_LABEL[platform]} custom check with the key {slug}.")
        if cat.setting(platform, custom.CUSTOM_PREFIX + slug) is not None:
            raise ValueError("That key is taken.")
        if _count(session, select(func.count(ConfigCustomCheck.id)).where(ConfigCustomCheck.platform == platform)) >= custom.MAX_CHECKS_PER_PLATFORM:
            raise ValueError(f"At most {custom.MAX_CHECKS_PER_PLATFORM} custom checks per platform.")
        c = ConfigCustomCheck(platform=platform, slug=slug, params={}, value_type="str")
    new_probe = probe if probe is not None else c.probe
    new_type = value_type if value_type is not None else c.value_type
    try:
        clean, default = custom.validate(c.platform, new_probe or "", params if params is not None else dict(c.params or {}), new_type or "",
                                         default_value if (params is not None or default_value is not None) else c.default_value)
    except custom.CheckInvalid as e:
        raise ValueError(str(e)) from None
    if c.id is not None and new_type != c.value_type and _rules_using(session, c):
        raise ValueError("Rules use this check, so its value type can't change. Remove those rules first.")
    c.probe, c.params, c.value_type, c.default_value = new_probe, clean, new_type, default
    if title is not None or c.id is None:
        c.title = require_text(title, "Title")[:200]
    if description is not None:
        c.description = description.strip()[:4000] or None
    if remediation is not None:
        c.remediation = remediation.strip()[:4000] or None
    if recommended is not None:
        c.recommended = _clean_recommended(session, c, recommended)
    if library_key is not None:
        c.library_key = library_key[:60]
    if c.id is None:
        session.add(c)
    session.flush()
    _reevaluate(session, c.platform)
    return c


def _clean_recommended(session: Session, c: ConfigCustomCheck, rec: dict) -> dict | None:
    if not rec:
        return None
    s = custom.as_setting(c)
    op, exp, sev, ctl = validate_rule(s, c.platform, s.key, rec.get("operator", ""), rec.get("expected"), rec.get("severity", "medium"), rec.get("controls") or [])
    return {"operator": op, "expected": exp, "severity": sev, "controls": _known_controls(session, ctl, drop_unknown=True)}


def _rules_using(session: Session, c: ConfigCustomCheck) -> list[ConfigRule]:
    key = custom.CUSTOM_PREFIX + c.slug
    return [r for r in session.scalars(select(ConfigRule).where(ConfigRule.key == key))
            if getattr(session.get(ConfigBaseline, r.baseline_id), "platform", None) == c.platform]


def delete_custom_check(session: Session, actor, check_id: int) -> None:
    authorize(session, actor, "integration.manage")
    c = get_or_404(session, ConfigCustomCheck, check_id)
    used = _rules_using(session, c)
    if used:
        names = sorted({get_or_404(session, ConfigBaseline, r.baseline_id).name for r in used})
        raise ValueError(f"Rules in {', '.join(names[:5])} use this check. Remove them first.")
    key, platform = custom.CUSTOM_PREFIX + c.slug, c.platform
    session.delete(c)
    session.flush()
    for t in session.scalars(select(ConfigTarget).where(ConfigTarget.platform == platform)):
        if key in (t.facts or {}):
            t.facts = {k: v for k, v in t.facts.items() if k != key}


def add_from_library(session: Session, actor, library_key: str) -> ConfigCustomCheck:
    e = custom.library_entry(library_key)
    existing = session.scalar(select(ConfigCustomCheck).where(ConfigCustomCheck.platform == e["platform"], ConfigCustomCheck.slug == e["slug"]))
    if existing is not None:
        raise ValueError("This check from the library has already been added.")
    return save_custom_check(session, actor, platform=e["platform"], slug=e["slug"], title=e["title"], description=e.get("description"),
                             remediation=e.get("remediation"), probe=e["probe"], params=e.get("params") or {}, value_type=e["type"],
                             default_value=e.get("default"), recommended=e.get("rule"), library_key=e["slug"])


def checks_for_device(session: Session, t: ConfigTarget) -> list[ConfigCustomCheck]:
    return custom_checks(session, t.platform)[: custom.MAX_CHECKS_PER_PLATFORM]


# ---- baselines and rules (integration.manage) ---------------------------------------------------------------------------

def _set_default(session: Session, b: ConfigBaseline) -> None:
    for other in session.scalars(select(ConfigBaseline).where(ConfigBaseline.platform == b.platform, ConfigBaseline.id != b.id, ConfigBaseline.is_default.is_(True))):
        other.is_default = False
    b.is_default = True


def create_baseline(session: Session, actor, *, name: str, platform: str, description: str | None = None, recommended: bool = True, is_default: bool | None = None,
                    scope: dict | None = None) -> ConfigBaseline:
    """A new baseline, filled with the recommended rules unless `recommended` is false. The first baseline of a
    platform becomes its default."""
    authorize(session, actor, "integration.manage")
    platform = _check_platform(platform)
    b = ConfigBaseline(name=require_text(name, "Name")[:200], platform=platform, description=(description or "").strip()[:4000] or None, enabled=True, is_default=False,
                       scope=clean_scope(scope))
    session.add(b)
    session.flush()
    first = session.scalar(select(func.count(ConfigBaseline.id)).where(ConfigBaseline.platform == platform)) == 1
    if is_default or (is_default is None and first):
        _set_default(session, b)
    if recommended:
        from keystone.frameworks.models import CommonControl

        codes = set(session.scalars(select(CommonControl.code)))
        for s in cat.settings_for(platform):
            if s.recommended is None:
                continue
            op, expected, severity, controls = s.recommended
            session.add(ConfigRule(baseline_id=b.id, key=s.key, operator=op, expected=expected, severity=severity, controls=[c for c in controls if c in codes], enabled=True))
    session.flush()
    _reevaluate(session, platform)
    return b


def update_baseline(session: Session, actor, baseline_id: int, *, name: str | None = None, description: str | None = None, enabled: bool | None = None,
                    is_default: bool | None = None, scope: dict | None = None, clear_scope: bool = False) -> ConfigBaseline:
    authorize(session, actor, "integration.manage")
    b = get_or_404(session, ConfigBaseline, baseline_id)
    if name is not None:
        b.name = require_text(name, "Name")[:200]
    if description is not None:
        b.description = description.strip()[:4000] or None
    if enabled is not None:
        b.enabled = enabled
    if is_default is True:
        _set_default(session, b)
    elif is_default is False:
        b.is_default = False
    if clear_scope:
        b.scope = None
    elif scope is not None:
        b.scope = clean_scope(scope)
    session.flush()
    _reevaluate(session, b.platform)
    return b


def clone_baseline(session: Session, actor, baseline_id: int, name: str | None = None) -> ConfigBaseline:
    authorize(session, actor, "integration.manage")
    src = get_or_404(session, ConfigBaseline, baseline_id)
    b = ConfigBaseline(name=(name or "").strip()[:200] or f"{src.name} (copy)"[:200], platform=src.platform, description=src.description, enabled=True,
                       is_default=False, scope=dict(src.scope) if src.scope else None)
    session.add(b)
    session.flush()
    for r in rules(session, src.id):
        session.add(ConfigRule(baseline_id=b.id, key=r.key, operator=r.operator, expected=r.expected, severity=r.severity, controls=list(r.controls or []),
                               enabled=r.enabled, applies_to_tags=list(r.applies_to_tags) if r.applies_to_tags else None, remediation=r.remediation))
    session.flush()
    _reevaluate(session, b.platform)
    return b


def delete_baseline(session: Session, actor, baseline_id: int) -> None:
    authorize(session, actor, "integration.manage")
    b = get_or_404(session, ConfigBaseline, baseline_id)
    platform = b.platform
    for t in session.scalars(select(ConfigTarget).where(ConfigTarget.baseline_id == b.id)):
        t.baseline_id = None
    rule_ids = list(session.scalars(select(ConfigRule.id).where(ConfigRule.baseline_id == b.id)))
    if rule_ids:
        session.execute(delete(ConfigFinding).where(ConfigFinding.rule_id.in_(rule_ids)))
    for r in session.scalars(select(ConfigRule).where(ConfigRule.baseline_id == b.id)):
        session.delete(r)  # one by one, so each removal is in the audit log
    session.flush()
    session.delete(b)
    session.flush()
    _reevaluate(session, platform)


def save_rule(session: Session, actor, *, baseline_id: int | None = None, rule_id: int | None = None, key: str | None = None, operator: str | None = None,
              expected=None, severity: str | None = None, controls: list[str] | None = None, enabled: bool | None = None,
              applies_to_tags: list[str] | None = None, remediation: str | None = None, reevaluate: bool = True, drop_unknown_controls: bool = False) -> ConfigRule:
    authorize(session, actor, "integration.manage")
    if rule_id is not None:
        r = get_or_404(session, ConfigRule, rule_id)
        b = get_or_404(session, ConfigBaseline, r.baseline_id)
    else:
        if baseline_id is None:
            raise ValueError("Choose the baseline.")
        b = get_or_404(session, ConfigBaseline, baseline_id)
        if not key:
            raise ValueError("Choose the setting to check.")
        if session.scalar(select(ConfigRule.id).where(ConfigRule.baseline_id == b.id, ConfigRule.key == key)):
            raise ValueError("This baseline already has a rule for that setting.")
        if _count(session, select(func.count(ConfigRule.id)).where(ConfigRule.baseline_id == b.id)) >= MAX_RULES:
            raise ValueError(f"A baseline can have at most {MAX_RULES} rules.")
        r = ConfigRule(baseline_id=b.id, key=key, operator="", expected=None, severity="medium", controls=[], enabled=True)
    s = settings_map(session, b.platform).get(r.key or key or "")
    op = operator if operator is not None else r.operator or (s.recommended[0] if s and s.recommended else "")
    exp = expected if (operator is not None or expected is not None) else r.expected
    if operator is None and not r.operator and s and s.recommended:
        exp = s.recommended[1]
    sev_default = (s.recommended[2] if s and s.recommended and not r.operator else r.severity)
    ctl_default = list(s.recommended[3]) if (s and s.recommended and not r.operator and controls is None) else list(r.controls or [])
    op, exp, sev, ctl = validate_rule(s, b.platform, r.key or key or "", op, exp, severity or sev_default, controls if controls is not None else ctl_default)
    r.operator, r.expected, r.severity, r.controls = op, exp, sev, _known_controls(session, ctl, drop_unknown=drop_unknown_controls or controls is None)
    if enabled is not None:
        r.enabled = enabled
    if applies_to_tags is not None:
        r.applies_to_tags = clean_tags(applies_to_tags, "Applies to tags") or None
    if remediation is not None:
        r.remediation = remediation.strip()[:4000] or None
    if r.id is None:
        session.add(r)
    session.flush()
    if reevaluate:
        _reevaluate(session, b.platform)
    return r


def reset_rule(session: Session, actor, rule_id: int) -> ConfigRule:
    """Back to the catalogue's (or the custom check's) recommended value, severity and controls."""
    r = get_or_404(session, ConfigRule, rule_id)
    b = get_or_404(session, ConfigBaseline, r.baseline_id)
    s = settings_map(session, b.platform).get(r.key)
    if s is None or s.recommended is None:
        raise ValueError("This setting has no recommended value.")
    op, exp, sev, ctl = s.recommended
    return save_rule(session, actor, rule_id=r.id, operator=op, expected=exp, severity=sev, controls=list(ctl), drop_unknown_controls=True)


def delete_rule(session: Session, actor, rule_id: int) -> None:
    authorize(session, actor, "integration.manage")
    r = get_or_404(session, ConfigRule, rule_id)
    b = get_or_404(session, ConfigBaseline, r.baseline_id)
    session.execute(delete(ConfigFinding).where(ConfigFinding.rule_id == r.id))
    session.delete(r)
    session.flush()
    _reevaluate(session, b.platform)


def baselines(session: Session) -> list[ConfigBaseline]:
    return list(session.scalars(select(ConfigBaseline).order_by(ConfigBaseline.platform, ConfigBaseline.name)))


def rules(session: Session, baseline_id: int) -> list[ConfigRule]:
    return list(session.scalars(select(ConfigRule).where(ConfigRule.baseline_id == baseline_id).order_by(ConfigRule.id)))


# ---- export and import ----------------------------------------------------------------------------------------------------

def export_baseline(session: Session, actor, baseline_id: int) -> dict:
    authorize(session, actor, "read")
    b = get_or_404(session, ConfigBaseline, baseline_id)
    rs = rules(session, b.id)
    used = {r.key[len(custom.CUSTOM_PREFIX):] for r in rs if r.key.startswith(custom.CUSTOM_PREFIX)}
    checks = [c for c in custom_checks(session, b.platform) if c.slug in used]
    return {"format": EXPORT_FORMAT, "version": 1,
            "baseline": {"name": b.name, "platform": b.platform, "description": b.description, "scope": b.scope},
            "rules": [{"key": r.key, "operator": r.operator, "expected": r.expected, "severity": r.severity, "controls": list(r.controls or []), "enabled": r.enabled,
                       "applies_to_tags": r.applies_to_tags, "remediation": r.remediation} for r in rs],
            "custom_checks": [{"slug": c.slug, "title": c.title, "description": c.description, "remediation": c.remediation, "probe": c.probe, "params": c.params,
                               "value_type": c.value_type, "default_value": c.default_value, "recommended": c.recommended} for c in checks]}


def import_baseline(session: Session, actor, data: dict) -> tuple[ConfigBaseline, list[str]]:
    """Create a baseline (and any custom checks it needs) from an export. Everything is validated as if entered by hand.
    An existing custom check with the same key is reused only if its definition is identical."""
    authorize(session, actor, "integration.manage")
    if data.get("format") != EXPORT_FORMAT or data.get("version") != 1:
        raise ValueError("This isn't a Keystone configuration baseline export (version 1).")
    meta = data.get("baseline") or {}
    platform = _check_platform(str(meta.get("platform") or ""))
    notes: list[str] = []
    for c in data.get("custom_checks") or []:
        existing = session.scalar(select(ConfigCustomCheck).where(ConfigCustomCheck.platform == platform, ConfigCustomCheck.slug == c.get("slug")))
        if existing is not None:
            same = (existing.probe, existing.params, existing.value_type, existing.default_value) == (c.get("probe"), c.get("params"), c.get("value_type"), c.get("default_value"))
            if not same:
                raise ValueError(f"A different custom check with the key {c.get('slug')} already exists. Rename one of them first.")
            notes.append(f"Custom check {c.get('slug')} already existed and was reused.")
            continue
        save_custom_check(session, actor, platform=platform, slug=c.get("slug"), title=c.get("title"), description=c.get("description"), remediation=c.get("remediation"),
                          probe=c.get("probe"), params=c.get("params") or {}, value_type=c.get("value_type"), default_value=c.get("default_value"),
                          recommended=c.get("recommended") or None)
    name = str(meta.get("name") or "Imported baseline").strip()[:190]
    if session.scalar(select(ConfigBaseline.id).where(ConfigBaseline.platform == platform, ConfigBaseline.name == name)):
        name += " (imported)"
    b = create_baseline(session, actor, name=name, platform=platform, description=meta.get("description"), recommended=False, is_default=False, scope=meta.get("scope"))
    for r in (data.get("rules") or [])[:MAX_RULES]:
        before = len(r.get("controls") or [])
        rule = save_rule(session, actor, baseline_id=b.id, key=r.get("key"), operator=r.get("operator"), expected=r.get("expected"), severity=r.get("severity", "medium"),
                         controls=r.get("controls") or [], enabled=bool(r.get("enabled", True)), applies_to_tags=r.get("applies_to_tags"), remediation=r.get("remediation"),
                         reevaluate=False, drop_unknown_controls=True)
        if len(rule.controls) < before:
            notes.append(f"Unknown control codes were dropped from the rule for {r.get('key')}.")
    _reevaluate(session, platform)
    log_event(session, actor, "import", "ConfigBaseline", b.id, f"Imported baseline {b.name} with {len(data.get('rules') or [])} rule(s)")
    return b, notes


# ---- evaluation ---------------------------------------------------------------------------------------------------------

def _scope_matches(b: ConfigBaseline, t: ConfigTarget) -> bool:
    sc = b.scope or {}
    tags = set(t.tags or [])
    if sc.get("tags") and tags & set(sc["tags"]):
        return True
    names = [n for n in (t.name, t.hostname) if n]
    return any(glob_match(n, p) for p in sc.get("names") or [] for n in names)


def effective_baselines(session: Session, t: ConfigTarget) -> list[ConfigBaseline]:
    """The pinned baseline (or else the platform default), then every other enabled baseline whose scope matches."""
    out: list[ConfigBaseline] = []
    candidates = list(session.scalars(select(ConfigBaseline).where(ConfigBaseline.platform == t.platform, ConfigBaseline.enabled.is_(True)).order_by(ConfigBaseline.id)))
    primary = next((b for b in candidates if b.id == t.baseline_id), None) if t.baseline_id else next((b for b in candidates if b.is_default), None)
    if primary is not None:
        out.append(primary)
    out += [b for b in candidates if b not in out and b.scope and _scope_matches(b, t)]
    return out


def effective_baseline(session: Session, t: ConfigTarget) -> ConfigBaseline | None:
    """The primary baseline (pinned or default), for summaries."""
    bs = effective_baselines(session, t)
    return bs[0] if bs else None


def judge(s: cat.Setting | None, r: ConfigRule, facts: dict, settings: dict[str, cat.Setting] | None = None, errors: dict | None = None,
          custom_off: bool = False) -> tuple[str, object, str]:
    """(status, actual value, explanation) for one rule. A missing or unreadable value is unknown, never a pass."""
    if s is None:
        return "unknown", None, "This setting no longer exists (a removed custom check?)."
    if s.requires:
        pre = facts.get(s.requires)
        if pre is False:
            req = (settings or {}).get(s.requires)
            return "na", None, f"Not applicable: {(req.title if req else s.requires).lower()} is off."
        if pre is None:
            return "unknown", None, "Not reported."
    v = cat.clean_value(s, facts.get(r.key))
    if v is None:
        if r.key.startswith(custom.CUSTOM_PREFIX):
            if custom_off:
                return "unknown", None, ERROR_TEXT["disabled"]
            code = (errors or {}).get(r.key)
            if code in ERROR_TEXT:
                return "unknown", None, ERROR_TEXT[code]
        return "unknown", None, "Not reported."
    op, exp = r.operator, r.expected
    ok: bool
    if op == "is_true":
        ok = v is True
    elif op == "is_false":
        ok = v is False
    elif op == "empty":
        ok = isinstance(v, list) and not v
    elif op in ("in", "not_in"):
        values = [str(x).lower() for x in exp] if isinstance(exp, list) else []
        ok = (str(v).lower() in values) == (op == "in")
    elif s.type == "int":
        if not isinstance(exp, int):
            return "unknown", v, "The rule has no number to compare with."
        ok = {"eq": v == exp, "ne": v != exp, "gte": v >= exp, "lte": v <= exp}[op]
    else:
        ok = {"eq": str(v).lower() == str(exp).lower(), "ne": str(v).lower() != str(exp).lower()}.get(op, False)
    if ok:
        return "pass", v, ""
    shown = "on" if v is True else "off" if v is False else ", ".join(v) if isinstance(v, list) else str(v)
    return "fail", v, f"Reported {shown}; required: {cat.describe_expected(op, exp)}."


def evaluate_target(session: Session, t: ConfigTarget, source: str = "evaluate", settings: dict[str, cat.Setting] | None = None) -> dict:
    """Compare the target's latest facts with every baseline that applies. Updates findings, records a snapshot with
    what changed, and returns the counts. New critical and high failures alert the ISMS managers."""
    now, on = utcnow(), today()
    settings = settings if settings is not None else settings_map(session, t.platform)
    bs = effective_baselines(session, t)
    current = {f.rule_id: f for f in session.scalars(select(ConfigFinding).where(ConfigFinding.target_id == t.id))}
    counts: Counter = Counter()
    changes, new_failures = [], []
    seen = set()
    tags = set(t.tags or [])
    if t.facts_at is not None:
        for b in bs:
            for r in session.scalars(select(ConfigRule).where(ConfigRule.baseline_id == b.id, ConfigRule.enabled.is_(True)).order_by(ConfigRule.id)):
                if r.applies_to_tags and not (tags & set(r.applies_to_tags)):
                    continue
                status, actual, detail = judge(settings.get(r.key), r, t.facts or {}, settings, t.check_errors, t.custom_checks == "disabled")
                f = current.get(r.id)
                if status == "fail" and f is not None and f.status == "excepted" and f.exception_until and f.exception_until >= on:
                    status = "excepted"
                if f is None:
                    f = ConfigFinding(target_id=t.id, rule_id=r.id, status=status, since=now)
                    session.add(f)
                    if status == "fail":
                        new_failures.append((r, t))
                elif f.status != status:
                    changes.append({"key": r.key, "from": f.status, "to": status, "value_from": f.actual, "value_to": actual})
                    if status == "fail" and f.status != "excepted":
                        new_failures.append((r, t))
                    f.status, f.since = status, now
                    if status != "excepted":
                        f.exception_reason = f.exception_by_id = f.exception_until = None
                f.actual, f.detail, f.evaluated_at = actual, detail[:500], now
                counts[status] += 1
                seen.add(r.id)
    for rid, f in current.items():
        if rid not in seen:
            session.delete(f)  # the rule was removed, disabled, out of scope, or the baseline no longer applies
    if source != "evaluate" or changes:  # a re-check after a baseline edit is recorded only when results changed
        session.add(ConfigSnapshot(target_id=t.id, at=now, source=source, baseline_id=bs[0].id if bs else None, counts=dict(counts), changes=changes[:200]))
    session.flush()
    _alert(session, new_failures, settings)
    return {"baseline_id": bs[0].id if bs else None, "baseline_ids": [b.id for b in bs], **{k: counts.get(k, 0) for k in ("pass", "fail", "unknown", "na", "excepted")},
            "changes": len(changes)}


def _reevaluate(session: Session, platform: str) -> None:
    settings = settings_map(session, platform)
    for t in session.scalars(select(ConfigTarget).where(ConfigTarget.platform == platform, ConfigTarget.revoked_at.is_(None))):
        if t.facts_at is not None:
            evaluate_target(session, t, settings=settings)


def _alert(session: Session, failures: list[tuple[ConfigRule, ConfigTarget]], settings: dict[str, cat.Setting]) -> None:
    from keystone.notifications.models import Notification
    from keystone.outbound.service import emit

    serious = [(r, t) for r, t in failures if r.severity in ("critical", "high")]
    if not serious:
        return
    users = [u for u in session.scalars(select(User).where(User.active.is_(True))) if not expired(u)]
    managers = [u.id for u in users if u.role == Role.ISMS_MANAGER.value] or [u.id for u in users if u.role == Role.ADMIN.value]
    stamp = datetime.now()
    by_target: dict[int, list[ConfigRule]] = {}
    for r, t in serious:
        by_target.setdefault(t.id, []).append(r)
    for tid, rs in by_target.items():
        t = get_or_404(session, ConfigTarget, tid)
        worst = "critical" if any(r.severity == "critical" for r in rs) else "high"
        names = ", ".join(_title(settings, r.key) for r in rs[:3])
        text = f"{t.name}: {len(rs)} {worst} configuration failure(s) ({names}{'…' if len(rs) > 3 else ''})"
        for m in managers:
            session.add(Notification(user_id=m, key=f"config:{tid}:{stamp:%Y%m%d%H%M%S%f}", kind="config", title=text[:500], page=f"/configuration?target={tid}", created_at=stamp))
        emit(session, "config.failed", title=text, severity=worst, page=f"/configuration?target={tid}")
    session.flush()


def file_evidence(session: Session) -> int:
    """Each enabled baseline whose targets (at least one, reported recently) all pass or have approved exceptions is
    evidence for its rules' controls. Refreshed by the scheduled job; lapses after three days without a refresh."""
    from keystone.controls.models import Evidence
    from keystone.frameworks.models import CommonControl

    filed = 0
    targets_ = [t for t in session.scalars(select(ConfigTarget).where(ConfigTarget.revoked_at.is_(None))) if t.facts_at and not is_stale(session, t)]
    applies = {t.id: {b.id for b in effective_baselines(session, t)} for t in targets_}
    for b in session.scalars(select(ConfigBaseline).where(ConfigBaseline.enabled.is_(True))):
        mine = [t for t in targets_ if b.id in applies[t.id]]
        if not mine:
            continue
        rule_ids = list(session.scalars(select(ConfigRule.id).where(ConfigRule.baseline_id == b.id)))
        statuses = Counter(f.status for f in session.scalars(select(ConfigFinding).where(ConfigFinding.target_id.in_([t.id for t in mine]), ConfigFinding.rule_id.in_(rule_ids))))
        if statuses.get("fail") or statuses.get("unknown") or not statuses.get("pass"):
            continue
        codes = sorted({c for r in rules(session, b.id) if r.enabled for c in (r.controls or [])})
        title = f"Configuration baseline met: {b.name}"
        desc = (f"{len(mine)} {cat.PLATFORM_LABEL[b.platform]} target(s) meet every rule of “{b.name}”"
                + (f" ({statuses['excepted']} result(s) under an approved exception)" if statuses.get("excepted") else "")
                + f". Checked {utcnow():%Y-%m-%d %H:%M} UTC from agent reports and uploaded configurations.")
        for code in codes:
            c = session.scalar(select(CommonControl).where(CommonControl.code == code))
            if c is None:
                continue
            ev = session.scalar(select(Evidence).where(Evidence.common_control_id == c.id, Evidence.title == title, Evidence.kind == "note"))
            if ev is None:
                session.add(Evidence(common_control_id=c.id, title=title, kind="note", description=desc, collected_on=today(), valid_until=today() + timedelta(days=3)))
            else:
                ev.description, ev.collected_on, ev.valid_until = desc, today(), today() + timedelta(days=3)
            filed += 1
    session.flush()
    return filed


def housekeeping(session: Session) -> dict:
    """The scheduled job: lapse expired exceptions (re-evaluating, so they show as failing), file evidence, trim history."""
    lapsed = expire_exceptions(session)
    if lapsed:
        for p in cat.PLATFORMS:
            _reevaluate(session, p)
    return {"lapsed": lapsed, "evidence": file_evidence(session), "pruned": prune_snapshots(session)}


def prune_snapshots(session: Session) -> int:
    removed = 0
    for tid in session.scalars(select(ConfigTarget.id)):
        cutoff = session.scalar(select(ConfigSnapshot.id).where(ConfigSnapshot.target_id == tid).order_by(ConfigSnapshot.id.desc()).offset(SNAPSHOTS_KEPT).limit(1))
        if cutoff is not None:
            gone = list(session.scalars(select(ConfigSnapshot.id).where(ConfigSnapshot.target_id == tid, ConfigSnapshot.id <= cutoff)))
            session.execute(delete(ConfigSnapshot).where(ConfigSnapshot.id.in_(gone)))
            removed += len(gone)
    return removed


# ---- targets (read / integration.manage) ----------------------------------------------------------------------------------

def agent_settings(session: Session) -> ConfigAgentSettings:
    s = session.scalar(select(ConfigAgentSettings).limit(1))
    if s is None:
        s = ConfigAgentSettings(report_hours=4)
        session.add(s)
        session.flush()
    return s


def is_stale(session: Session, t: ConfigTarget, settings: ConfigAgentSettings | None = None) -> bool:
    if t.facts_at is None:
        return True
    if t.kind == "firewall":
        return t.facts_at < utcnow() - timedelta(days=FIREWALL_STALE_DAYS)
    hours = (settings or agent_settings(session)).report_hours
    return t.facts_at < utcnow() - timedelta(hours=hours * STALE_FACTOR)


def targets(session: Session) -> list[ConfigTarget]:
    return list(session.scalars(select(ConfigTarget).order_by(ConfigTarget.platform, ConfigTarget.name)))


def findings(session: Session, target_id: int) -> list[ConfigFinding]:
    return list(session.scalars(select(ConfigFinding).where(ConfigFinding.target_id == target_id)))


def history(session: Session, target_id: int, limit: int = 100) -> list[ConfigSnapshot]:
    return list(session.scalars(select(ConfigSnapshot).where(ConfigSnapshot.target_id == target_id).order_by(ConfigSnapshot.id.desc()).limit(limit)))


def suggest_assets(session: Session, t: ConfigTarget, limit: int = 5) -> list:
    """Assets whose name matches the host name (exactly, or the short name before the first dot)."""
    from keystone.assets.models import Asset

    names = {n.lower() for n in (t.name, t.hostname) if n}
    names |= {n.split(".")[0] for n in names}
    out = [a for a in session.scalars(select(Asset).where(Asset.status != "retired")) if a.name.lower() in names or a.name.lower().split(".")[0] in names]
    return out[:limit]


def update_target(session: Session, actor, target_id: int, *, name: str | None = None, baseline_id: int | None = None, clear_baseline: bool = False,
                  tags: list[str] | None = None, asset_id: int | None = None, clear_asset: bool = False) -> ConfigTarget:
    authorize(session, actor, "integration.manage")
    t = get_or_404(session, ConfigTarget, target_id)
    changes = []
    if name is not None:
        t.name = require_text(name, "Name")[:200]
        changes.append("renamed")
    if clear_baseline:
        t.baseline_id = None
        changes.append("uses the platform default baseline")
    elif baseline_id is not None:
        b = get_or_404(session, ConfigBaseline, baseline_id)
        if b.platform != t.platform:
            raise ValueError("Choose a baseline for the same platform.")
        t.baseline_id = b.id
        changes.append(f"baseline {b.name}")
    if tags is not None:
        t.tags = clean_tags(tags) or None
        changes.append("tags " + (", ".join(t.tags or []) or "cleared"))
    if clear_asset:
        t.asset_id = None
        changes.append("unlinked from its asset")
    elif asset_id is not None:
        from keystone.assets.models import Asset

        a = get_or_404(session, Asset, asset_id)
        t.asset_id = a.id
        changes.append(f"linked to asset {a.name}")
    session.flush()
    evaluate_target(session, t)
    log_event(session, actor, "update", "ConfigTarget", t.id, f"{t.name}: " + ", ".join(changes or ["re-evaluated"]))
    return t


def targets_for_asset(session: Session, asset_id: int) -> list[ConfigTarget]:
    return list(session.scalars(select(ConfigTarget).where(ConfigTarget.asset_id == asset_id)))


def revoke_target(session: Session, actor, target_id: int) -> ConfigTarget:
    """Stops an agent's token working. Its results stay until the target is deleted."""
    authorize(session, actor, "integration.manage")
    t = get_or_404(session, ConfigTarget, target_id)
    if t.kind != "agent":
        raise ValueError("Only agents have a token to revoke.")
    t.revoked_at = t.revoked_at or utcnow()
    session.flush()
    log_event(session, actor, "revoke", "ConfigTarget", t.id, f"Agent token revoked for {t.name}")
    return t


def delete_target(session: Session, actor, target_id: int) -> None:
    authorize(session, actor, "integration.manage")
    t = get_or_404(session, ConfigTarget, target_id)
    name = t.name
    from keystone.collab.models import Comment

    session.execute(delete(ConfigFinding).where(ConfigFinding.target_id == t.id))
    session.execute(delete(ConfigSnapshot).where(ConfigSnapshot.target_id == t.id))
    session.execute(delete(Comment).where(Comment.entity_type == "config_target", Comment.entity_id == t.id))
    session.delete(t)
    session.flush()
    log_event(session, actor, "delete", "ConfigTarget", target_id, f"Removed {name} from configuration checks")


# ---- exceptions (risk.accept) -----------------------------------------------------------------------------------------------

def _check_until(until: date) -> None:
    if until <= today() or until > today() + timedelta(days=MAX_EXCEPTION_DAYS):
        raise ValueError("The exception must end within a year.")


def grant_exception(session: Session, actor, finding_id: int, reason: str, until: date) -> ConfigFinding:
    authorize(session, actor, "risk.accept")
    f = get_or_404(session, ConfigFinding, finding_id)
    if f.status != "fail":
        raise ValueError("Only failing results can get an exception.")
    _check_until(until)
    f.status, f.since = "excepted", utcnow()
    f.exception_reason, f.exception_by_id, f.exception_until = require_text(reason, "Reason")[:2000], actor.id, until
    session.flush()
    r = session.get(ConfigRule, f.rule_id)
    t = session.get(ConfigTarget, f.target_id)
    log_event(session, actor, "exception", "ConfigFinding", f.id, f"Exception until {until.isoformat()} for {r.key if r else '?'} on {t.name if t else '?'}: {f.exception_reason[:200]}")
    return f


def grant_exceptions(session: Session, actor, rule_id: int, target_ids: list[int] | None, reason: str, until: date) -> int:
    """One exception for a rule on several targets (all currently failing ones when no targets are given)."""
    authorize(session, actor, "risk.accept")
    r = get_or_404(session, ConfigRule, rule_id)
    _check_until(until)
    reason = require_text(reason, "Reason")[:2000]
    q = select(ConfigFinding).where(ConfigFinding.rule_id == r.id, ConfigFinding.status == "fail")
    if target_ids:
        q = q.where(ConfigFinding.target_id.in_(target_ids[:MAX_TARGETS]))
    n = 0
    for f in session.scalars(q):
        f.status, f.since = "excepted", utcnow()
        f.exception_reason, f.exception_by_id, f.exception_until = reason, actor.id, until
        n += 1
    session.flush()
    log_event(session, actor, "exception", "ConfigRule", r.id, f"Exception until {until.isoformat()} for {r.key} on {n} target(s): {reason[:200]}")
    return n


def revoke_exception(session: Session, actor, finding_id: int) -> ConfigFinding:
    authorize(session, actor, "risk.accept")
    f = get_or_404(session, ConfigFinding, finding_id)
    if f.status != "excepted":
        raise ValueError("This result has no exception.")
    f.status, f.since = "fail", utcnow()
    f.exception_reason = f.exception_by_id = f.exception_until = None
    session.flush()
    log_event(session, actor, "exception_revoked", "ConfigFinding", f.id, "Exception withdrawn")
    return f


def expire_exceptions(session: Session) -> int:
    n = 0
    for f in session.scalars(select(ConfigFinding).where(ConfigFinding.status == "excepted", ConfigFinding.exception_until < today())):
        f.status, f.since = "fail", utcnow()
        f.exception_reason = f.exception_by_id = f.exception_until = None
        n += 1
    session.flush()
    return n


# ---- firewall uploads (integration.manage) ------------------------------------------------------------------------------------

def upload_firewall(session: Session, actor, *, platform: str, filename: str, data: bytes, target_id: int | None = None, name: str | None = None) -> tuple[ConfigTarget, dict, list[str]]:
    """Parse a configuration export, keep only the facts (never the file, which holds secrets), run the platform's
    custom checks on it, and evaluate."""
    from keystone.core.attachments import safe_filename

    authorize(session, actor, "integration.manage")
    if platform not in cat.FIREWALL_PLATFORMS:
        raise ValueError("Choose FortiGate, PAN-OS, Cisco or pfSense/OPNsense.")
    parsed = parsers.parse(platform, data)
    allowed = {s.key: s for s in cat.settings_for(platform)}
    facts = {k: cat.clean_value(allowed[k], v) for k, v in parsed.facts.items() if k in allowed}
    facts = {k: v for k, v in facts.items() if v is not None}
    errors: dict[str, str] = {}
    for c in custom_checks(session, platform):
        value, err = custom.firewall_value(platform, parsed.ctx, c)
        if err:
            errors[custom.CUSTOM_PREFIX + c.slug] = err
        else:
            facts[custom.CUSTOM_PREFIX + c.slug] = value
    parsed.ctx = None  # drop the parsed file now: it may hold secrets
    if target_id is not None:
        t = get_or_404(session, ConfigTarget, target_id)
        if t.kind != "firewall" or t.platform != platform:
            raise ValueError("That target is not a firewall of this platform.")
    else:
        if _count(session, select(func.count(ConfigTarget.id))) >= MAX_TARGETS:
            raise ValueError(f"At most {MAX_TARGETS} targets.")
        label = (name or "").strip() or parsed.hostname or safe_filename(filename)
        t = ConfigTarget(kind="firewall", platform=platform, name=label[:200], facts={}, created_at=utcnow())
        session.add(t)
    t.hostname = (parsed.hostname or t.hostname or "")[:253] or None
    t.os_name, t.os_version = cat.PLATFORM_LABEL[platform], (parsed.version or "")[:100] or None
    t.source_filename, t.source_sha256 = safe_filename(filename), hashlib.sha256(data).hexdigest()
    t.facts, t.facts_at, t.check_errors = facts, utcnow(), errors or None
    session.flush()
    result = evaluate_target(session, t, source="upload")
    log_event(session, actor, "upload", "ConfigTarget", t.id, f"Configuration of {t.name} ({cat.PLATFORM_LABEL[platform]}) checked: {result['fail']} failing, {result['unknown']} unknown; file SHA-256 {t.source_sha256[:16]}…")
    return t, result, parsed.notes


# ---- agents: enrolment key (integration.manage), enrolment, check definitions and reports (device credentials) ---------------

def enrolment_key(session: Session, actor) -> str:
    """The current enrolment key, created on first use. Shown to administrators for the install command."""
    authorize(session, actor, "integration.manage")
    s = agent_settings(session)
    if not s.enrollment_key_enc:
        s.enrollment_key_enc, s.rotated_at = crypto.encrypt(ENROLMENT_PREFIX + pysecrets.token_urlsafe(24)), utcnow()
        session.flush()
    return crypto.decrypt(s.enrollment_key_enc)


def rotate_enrolment_key(session: Session, actor) -> str:
    """A new key for new installs. Agents already enrolled keep working: they use their own device tokens."""
    authorize(session, actor, "integration.manage")
    s = agent_settings(session)
    s.enrollment_key_enc, s.rotated_at = crypto.encrypt(ENROLMENT_PREFIX + pysecrets.token_urlsafe(24)), utcnow()
    s.enrollment_uses = 0
    if s.enrollment_expires_at is not None:  # a limited key stays limited: the same length of time from now
        s.enrollment_expires_at = utcnow() + timedelta(days=s.enrollment_days or 7)
    session.flush()
    log_event(session, actor, "rotate", "ConfigAgentSettings", s.id, "Agent enrolment key rotated")
    return crypto.decrypt(s.enrollment_key_enc)


MAX_KEY_DAYS = 90
MAX_KEY_USES = 10_000


def set_enrolment_limits(session: Session, actor, *, days: int | None, max_uses: int | None) -> ConfigAgentSettings:
    """Limit the current enrolment key: it expires `days` from now and/or after `max_uses` enrolments (None: no limit).
    Uses so far are kept, so lowering the limit can close the key at once."""
    authorize(session, actor, "integration.manage")
    if days is not None and not 1 <= days <= MAX_KEY_DAYS:
        raise ValueError(f"The key can last 1 to {MAX_KEY_DAYS} days.")
    if max_uses is not None and not 1 <= max_uses <= MAX_KEY_USES:
        raise ValueError(f"Allow 1 to {MAX_KEY_USES} enrolments.")
    s = agent_settings(session)
    s.enrollment_expires_at = utcnow() + timedelta(days=days) if days else None
    s.enrollment_days = days
    s.enrollment_max_uses = max_uses
    session.flush()
    log_event(session, actor, "update", "ConfigAgentSettings", s.id,
              f"Enrolment key limits: {f'expires in {days} day(s)' if days else 'no expiry'}, {f'at most {max_uses} use(s)' if max_uses else 'no use limit'}")
    return s


def set_report_hours(session: Session, actor, hours: int) -> ConfigAgentSettings:
    authorize(session, actor, "integration.manage")
    if hours not in (1, 2, 4, 8, 12, 24):
        raise ValueError("Choose 1, 2, 4, 8, 12 or 24 hours.")
    s = agent_settings(session)
    s.report_hours = hours
    session.flush()
    return s


class AgentRejected(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def enrol(session: Session, *, key: str, hostname: str, platform: str, os_name: str | None, os_version: str | None, agent_version: str | None, ip: str | None,
          tags: list[str] | None = None) -> tuple[ConfigTarget, str]:
    """Exchange the enrolment key for a device token. Every enrolment creates a new target; an administrator removes
    the old one after a reinstall. The token is returned once and stored only as a hash."""
    s = session.scalar(select(ConfigAgentSettings).limit(1))
    current = crypto.decrypt(s.enrollment_key_enc) if s is not None and s.enrollment_key_enc else None
    if s is None or current is None or not hmac.compare_digest(current.encode(), (key or "").encode()):
        raise AgentRejected(401, "Invalid enrolment key.")
    if s.enrollment_expires_at is not None and s.enrollment_expires_at < utcnow():
        raise AgentRejected(401, "The enrolment key has expired. Ask for a new one.")
    if s.enrollment_max_uses is not None and (s.enrollment_uses or 0) >= s.enrollment_max_uses:
        raise AgentRejected(401, "The enrolment key has been used as many times as allowed. Ask for a new one.")
    if platform not in cat.AGENT_PLATFORMS:
        raise AgentRejected(400, "Unsupported platform.")
    try:
        clean = clean_tags(tags)
    except ValueError as e:
        raise AgentRejected(400, str(e)) from None
    if _count(session, select(func.count(ConfigTarget.id))) >= MAX_TARGETS:
        raise AgentRejected(409, "Too many targets.")
    raw = DEVICE_PREFIX + pysecrets.token_urlsafe(32)
    now = utcnow()
    t = ConfigTarget(kind="agent", platform=platform, name=hostname, hostname=hostname, os_name=(os_name or "")[:200] or None, os_version=(os_version or "")[:100] or None,
                     agent_version=(agent_version or "")[:20] or None, token_hash=_hash(raw), enrolled_at=now, last_ip=(ip or "")[:64] or None, facts={}, created_at=now,
                     tags=clean or None)
    session.add(t)
    s.enrollment_uses = (s.enrollment_uses or 0) + 1
    session.flush()
    log_event(session, None, "enrol", "ConfigTarget", t.id, f"Agent enrolled: {hostname} ({cat.PLATFORM_LABEL[platform]}) from {ip or 'unknown address'}")
    return t, raw


def resolve_device(session: Session, header: str | None) -> ConfigTarget:
    if not header or not header.startswith("Bearer ") or len(header) > 300:
        raise AgentRejected(401, "Device token required.")
    raw = header[7:].strip()
    if not raw.startswith(DEVICE_PREFIX):
        raise AgentRejected(401, "Invalid device token.")
    digest = _hash(raw)
    t = session.scalar(select(ConfigTarget).where(ConfigTarget.token_hash == digest))
    if t is None or not hmac.compare_digest(t.token_hash or "", digest) or t.revoked_at is not None:
        raise AgentRejected(401, "Invalid or revoked device token.")
    return t


def checkin(session: Session, t: ConfigTarget, *, agent_version: str | None, agent_sha256: str | None, ip: str | None) -> dict:
    """The hourly check-in of agents 1.2+: proves the host is alive between reports and says whether a report is due."""
    from . import agents

    agents.record_releases(session)
    t.last_seen_at = utcnow()
    t.agent_version = (agent_version or t.agent_version or "")[:20] or None
    t.agent_sha256 = agents.clean_sha(agent_sha256) or t.agent_sha256
    t.last_ip = (ip or "")[:64] or None
    hours = agent_settings(session).report_hours
    session.flush()
    return {"report_due": agents.report_due(t, hours), "report_hours": hours}


MAX_SOFTWARE = 5000
OS_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,29}$")
OS_VERSION_ID = re.compile(r"^[0-9][0-9A-Za-z._-]{0,19}$")


def clean_software(items) -> list[list[str]]:
    """[[name, version], ...]: strings only, trimmed, at most MAX_SOFTWARE distinct entries. Anything else is dropped."""
    out, seen = [], set()
    for x in items or []:
        if not isinstance(x, (list, tuple)) or len(x) != 2 or not all(isinstance(v, str) for v in x):
            continue
        name, version = x[0].strip()[:200], x[1].strip()[:100]
        if not name or not version or (name, version) in seen or any(ord(c) < 32 for c in name + version):
            continue
        seen.add((name, version))
        out.append([name, version])
        if len(out) >= MAX_SOFTWARE:
            break
    return sorted(out, key=lambda p: (p[0].lower(), p[1]))


def software_search(session: Session, actor, q: str | None = None, limit: int = 200) -> dict:
    """Installed software across hosts: each name and version with the hosts that have it, most widespread first."""
    authorize(session, actor, "read")
    needle = (q or "").strip().lower()[:100]
    rows: dict[tuple[str, str], list[dict]] = {}
    hosts = 0
    for t in session.scalars(select(ConfigTarget).where(ConfigTarget.kind == "agent", ConfigTarget.revoked_at.is_(None), ConfigTarget.software_at.is_not(None))):
        hosts += 1
        for name, version in t.software or []:
            if needle and needle not in name.lower():
                continue
            rows.setdefault((name, version), []).append({"id": t.id, "name": t.name, "platform": t.platform})
    ordered = sorted(rows.items(), key=lambda kv: (-len(kv[1]), kv[0][0].lower(), kv[0][1]))
    return {"hosts": hosts, "total": len(ordered), "rows": [{"name": n, "version": v, "hosts": h} for (n, v), h in ordered[:max(1, min(limit, 1000))]]}


def report(session: Session, t: ConfigTarget, *, facts: dict, hostname: str | None, os_name: str | None, os_version: str | None, agent_version: str | None, ip: str | None,
           check_errors: dict | None = None, custom_checks_state: str | None = None, agent_sha256: str | None = None, software: list | None = None,
           os_release: dict | None = None) -> dict:
    """Store an agent's report and evaluate it. Unknown keys and values of the wrong type are dropped, not stored."""
    allowed = settings_map(session, t.platform)
    clean, ignored = {}, []
    for k, v in (facts or {}).items():
        s = allowed.get(k)
        value = cat.clean_value(s, v) if s else None
        if value is None:
            ignored.append(str(k)[:60])
        else:
            clean[k] = value
    errors = {k: v for k, v in (check_errors or {}).items() if k in allowed and k.startswith(custom.CUSTOM_PREFIX) and v in CHECK_ERRORS and k not in clean}
    was_reported = t.facts_at is not None
    t.facts, t.facts_at, t.check_errors = clean, utcnow(), errors or None
    t.custom_checks = "disabled" if custom_checks_state == "disabled" else None
    if hostname:
        t.hostname = hostname[:253]
    t.os_name = (os_name or t.os_name or "")[:200] or None
    t.os_version = (os_version or t.os_version or "")[:100] or None
    t.agent_version = (agent_version or t.agent_version or "")[:20] or None
    t.last_ip = (ip or "")[:64] or None
    from . import agents

    agents.record_releases(session)
    # Assets are linked automatically only on a host's first report, or its first from agent 1.2+, so a link an
    # administrator removed isn't put back.
    first = t.agent_sha256 is None and (not was_reported or bool(agent_sha256))
    t.agent_sha256 = agents.clean_sha(agent_sha256) or t.agent_sha256
    if software is not None:
        t.software, t.software_at = clean_software(software), utcnow()
    if os_release:
        oid, ver = str(os_release.get("id") or "").strip().lower(), str(os_release.get("version_id") or "").strip()
        t.os_release = f"{oid} {ver}" if OS_ID.match(oid) and OS_VERSION_ID.match(ver) else None
    if t.last_seen_at is not None or agent_sha256:
        t.last_seen_at = utcnow()
    agents.link(session, t, assets=first)
    session.flush()
    session.info["actor"] = None
    evaluate_target(session, t, source="agent", settings=allowed)
    return {"accepted": len(clean), "ignored": ignored[:50], "report_hours": agent_settings(session).report_hours}


# ---- overview and reports ---------------------------------------------------------------------------------------------------

def summary(session: Session, t: ConfigTarget, settings: ConfigAgentSettings | None = None) -> dict:
    c = Counter(f.status for f in findings(session, t.id))
    bs = effective_baselines(session, t)
    stale = is_stale(session, t, settings)
    total = c["pass"] + c["fail"] + c["unknown"]
    state = ("revoked" if t.revoked_at else "waiting" if t.facts_at is None else "no_baseline" if not bs else
             "failing" if c["fail"] else "unknown" if c["unknown"] else "compliant")
    return {"baseline_id": bs[0].id if bs else None, "baseline": bs[0].name if bs else None, "baselines": [{"id": b.id, "name": b.name} for b in bs],
            "stale": stale, "state": state, "counts": {k: c.get(k, 0) for k in ("pass", "fail", "unknown", "na", "excepted")},
            "score": round(100 * (c["pass"] + c["excepted"]) / (total + c["excepted"])) if (total + c["excepted"]) else None}


def overview(session: Session) -> dict:
    s = agent_settings(session)
    rows = [(t, summary(session, t, s)) for t in targets(session)]
    per = {}
    for p in cat.PLATFORMS:
        mine = [x for t, x in rows if t.platform == p and t.revoked_at is None]
        per[p] = {"targets": len(mine), "compliant": sum(1 for x in mine if x["state"] == "compliant"), "failing": sum(1 for x in mine if x["state"] == "failing"),
                  "stale": sum(1 for x in mine if x["stale"]), "fail_results": sum(x["counts"]["fail"] for x in mine)}
    worst: Counter[tuple[str, str, str]] = Counter()
    for f in session.scalars(select(ConfigFinding).where(ConfigFinding.status == "fail")):
        r = session.get(ConfigRule, f.rule_id)
        t = session.get(ConfigTarget, f.target_id)
        if r is not None and t is not None and t.revoked_at is None:
            worst[(t.platform, r.key, r.severity)] += 1
    order = {s: i for i, s in enumerate(reversed(cat.SEVERITIES))}
    top = sorted(worst.items(), key=lambda kv: (order[kv[0][2]], -kv[1]))[:10]
    maps = {p: settings_map(session, p) for p in {p for (p, _, _), _ in top}}
    return {"platforms": per, "report_hours": s.report_hours,
            "top_failures": [{"platform": p, "key": k, "title": _title(maps[p], k), "severity": sev, "targets": n} for (p, k, sev), n in top]}


def compliance_rows(session: Session, actor, baseline_id: int | None = None, target_id: int | None = None) -> tuple[list[str], list[list]]:
    """Every result, one row per target and rule, for the xlsx report."""
    authorize(session, actor, "read")
    headers = ["Target", "Platform", "Kind", "Tags", "Baseline", "Setting", "Severity", "Required", "Reported", "Result", "Since", "Exception until", "Exception reason", "Controls", "Last report"]
    q = select(ConfigFinding)
    if target_id is not None:
        q = q.where(ConfigFinding.target_id == target_id)
    rows = []
    maps: dict[str, dict] = {}
    for f in session.scalars(q):
        r = session.get(ConfigRule, f.rule_id)
        t = session.get(ConfigTarget, f.target_id)
        if r is None or t is None or (baseline_id is not None and r.baseline_id != baseline_id):
            continue
        b = session.get(ConfigBaseline, r.baseline_id)
        settings = maps.setdefault(t.platform, settings_map(session, t.platform))
        actual = f.actual
        shown = "" if actual is None else "on" if actual is True else "off" if actual is False else ", ".join(actual) if isinstance(actual, list) else str(actual)
        rows.append([t.name, cat.PLATFORM_LABEL.get(t.platform, t.platform), t.kind, ", ".join(t.tags or []), b.name if b else "", _title(settings, r.key), r.severity,
                     cat.describe_expected(r.operator, r.expected), shown, f.status, f.since, f.exception_until, f.exception_reason or "", ", ".join(r.controls or []), t.facts_at])
    rows.sort(key=lambda x: (str(x[0]), str(x[4]), str(x[5])))
    return headers, rows
