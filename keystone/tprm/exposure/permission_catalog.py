"""Permission value -> tier, from config/permission_tiers.yaml. Unlisted values are never assumed low."""

from __future__ import annotations

from functools import lru_cache

import yaml

from .paths import CONFIG_DIR

TIERS = ("low", "medium", "high", "critical")
TIER_RANK = {t: i for i, t in enumerate(TIERS)}


@lru_cache(maxsize=4)
def _load(path: str) -> tuple[dict[str, str], str]:
    d = yaml.safe_load(open(path, encoding="utf-8"))
    mapping: dict[str, str] = {}
    for tier in TIERS:
        for value in d.get(tier) or []:
            key = str(value).lower()
            if key in mapping:
                raise ValueError(f"permission {value} is listed in two tiers")
            mapping[key] = tier
    default = d.get("default_unlisted", "medium")
    if default not in TIERS or default == "low":
        raise ValueError("default_unlisted must be medium, high or critical")
    return mapping, default


def tier_for(value: str | None, path: str | None = None) -> str:
    mapping, default = _load(path or str(CONFIG_DIR / "permission_tiers.yaml"))
    if not value:
        return default
    return mapping.get(value.lower(), default)


def max_tier(tiers) -> str | None:
    tiers = [t for t in tiers if t]
    return max(tiers, key=TIER_RANK.__getitem__) if tiers else None


def at_least(tier: str, minimum: str) -> bool:
    return TIER_RANK[tier] >= TIER_RANK[minimum]
