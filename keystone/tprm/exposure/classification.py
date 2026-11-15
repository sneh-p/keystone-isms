"""Who owns an app: microsoft | internal | third_party | unknown."""

from __future__ import annotations

import json
from functools import lru_cache

from .paths import CONFIG_DIR


@lru_cache(maxsize=2)
def microsoft_owner_ids(path: str | None = None) -> frozenset[str]:
    d = json.loads(open(path or CONFIG_DIR / "microsoft_owner_tenants.json", encoding="utf-8").read())
    return frozenset(t["id"].lower() for t in d["tenant_ids"])


def classify(owner_org_id: str | None, tenant_id: str, service_principal_type: str | None = None, microsoft_ids: frozenset[str] | None = None) -> tuple[str, bool]:
    """Return (owner_class, needs_review).

    Null owners are never assumed to be Microsoft. Managed identities belong to the tenant.
    """
    ms = microsoft_ids if microsoft_ids is not None else microsoft_owner_ids()
    if owner_org_id:
        owner = owner_org_id.lower()
        if owner in ms:
            return "microsoft", False
        if owner == tenant_id.lower():
            return "internal", False
        return "third_party", False
    if (service_principal_type or "").lower() == "managedidentity":
        return "internal", False
    return "unknown", True
