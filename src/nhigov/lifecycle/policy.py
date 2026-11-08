"""Tenant app management policy: from *detecting* secrets (NHI-003) to *preventing* them (P7).

Two restrictions, on applications and service principals alike:
  passwordAddition + symmetricKeyAddition  no new client secrets (the portal treats
                                           these two as one setting, so both are set)
  asymmetricKeyLifetime                    new certificates valid at most N days

A PATCH replaces each restriction list it sends, so the current policy is read
first and our entries are merged into it: restrictions Microsoft or an admin set
(like Microsoft's identifier-URI rule) are kept.
"""

from __future__ import annotations

import copy
from typing import Any

JsonDict = dict[str, Any]
# Every app in the tenant, whenever it was created (Entra treats a missing
# createdDateTime as 2019-01-01, so the cutoff must be earlier than that).
ALL_APPS = "2015-01-01T00:00:00Z"
TARGETS = ("applicationRestrictions", "servicePrincipalRestrictions")


def _want(max_cert_days: int) -> dict[str, list[JsonDict]]:
    def r(kind: str, lifetime: str | None = None) -> JsonDict:
        return {"restrictionType": kind, "state": "enabled", "maxLifetime": lifetime,
                "restrictForAppsCreatedAfterDateTime": ALL_APPS}  # fmt: skip

    return {
        "passwordCredentials": [r("passwordAddition"), r("symmetricKeyAddition")],
        "keyCredentials": [r("asymmetricKeyLifetime", f"P{max_cert_days}D")],
    }


def _same(current: JsonDict, wanted: JsonDict) -> bool:
    keys = ("state", "maxLifetime")
    return all(current.get(k) == wanted.get(k) for k in keys)


def _writable(value: Any) -> Any:
    """Drop fields Graph returns but rejects on PATCH (400 "Invalid property",
    live 2026-11-01): `isStateSetByMicrosoft` on the identifier-URI rule."""
    if isinstance(value, dict):
        return {k: _writable(v) for k, v in value.items() if k != "isStateSetByMicrosoft"}
    if isinstance(value, list):
        return [_writable(v) for v in value]
    return value


def desired_policy(current: JsonDict, max_cert_days: int) -> tuple[JsonDict, list[str]]:
    """(PATCH body, human-readable changes). An empty change list means nothing to do."""
    body: JsonDict = {}
    changes: list[str] = []
    if not current.get("isEnabled"):
        body["isEnabled"] = True
        changes.append("enable the tenant default policy")
    for target in TARGETS:
        config: JsonDict = _writable(copy.deepcopy(current.get(target) or {}))
        touched = False
        for collection, wanted in _want(max_cert_days).items():
            existing: list[JsonDict] = list(config.get(collection) or [])
            for w in wanted:
                kind = w["restrictionType"]
                found = next((e for e in existing if e.get("restrictionType") == kind), None)
                if found is not None and _same(found, w):
                    continue
                existing = [e for e in existing if e.get("restrictionType") != w["restrictionType"]]
                existing.append(w)
                touched = True
                label = w["restrictionType"] + (f" {w['maxLifetime']}" if w["maxLifetime"] else "")
                changes.append(f"{target}: {label}")
            config[collection] = existing
        if touched:
            body[target] = config  # whole config, so untouched restrictions survive
    return body, changes
