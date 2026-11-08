"""The humans behind NHIs (owners, sponsors) and whether they can still be accountable.

A sponsor whose account is disabled or deleted is the classic orphaning path:
the NHI keeps working while nobody answers for it (NHI-002, ADR-012).
"""

from __future__ import annotations

from typing import Any

from nhigov.graph.client import GraphClient

USER_SELECT = "id,userPrincipalName,accountEnabled,userType"


def collect_users(graph: GraphClient, ids_or_upns: set[str]) -> dict[str, dict[str, Any]]:
    """Keyed by both object ID and lower-cased UPN. Missing users are left out."""
    users: dict[str, dict[str, Any]] = {}
    for ref in sorted(ids_or_upns):
        response = graph.request(
            "GET", f"users/{ref}", params={"$select": USER_SELECT}, check=False
        )
        if response.status_code == 404:
            continue
        response.raise_for_status()
        user: dict[str, Any] = response.json()
        users[user["id"]] = user
        users[str(user["userPrincipalName"]).lower()] = user
    return users
