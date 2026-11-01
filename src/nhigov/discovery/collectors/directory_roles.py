"""Entra directory role assignments (RBAC over the *directory*, e.g. Global Administrator).

These are separate from app roles: an app role lets an NHI call an API, while a
directory role lets it administer Entra itself. No NHI here should hold one (NHI-006).
"""

from __future__ import annotations

from nhigov.graph.client import GraphClient


def collect_directory_roles(graph: GraphClient) -> dict[str, list[str]]:
    names = {
        d["id"]: d["displayName"]
        for d in graph.list_all(
            "roleManagement/directory/roleDefinitions", params={"$select": "id,displayName"}
        )
    }
    held: dict[str, list[str]] = {}
    for a in graph.list_all(
        "roleManagement/directory/roleAssignments",
        params={"$select": "principalId,roleDefinitionId"},
    ):
        role = str(a["roleDefinitionId"])
        held.setdefault(str(a["principalId"]), []).append(names.get(role, role))
    return held
