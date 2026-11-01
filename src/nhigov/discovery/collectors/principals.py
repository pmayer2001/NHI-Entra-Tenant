"""Service principals of every kind, and what each local one holds.

`servicePrincipalType` distinguishes Application / ManagedIdentity / Legacy; Agent
ID adds two subtypes found through typed-cast lists: blueprint principals and
agent identities. App role assignments (application permissions) are what an
app-only token's `roles` claim carries.
"""

from __future__ import annotations

from typing import Any

from nhigov.discovery.collectors.applications import OWNER_SELECT
from nhigov.graph.client import GraphClient

SP_SELECT = (
    "id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled,"
    "tags,passwordCredentials,keyCredentials,appRoles"
)
AGENTS = "servicePrincipals/microsoft.graph.agentIdentity"
BP_PRINCIPALS = "servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal"


def collect_service_principals(
    graph: GraphClient, tenant_id: str, local_app_ids: set[str]
) -> list[dict[str, Any]]:
    agents = {
        a["id"]: a
        for a in graph.list_all(
            AGENTS,
            params={"$select": "id,appId,displayName,accountEnabled,agentIdentityBlueprintId"},
        )
    }
    bp_principals = {b["id"] for b in graph.list_all(BP_PRINCIPALS, params={"$select": "id"})}
    sps = list(graph.list_all("servicePrincipals", params={"$select": SP_SELECT}))
    seen = {sp["id"] for sp in sps}
    # In case the plain listing leaves the Agent ID subtypes out.
    sps += [
        {**a, "servicePrincipalType": "Application"} for i, a in agents.items() if i not in seen
    ]

    for sp in sps:
        sp["agentKind"] = (
            "agentIdentity" if sp["id"] in agents
            else "blueprintPrincipal" if sp["id"] in bp_principals
            else None
        )  # fmt: skip
        if sp["id"] in agents:
            sp["agentIdentityBlueprintId"] = agents[sp["id"]].get("agentIdentityBlueprintId")
        local = (
            sp.get("appOwnerOrganizationId") == tenant_id
            or sp["appId"] in local_app_ids
            or sp["agentKind"] is not None
        )
        sp["local"] = local
        if not local:
            continue  # first-party / third-party: listed, not expanded
        sp["owners"] = list(
            graph.list_all(f"servicePrincipals/{sp['id']}/owners", params={"$select": OWNER_SELECT})
        )
        sp["appRoleAssignments"] = list(
            graph.list_all(f"servicePrincipals/{sp['id']}/appRoleAssignments")
        )
        if sp["agentKind"] == "agentIdentity":
            sp["sponsors"] = list(
                graph.list_all(
                    f"servicePrincipals/{sp['id']}/microsoft.graph.agentIdentity/sponsors",
                    params={"$select": "id"},
                )
            )
    return sps
