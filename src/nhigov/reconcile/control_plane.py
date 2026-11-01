"""Report-only check of the control plane's Graph permissions (P9).

The provisioner and scanner were bootstrapped by hand and are never changed by
`apply` (Paul's decision, 2026-11-01): a reconciler able to edit the
provisioner's own permissions is one bug away from granting itself more.
So plan compares what they hold with wf-control-plane.yaml and reports drift.
"""

from __future__ import annotations

from nhigov.graph.client import GraphClient
from nhigov.reconcile.desired import ControlPlaneGrants

MICROSOFT_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"


def graph_roles_held(graph: GraphClient, client_app_id: str) -> list[str] | None:
    """Microsoft Graph application permissions held by an app, or None if it isn't found."""
    sps = graph.get(
        "servicePrincipals", params={"$filter": f"appId eq '{client_app_id}'", "$select": "id"}
    ).get("value", [])
    graph_sp = graph.get(
        "servicePrincipals",
        params={"$filter": f"appId eq '{MICROSOFT_GRAPH_APP_ID}'", "$select": "id,appRoles"},
    ).get("value", [])
    if not sps or not graph_sp:
        return None
    names = {str(r["id"]): str(r["value"]) for r in graph_sp[0].get("appRoles", [])}
    return sorted(
        names.get(str(a["appRoleId"]), str(a["appRoleId"]))
        for a in graph.list_all(f"servicePrincipals/{sps[0]['id']}/appRoleAssignments")
        if a.get("resourceId") == graph_sp[0]["id"]
    )


def control_plane_notes(
    graph: GraphClient, expected: list[ControlPlaneGrants], client_ids: dict[str, str]
) -> list[str]:
    notes = []
    for cp in expected:
        client_id = client_ids.get(cp.agent_id)
        if client_id is None:
            notes.append(f"{cp.agent_id}: no client ID in config.yaml; Graph grants not checked")
            continue
        held = graph_roles_held(graph, client_id)
        if held is None:
            notes.append(f"{cp.agent_id}: service principal not found in the tenant")
            continue
        missing = sorted(set(cp.graph_roles) - set(held))
        extra = sorted(set(held) - set(cp.graph_roles))
        if missing:
            notes.append(f"{cp.agent_id}: registry declares but tenant lacks {', '.join(missing)}")
        if extra:
            notes.append(f"{cp.agent_id}: holds undeclared {', '.join(extra)} (NHI-007 drift)")
        if not missing and not extra:
            notes.append(f"{cp.agent_id}: Graph grants match the registry ({len(held)})")
    return notes
