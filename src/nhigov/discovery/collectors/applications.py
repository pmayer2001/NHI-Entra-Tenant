"""App registrations (including agent identity blueprints), their credentials and owners.

Credentials live on the *application*: secrets in passwordCredentials, certificates
in keyCredentials, and federated credentials (no secret at all) as a child
collection. Graph returns credential metadata only, never the secret or key.
"""

from __future__ import annotations

from typing import Any

from nhigov.graph.client import GraphClient

APP_SELECT = (
    "id,appId,displayName,tags,createdDateTime,signInAudience,passwordCredentials,keyCredentials"
)
OWNER_SELECT = "id,displayName,userPrincipalName,accountEnabled,userType,appId"


def collect_applications(graph: GraphClient) -> tuple[list[dict[str, Any]], set[str]]:
    blueprint_ids = {
        b["id"]
        for b in graph.list_all(
            "applications/microsoft.graph.agentIdentityBlueprint", params={"$select": "id"}
        )
    }
    apps = list(graph.list_all("applications", params={"$select": APP_SELECT}))
    for app in apps:
        app["owners"] = list(
            graph.list_all(f"applications/{app['id']}/owners", params={"$select": OWNER_SELECT})
        )
        app["federatedIdentityCredentials"] = list(
            graph.list_all(f"applications/{app['id']}/federatedIdentityCredentials")
        )
        if app["id"] in blueprint_ids:
            app["sponsors"] = list(
                graph.list_all(
                    f"applications/{app['id']}/microsoft.graph.agentIdentityBlueprint/sponsors",
                    params={"$select": "id"},
                )
            )
    return apps, blueprint_ids
