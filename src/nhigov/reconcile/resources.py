"""Registry Resource -> the app registration and service principal that represent it in Entra.

Pure functions: they build request bodies and never call Graph, so `plan` can
print exactly what `apply` will send.

Entra concepts:
* The **application** (app registration) is the API's definition: its identifier
  URI, the app roles it offers, and which token version it receives.
* The **service principal** is the API's instance in this tenant. App role
  assignments (an agent holding `Records.Read.Redacted`) attach to it.
"""

from __future__ import annotations

import uuid
from typing import Any

from nhigov.registry.models import Resource

# Fixed namespace for deriving app role IDs. Never change it: assignments point
# at role IDs, so new IDs would orphan every existing assignment.
ROLE_ID_NAMESPACE = uuid.UUID("6f1b3c3e-4d0a-5c2e-9a57-2b1d8e0c7f41")


def role_id(resource_id: str, role_value: str) -> str:
    """The same role always gets the same GUID, so a second apply changes nothing."""
    return str(uuid.uuid5(ROLE_ID_NAMESPACE, f"{resource_id}/{role_value}"))


def desired_application(resource: Resource) -> dict[str, Any]:
    if not resource.managed:
        raise ValueError(f"{resource.id} is not managed by nhigov (managed: false)")
    return {
        "displayName": resource.id,
        "signInAudience": "AzureADMyOrg",  # single tenant: no other tenant can get tokens for it
        "identifierUris": [resource.identifier_uri],
        "tags": ["nhigov:managed", f"nhigov:resource={resource.id}"],
        "api": {
            # v2: `aud` is the appId GUID, and custom identifier URIs are exempt from
            # the tenant's identifier URI restriction (ADR-009).
            "requestedAccessTokenVersion": 2,
        },
        "appRoles": [
            {
                "id": role_id(resource.id, role.value),
                "value": role.value,
                "displayName": role.value,
                "description": role.description,
                "allowedMemberTypes": list(role.member_types),
                "isEnabled": True,
            }
            for role in resource.app_roles
        ],
        "optionalClaims": {
            # Without this, app-only tokens carry no `idtyp`, and the API can't tell
            # an agent from a user reliably (ADR-009).
            "accessToken": [{"name": "idtyp", "essential": False, "additionalProperties": []}]
        },
    }


def desired_service_principal(app_id: str) -> dict[str, Any]:
    return {
        "appId": app_id,
        # Only principals holding one of the API's roles can get a token for it at all:
        # an unassigned client is refused by Entra before it ever reaches the API.
        "appRoleAssignmentRequired": True,
        "tags": ["nhigov:managed"],
    }
