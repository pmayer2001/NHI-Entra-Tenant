"""Live check: does Entra refuse tokens for our API to clients that hold none of its roles?

The API's service principal has `appRoleAssignmentRequired: true`. With that
set, Entra itself refuses the client-credentials request (AADSTS501051) from
any client without an app role assignment on the API, before a token exists.
The API's own 403s are the second gate; this is the first.

Uses the control-plane identities as the "unassigned clients": neither holds a
role on the API, and they're the only credentials we have before Phase 3.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx

from nhigov.agent_auth import (
    JWT_BEARER,
    TokenError,
    client_assertion,
    request_token,
    unverified_claims,
)

NOT_ASSIGNED = 501051  # "Application ... is not assigned to a role for the application"


@dataclass(frozen=True)
class GateResult:
    identity: str
    refused: bool  # True only for the expected refusal, AADSTS501051
    codes: tuple[int, ...] = ()
    detail: str = ""
    granted_roles: tuple[str, ...] = ()  # set only if a token was (wrongly) issued


def request_api_token(
    http: httpx.Client, tenant_id: str, client_id: str, pem: Path, scope: str
) -> str:
    return request_token(
        http,
        tenant_id,
        {
            "client_id": client_id,
            "scope": scope,
            "grant_type": "client_credentials",
            "client_assertion_type": JWT_BEARER,
            "client_assertion": client_assertion(pem, client_id, tenant_id),
        },
    )


def check_gate(
    http: httpx.Client, tenant_id: str, identity: str, client_id: str, pem: Path, scope: str
) -> GateResult:
    try:
        token = request_api_token(http, tenant_id, client_id, pem, scope)
    except TokenError as exc:
        first_line = exc.description.splitlines()[0] if exc.description else exc.error
        return GateResult(identity, NOT_ASSIGNED in exc.codes, tuple(exc.codes), first_line)
    # Inspection only: we're reporting a failed gate, not authorizing anything.
    roles = tuple(unverified_claims(token).get("roles", []))
    return GateResult(identity, False, detail="token issued", granted_roles=roles)
