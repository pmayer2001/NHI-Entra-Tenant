"""How an NHI gets a token for a resource, on either backend (ADR-003, Phase 0 spike).

Agent ID: the agent identity has no credential. The *blueprint* proves possession
of its certificate and asks for an exchange token bound to one agent (T1, via
`fmi_path`); the agent identity then presents T1 as its own client assertion
and receives a token *as itself* (T2).

Service principal: the NHI's own app registration holds its certificate, so a
single client-credentials request returns the token.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx

from nhigov.agent_auth import agent_identity_token, app_token, blueprint_exchange_token
from nhigov.certs import DEFAULT_CERT_DIR
from nhigov.reconcile.state import TenantState


class NotProvisioned(Exception):
    """The NHI isn't in the state file yet: run `nhigov apply` first."""


@dataclass(frozen=True)
class AgentCredentials:
    key: str  # "<workflow>/<agent>"
    backend: str
    client_id: str  # the agent identity's appId, or the SP-backend app's appId
    pem: Path  # private key + cert: the blueprint's (Agent ID) or the NHI's own
    blueprint_app_id: str | None = None


def credentials_for(
    key: str, state: TenantState, cert_dir: Path = DEFAULT_CERT_DIR
) -> AgentCredentials:
    rec = state.nhis.get(key)
    if rec is None or rec.app_id is None:
        raise NotProvisioned(f"{key} isn't provisioned; run `nhigov plan` / `nhigov apply`")
    workflow, agent = key.split("/", 1)
    if rec.backend == "agent_id":
        bp = state.blueprints.get(agent)
        if bp is None:
            raise NotProvisioned(f"blueprint for {agent} isn't in state")
        pem = cert_dir.expanduser() / f"bp-{agent}.pem"
        return AgentCredentials(key, rec.backend, rec.app_id, pem, bp.app_id)
    pem = cert_dir.expanduser() / f"nhi-{workflow}-{agent}.pem"
    return AgentCredentials(key, rec.backend, rec.app_id, pem)


def acquire_token(http: httpx.Client, tenant_id: str, creds: AgentCredentials, scope: str) -> str:
    if creds.backend == "agent_id":
        assert creds.blueprint_app_id is not None
        t1 = blueprint_exchange_token(
            http, tenant_id, creds.blueprint_app_id, creds.pem, creds.client_id
        )
        return agent_identity_token(http, tenant_id, creds.client_id, t1, scope)
    return app_token(http, tenant_id, creds.client_id, creds.pem, scope)
