"""How an NHI gets a token for a resource, on either backend (ADR-003, Agent ID token spike).

Agent ID: the agent identity has no credential. The *blueprint* proves possession
of its certificate and asks for an exchange token bound to one agent (T1, via
`fmi_path`); the agent identity then presents T1 as its own client assertion
and receives a token *as itself* (T2).

Service principal: the NHI's own app registration holds its certificate, so a
single client-credentials request returns the token.

In GitHub Actions the same flows run with the job's OIDC token in place of the
certificate: the blueprint (or SP-backend app) trusts it through a federated
credential bound to the workflow's GitHub environment (ADR-014). The state file
isn't in CI, so the object IDs come from environment variables instead.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import httpx

from nhigov.agent_auth import (
    AssertionSource,
    agent_identity_token,
    app_token,
    blueprint_exchange_token,
    github_oidc_token,
)
from nhigov.certs import DEFAULT_CERT_DIR
from nhigov.reconcile.state import TenantState


class NotProvisioned(Exception):
    """The NHI isn't in the state file yet: run `nhigov apply` first."""


@dataclass(frozen=True)
class AgentCredentials:
    key: str  # "<workflow>/<agent>"
    backend: str
    client_id: str  # the agent identity's appId, or the SP-backend app's appId
    # private key + cert: the blueprint's (Agent ID) or the NHI's own. None: GitHub OIDC.
    pem: Path | None
    blueprint_app_id: str | None = None

    @property
    def method(self) -> str:
        return "certificate" if self.pem else "GitHub OIDC (federated credential)"


# Set by the GitHub workflow from its environment's variables (`nhigov ci vars`).
ENV_BACKEND = "NHIGOV_AGENT_BACKEND"
ENV_CLIENT_ID = "NHIGOV_AGENT_CLIENT_ID"
ENV_BLUEPRINT = "NHIGOV_BLUEPRINT_APP_ID"


def credentials_from_env(key: str, env: dict[str, str] | None = None) -> AgentCredentials:
    """CI: no state file and no key; the job's OIDC token is the credential."""
    env = dict(os.environ) if env is None else env
    client_id = env.get(ENV_CLIENT_ID)
    if not client_id:
        raise NotProvisioned(f"{ENV_CLIENT_ID} isn't set; see `nhigov ci vars` for {key}")
    backend = env.get(ENV_BACKEND, "agent_id")
    blueprint = env.get(ENV_BLUEPRINT) if backend == "agent_id" else None
    if backend == "agent_id" and not blueprint:
        raise NotProvisioned(f"{ENV_BLUEPRINT} isn't set; see `nhigov ci vars` for {key}")
    return AgentCredentials(key, backend, client_id, None, blueprint)


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
    source: AssertionSource = creds.pem or (lambda: github_oidc_token(http))
    if creds.backend == "agent_id":
        assert creds.blueprint_app_id is not None
        t1 = blueprint_exchange_token(
            http, tenant_id, creds.blueprint_app_id, source, creds.client_id
        )
        return agent_identity_token(http, tenant_id, creds.client_id, t1, scope)
    return app_token(http, tenant_id, creds.client_id, source, scope)
