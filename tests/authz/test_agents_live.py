"""LIVE (P8): every NHI can do what the registry grants it, and nothing else.

Tokens are real (issued by Entra to each NHI). The API is the real FastAPI app,
run in-process, validating signatures against the tenant's real JWKS. Which
NHIs and roles to test comes from the registry, so a new workflow is tested
without editing this file.

Needs config.yaml, state/tenant-state.json (after `nhigov apply`) and the
certificates in ~/.nhigov/certs/. Only requests tokens and calls the local API;
never changes the tenant. Run: uv run pytest tests/authz
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from nhigov.agent_auth import (
    TokenError,
    agent_identity_token,
    blueprint_exchange_token,
    unverified_claims,
)
from nhigov.agents.identity import acquire_token, credentials_for
from nhigov.config import Config, load_config
from nhigov.lifecycle.state import load_lifecycle
from nhigov.reconcile.desired import DesiredNhi, build_desired
from nhigov.reconcile.state import TenantState, load_state
from nhigov.registry.loader import load_registry
from nhigov.registry.models import Backend
from sensitive_api.app import DEFAULT_DATA, RecordStore, create_app
from sensitive_api.auth import JwksCache, TokenValidator, http_jwks_fetcher
from sensitive_api.redaction import PII
from sensitive_api.settings import ApiSettings
from sensitive_api.usage import UsageLog

pytestmark = pytest.mark.live

CONFIG, STATE = Path("config.yaml"), Path("state/tenant-state.json")
RESOURCE_ID = "res-sensitive-records"
REC = "rec-0001"
ROUTE_FOR_ROLE = {
    "Records.Read.Metadata": ("GET", "/records"),
    "Records.Read.Redacted": ("GET", f"/records/{REC}"),
    "Records.Annotate": ("POST", f"/records/{REC}/notes"),
}
HUMAN_ONLY = ("GET", f"/records/{REC}/full")
# "credential was issued for agent blueprint X and agent identity Y, but ..."
CROSS_BLUEPRINT = 7002134
RECORDS: list[dict[str, Any]] = json.loads(DEFAULT_DATA.read_text(encoding="utf-8"))
PII_VALUES = {str(r[f]) for r in RECORDS for f in PII}

# Which NHIs to test: every enabled (workflow, agent) pair in the registry. NHIs the
# lifecycle engine has disabled (holds) get the opposite test: Entra must refuse them.
_REGISTRY, _ = load_registry(Path("registry"))
_DESIRED = build_desired(_REGISTRY, Backend.AGENT_ID, load_lifecycle().holds())
NHIS = sorted(k for k, n in _DESIRED.nhis.items() if n.should_be_enabled)
HELD = sorted(k for k, n in _DESIRED.nhis.items() if n.hold)
# "Application '...' is disabled."
DISABLED_APP = 7000112


@dataclass
class Live:
    cfg: Config
    state: TenantState
    scope: str
    api: TestClient
    usage_log: Path
    tokens: dict[str, str]

    def nhi(self, key: str) -> DesiredNhi:
        return _DESIRED.nhis[key]

    def call(self, key: str, method: str, path: str) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self.tokens[key]}"}
        body = {"text": "authz test note"} if method == "POST" else None
        return self.api.request(method, path, headers=headers, json=body)


@pytest.fixture(scope="module")
def live(tmp_path_factory: pytest.TempPathFactory) -> Live:
    if not CONFIG.exists() or not STATE.exists():
        pytest.skip("live tests need config.yaml and state/tenant-state.json (run nhigov apply)")
    cfg = load_config(CONFIG)
    state = load_state(STATE)
    resource = state.resources.get(RESOURCE_ID)
    if resource is None:
        pytest.skip(f"{RESOURCE_ID} isn't provisioned")
    scope = f"{_REGISTRY.resources[RESOURCE_ID].identifier_uri}/.default"

    tokens = {}
    with httpx.Client(timeout=30.0) as http:
        for key in NHIS:
            tokens[key] = acquire_token(http, cfg.tenant_id, credentials_for(key, state), scope)

    settings = ApiSettings(tenant_id=cfg.tenant_id, audience=resource.app_id)
    usage_log = tmp_path_factory.mktemp("usage") / "usage.log"
    app = create_app(
        TokenValidator(settings, JwksCache(http_jwks_fetcher(settings.jwks_url))),
        RecordStore.from_file(),
        UsageLog(usage_log),
    )
    return Live(cfg, state, scope, TestClient(app), usage_log, tokens)


def granted(key: str) -> set[str]:
    return {g.role for g in _DESIRED.nhis[key].grants if g.resource_id == RESOURCE_ID}


# ------------------------------------------------------------------ the tokens Entra issues


@pytest.mark.parametrize("key", NHIS)
def test_real_token_carries_exactly_the_declared_roles(live: Live, key: str) -> None:
    claims = unverified_claims(live.tokens[key])  # inspection; the API verifies below
    rec = live.state.nhis[key]
    assert claims["aud"] == live.state.resources[RESOURCE_ID].app_id  # v2: aud is the appId
    assert claims["iss"].endswith("/v2.0")
    assert claims.get("idtyp") == "app"  # the optional claim requested in Phase 2
    assert set(claims.get("roles", [])) == granted(key)
    assert claims["oid"] == rec.principal_id
    assert claims["azp"] == rec.app_id  # the agent itself, not its blueprint
    # Observed: v2 tokens for our API don't name the blueprint (the spike's v1 Graph
    # tokens carried xms_par_app_azp). Blueprint attribution comes from state instead.
    assert "xms_par_app_azp" not in claims


# ------------------------------------------------------------------ positive and negative


@pytest.mark.parametrize("key", NHIS)
def test_every_granted_role_works(live: Live, key: str) -> None:
    for role in sorted(granted(key)):
        method, path = ROUTE_FOR_ROLE[role]
        response = live.call(key, method, path)
        assert response.status_code in (200, 201), f"{role}: {response.text}"


@pytest.mark.parametrize("key", NHIS)
def test_every_other_route_is_403(live: Live, key: str) -> None:
    denied = [ROUTE_FOR_ROLE[r] for r in sorted(set(ROUTE_FOR_ROLE) - granted(key))]
    for method, path in [*denied, HUMAN_ONLY]:
        response = live.call(key, method, path)
        assert response.status_code == 403, f"{method} {path}: {response.status_code}"


@pytest.mark.parametrize("key", NHIS)
def test_no_pii_in_any_agent_response(live: Live, key: str) -> None:
    bodies = []
    for role in sorted(granted(key)):
        method, path = ROUTE_FOR_ROLE[role]
        bodies.append(live.call(key, method, path).text)
    if "Records.Read.Redacted" in granted(key):
        bodies += [live.call(key, "GET", f"/records/{r['id']}").text for r in RECORDS]
    leaked = {v for v in PII_VALUES for body in bodies if v in body}
    assert leaked == set()


@pytest.mark.parametrize("key", NHIS)
def test_usage_log_attributes_the_call_to_the_nhi(live: Live, key: str) -> None:
    role = sorted(granted(key))[0]
    live.call(key, *ROUTE_FOR_ROLE[role])
    rec = live.state.nhis[key]
    lines = [json.loads(x) for x in live.usage_log.read_text(encoding="utf-8").splitlines()]
    mine = [x for x in lines if x["oid"] == rec.principal_id and x["outcome"] == "allowed"]
    assert mine, "no allowed call logged for this NHI"
    assert mine[-1]["role_used"] in granted(key)
    assert mine[-1]["appid"] == rec.app_id


# ------------------------------------------------------------------ lifecycle (ADR-012)


@pytest.mark.parametrize("key", HELD)
def test_an_nhi_disabled_by_the_lifecycle_gets_no_token(live: Live, key: str) -> None:
    """Disabling is enforced by Entra at the token endpoint, not just recorded by us."""
    with httpx.Client(timeout=30.0) as http, pytest.raises(TokenError) as refused:
        acquire_token(http, live.cfg.tenant_id, credentials_for(key, live.state), live.scope)
    assert DISABLED_APP in refused.value.codes


# ------------------------------------------------------------------ blast radius (ADR-003)


def test_a_blueprint_cannot_become_another_blueprints_agent(live: Live) -> None:
    """The spike showed one blueprint reaches all of *its* agents. This checks the
    boundary between blueprints. Observed: Entra still issues T1 for a foreign agent,
    but refuses the T2 exchange with AADSTS7002134, so the boundary holds at T2."""
    agent_id_nhis = [k for k in NHIS if live.state.nhis[k].backend == "agent_id"]
    summarizer = next(k for k in agent_id_nhis if k.endswith("/agent-summarizer"))
    router = next(k for k in agent_id_nhis if k.endswith("/agent-router"))
    creds = credentials_for(summarizer, live.state)
    assert creds.blueprint_app_id is not None
    router_app_id = live.state.nhis[router].app_id
    assert router_app_id is not None
    with httpx.Client(timeout=30.0) as http:
        t1 = blueprint_exchange_token(
            http, live.cfg.tenant_id, creds.blueprint_app_id, creds.pem, router_app_id
        )
        with pytest.raises(TokenError) as refused:
            agent_identity_token(http, live.cfg.tenant_id, router_app_id, t1, live.scope)
    assert CROSS_BLUEPRINT in refused.value.codes
