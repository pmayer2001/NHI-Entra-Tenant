"""GitHub Actions runtime: OIDC token as the client assertion, IDs from the environment."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from typer.testing import CliRunner

from nhigov.agent_auth import EXCHANGE_AUDIENCE, GitHubOidcUnavailable, github_oidc_token
from nhigov.agents.identity import NotProvisioned, acquire_token, credentials_from_env
from nhigov.cli import app
from nhigov.config import GitHubSettings, load_config
from nhigov.reconcile.federated import WantedFic
from nhigov.reconcile.state import STATE_ENV, TenantState, load_state

TENANT = "tenant-x"
TOKEN = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
OIDC_URL = "https://pipelines.example/idtoken?api-version=2.0"
GH_ENV = {"ACTIONS_ID_TOKEN_REQUEST_URL": OIDC_URL, "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req-tok"}


@respx.mock
def test_github_oidc_token_asks_for_the_entra_exchange_audience() -> None:
    route = respx.get(url__startswith="https://pipelines.example/idtoken").respond(
        json={"value": "gh-oidc-jwt"}
    )
    with httpx.Client() as http:
        assert github_oidc_token(http, GH_ENV) == "gh-oidc-jwt"
    request = route.calls.last.request
    assert request.url.params["audience"] == EXCHANGE_AUDIENCE
    assert request.headers["Authorization"] == "Bearer req-tok"


def test_outside_github_there_is_no_oidc_token() -> None:
    with httpx.Client() as http, pytest.raises(GitHubOidcUnavailable, match="id-token: write"):
        github_oidc_token(http, {})


@respx.mock
def test_agent_token_in_ci_uses_the_github_token_instead_of_a_certificate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for k, v in GH_ENV.items():
        monkeypatch.setenv(k, v)
    respx.get(url__startswith="https://pipelines.example/idtoken").respond(json={"value": "gh"})
    token = respx.post(TOKEN).mock(
        side_effect=[
            httpx.Response(200, json={"access_token": "t1"}),
            httpx.Response(200, json={"access_token": "t2"}),
        ]
    )
    creds = credentials_from_env(
        "wf/agent",
        {"NHIGOV_AGENT_CLIENT_ID": "agent-1", "NHIGOV_BLUEPRINT_APP_ID": "bp-1"},
    )
    assert creds.pem is None and creds.method.startswith("GitHub OIDC")
    with httpx.Client() as http:
        assert acquire_token(http, TENANT, creds, "api://res/.default") == "t2"
    t1, t2 = (parse_qs(c.request.content.decode()) for c in token.calls)
    # T1: the blueprint presents GitHub's token; fmi_path still names the one agent.
    assert t1["client_id"] == ["bp-1"] and t1["client_assertion"] == ["gh"]
    assert t1["fmi_path"] == ["agent-1"]
    # T2: unchanged, the agent identity presents T1.
    assert t2["client_id"] == ["agent-1"] and t2["client_assertion"] == ["t1"]


def test_ci_credentials_need_the_ids_from_the_environment() -> None:
    with pytest.raises(NotProvisioned, match="NHIGOV_AGENT_CLIENT_ID"):
        credentials_from_env("wf/agent", {})
    with pytest.raises(NotProvisioned, match="NHIGOV_BLUEPRINT_APP_ID"):
        credentials_from_env("wf/agent", {"NHIGOV_AGENT_CLIENT_ID": "a"})
    sp = credentials_from_env(
        "wf/agent", {"NHIGOV_AGENT_CLIENT_ID": "a", "NHIGOV_AGENT_BACKEND": "service_principal"}
    )
    assert sp.blueprint_app_id is None


def test_state_comes_from_an_environment_variable_when_there_is_no_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = TenantState(blueprints={})
    monkeypatch.setenv(STATE_ENV, state.model_dump_json())
    assert load_state(tmp_path / "missing.json") == state


def test_config_loads_without_a_control_plane_for_agent_jobs(tmp_path: Path) -> None:
    cfg = load_config(
        tmp_path / "none.yaml", {"NHIGOV_TENANT_ID": "t", "NHIGOV_API_AUDIENCE": "aud"}
    )
    assert cfg.control_plane is None and cfg.sensitive_api is not None
    with pytest.raises(ValueError, match="control_plane"):
        _ = cfg.cp


def test_an_agent_may_only_run_where_the_registry_says(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # wf-usage-demo's summarizer lists only `local`: refused before any token request.
    for k, v in GH_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("NHIGOV_TENANT_ID", "t")
    result = CliRunner().invoke(
        app, ["agent", "run", "wf-usage-demo", "agent-summarizer", "--config", str(tmp_path / "x")]
    )
    assert result.exit_code != 0
    assert "github-actions as a runtime" in result.output


def test_new_repos_are_trusted_by_their_immutable_ids() -> None:
    # Repos created since mid-2026 send repo:<owner>@<id>/<repo>@<id>:...; a credential
    # with the name-only subject is refused (AADSTS700213, observed live).
    gh = GitHubSettings(repository="octo/nhigov", owner_id=11, repository_id=22)
    assert gh.subject_repo == "octo@11/nhigov@22"
    assert WantedFic("wf-x", gh.subject_repo).subject == "repo:octo@11/nhigov@22:environment:wf-x"
    # Without both IDs: the older name-only form.
    assert GitHubSettings(repository="octo/nhigov", owner_id=11).subject_repo == "octo/nhigov"
    assert GitHubSettings().subject_repo is None


def test_github_ids_can_come_from_the_environment(tmp_path: Path) -> None:
    cfg = load_config(
        tmp_path / "none.yaml",
        {
            "NHIGOV_TENANT_ID": "t",
            "NHIGOV_GITHUB_REPOSITORY": "octo/nhigov",
            "NHIGOV_GITHUB_OWNER_ID": "11",
            "NHIGOV_GITHUB_REPOSITORY_ID": "22",
        },
    )
    assert cfg.github.subject_repo == "octo@11/nhigov@22"


def test_a_ci_scan_without_state_fails_instead_of_calling_everything_shadow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for k, v in GH_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("NHIGOV_TENANT_ID", "t")
    monkeypatch.setenv("NHIGOV_TENANT_DOMAIN", "contoso.example")
    monkeypatch.setenv("NHIGOV_OWNER", "alice")
    monkeypatch.delenv(STATE_ENV, raising=False)
    result = CliRunner().invoke(
        app,
        ["scan", "--summary-only", "--config", str(tmp_path / "x"),
         "--state", str(tmp_path / "missing.json")],
    )  # fmt: skip
    assert result.exit_code == 2
    assert STATE_ENV in result.output and "shadow" in result.output


def test_blank_or_padded_environment_values_are_handled(tmp_path: Path) -> None:
    # GitHub sends a missing variable as ""; a pasted value can end in a newline.
    cfg = load_config(
        tmp_path / "none.yaml",
        {"NHIGOV_TENANT_ID": "t\n", "NHIGOV_TENANT_DOMAIN": "", "NHIGOV_API_AUDIENCE": " aud "},
    )
    assert cfg.tenant_id == "t" and cfg.tenant_domain is None
    assert cfg.sensitive_api is not None and cfg.sensitive_api.audience == "aud"


def test_a_ci_scan_without_the_tenant_domain_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for k, v in GH_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("NHIGOV_TENANT_ID", "t")
    monkeypatch.setenv("NHIGOV_TENANT_DOMAIN", "")
    result = CliRunner().invoke(app, ["scan", "--summary-only", "--config", str(tmp_path / "x")])
    assert result.exit_code == 2
    assert "NHIGOV_TENANT_DOMAIN" in result.output and "NHIGOV_OWNER" in result.output
