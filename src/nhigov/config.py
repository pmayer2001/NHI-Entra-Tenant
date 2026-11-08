"""Runtime configuration: config.yaml overlaid with NHIGOV_* environment variables.

Tenant and client IDs are identifiers, not secrets, but they stay out of the
public repo, so config.yaml is git-ignored and CI supplies env vars instead.
"""

from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field


class IdentityBackendKind(StrEnum):
    AGENT_ID = "agent_id"
    SERVICE_PRINCIPAL = "service_principal"


class ControlPlaneApp(BaseModel):
    """One of the two control-plane identities (ADR-005)."""

    client_id: str
    # None in CI: the app signs in with a GitHub OIDC token instead (federated credential).
    cert_path: Path | None = None

    def resolved_cert_path(self) -> Path:
        if self.cert_path is None:
            raise ValueError(f"no cert_path configured for {self.client_id}")
        return self.cert_path.expanduser()


class ControlPlane(BaseModel):
    provisioner: ControlPlaneApp
    scanner: ControlPlaneApp


class GraphSettings(BaseModel):
    base_url: str = "https://graph.microsoft.com"


class GitHubSettings(BaseModel):
    """Where the GitHub Actions runtime lives (ADR-014).

    Federated credentials trust exactly the `sub` claim of the job's OIDC token.
    Repositories created since mid-2026 put immutable numeric IDs in it:
    `repo:<owner>@<owner_id>/<repo>@<repository_id>:environment:<workflow id>`. With
    both IDs set, nhigov uses that form; without them, the older name-only form
    (`repo:<owner>/<repo>:...`), which only older repos that haven't opted in send.
    The IDs are public: `GET https://api.github.com/repos/<owner>/<repo>` returns
    `id` and `owner.id`.
    """

    repository: str | None = None  # "owner/name"
    owner_id: int | None = None
    repository_id: int | None = None

    @property
    def immutable(self) -> bool:
        return self.owner_id is not None and self.repository_id is not None

    @property
    def subject_repo(self) -> str | None:
        """The repository part of the OIDC subject, between `repo:` and `:environment`."""
        if not self.repository:
            return None
        if not self.immutable:
            return self.repository
        owner, _, name = self.repository.partition("/")
        return f"{owner}@{self.owner_id}/{name}@{self.repository_id}"


class SensitiveApiConfig(BaseModel):
    """How the mock resource API validates tokens (ADR-009). Filled in once it's registered."""

    # v2 tokens: the resource app's appId. v1 tokens: its identifier URI.
    audience: str
    token_version: Literal[1, 2] = 2


class Config(BaseModel):
    tenant_id: str
    # e.g. contoso.onmicrosoft.com. Substituted for {tenant_domain} in registry UPNs,
    # so the domain (which reveals the tenant) is never committed.
    tenant_domain: str | None = None
    identity_backend: IdentityBackendKind = IdentityBackendKind.SERVICE_PRINCIPAL
    # Optional so an agent job in CI (which needs neither app) can load config.
    control_plane: ControlPlane | None = None
    graph: GraphSettings = Field(default_factory=GraphSettings)
    sensitive_api: SensitiveApiConfig | None = None
    github: GitHubSettings = Field(default_factory=GitHubSettings)

    @property
    def cp(self) -> ControlPlane:
        """The control-plane apps, for commands that need them."""
        if self.control_plane is None:
            raise ValueError("config has no control_plane section (see config.example.yaml)")
        return self.control_plane


# env var -> path into the config dict
_ENV_OVERRIDES: dict[str, tuple[str, ...]] = {
    "NHIGOV_TENANT_ID": ("tenant_id",),
    "NHIGOV_TENANT_DOMAIN": ("tenant_domain",),
    "NHIGOV_IDENTITY_BACKEND": ("identity_backend",),
    "NHIGOV_PROVISIONER_CLIENT_ID": ("control_plane", "provisioner", "client_id"),
    "NHIGOV_PROVISIONER_CERT_PATH": ("control_plane", "provisioner", "cert_path"),
    "NHIGOV_SCANNER_CLIENT_ID": ("control_plane", "scanner", "client_id"),
    "NHIGOV_SCANNER_CERT_PATH": ("control_plane", "scanner", "cert_path"),
    "NHIGOV_API_AUDIENCE": ("sensitive_api", "audience"),
    "NHIGOV_API_TOKEN_VERSION": ("sensitive_api", "token_version"),
    "NHIGOV_GITHUB_REPOSITORY": ("github", "repository"),
    "NHIGOV_GITHUB_OWNER_ID": ("github", "owner_id"),
    "NHIGOV_GITHUB_REPOSITORY_ID": ("github", "repository_id"),
}


def _set_path(data: dict[str, Any], path: tuple[str, ...], value: str) -> None:
    node = data
    for key in path[:-1]:
        node = node.setdefault(key, {})
    node[path[-1]] = value


def load_tenant_domain(
    path: Path = Path("config.yaml"), env: dict[str, str] | None = None
) -> str | None:
    """Just the tenant domain, without requiring a complete config (offline CI has none)."""
    env = dict(os.environ) if env is None else env
    if "NHIGOV_TENANT_DOMAIN" in env:
        return env["NHIGOV_TENANT_DOMAIN"]
    if path.exists():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        value = data.get("tenant_domain")
        return str(value) if value else None
    return None


def load_config(path: Path = Path("config.yaml"), env: dict[str, str] | None = None) -> Config:
    env = dict(os.environ) if env is None else env
    data: dict[str, Any] = {}
    if path.exists():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    for var, key_path in _ENV_OVERRIDES.items():
        # GitHub passes a variable that doesn't exist as "", and pasted values can carry
        # a trailing newline: strip, and treat blank as unset.
        value = env.get(var, "").strip()
        if value:
            _set_path(data, key_path, value)
    return Config.model_validate(data)
