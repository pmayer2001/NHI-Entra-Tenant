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
    cert_path: Path

    def resolved_cert_path(self) -> Path:
        return self.cert_path.expanduser()


class ControlPlane(BaseModel):
    provisioner: ControlPlaneApp
    scanner: ControlPlaneApp


class GraphSettings(BaseModel):
    base_url: str = "https://graph.microsoft.com"


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
    control_plane: ControlPlane
    graph: GraphSettings = Field(default_factory=GraphSettings)
    sensitive_api: SensitiveApiConfig | None = None


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
        if var in env:
            _set_path(data, key_path, env[var])
    return Config.model_validate(data)
