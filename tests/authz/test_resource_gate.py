"""LIVE: Entra refuses tokens for the Sensitive API to clients holding none of its roles.

Needs config.yaml and the control-plane certs in ~/.nhigov/certs/. Only requests
tokens; never changes the tenant. Run: uv run pytest tests/authz -m live
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from nhigov.config import load_config
from nhigov.probe.gate import check_gate
from nhigov.registry.loader import load_registry

pytestmark = pytest.mark.live

CONFIG = Path("config.yaml")


@pytest.mark.parametrize("identity", ["scanner", "provisioner"])
def test_unassigned_control_plane_identity_gets_no_api_token(identity: str) -> None:
    if not CONFIG.exists():
        pytest.skip("no config.yaml: live tests need a tenant")
    cfg = load_config(CONFIG)
    client = getattr(cfg.control_plane, identity)
    if not client.resolved_cert_path().exists():
        pytest.skip(f"no certificate for nhigov-{identity}")
    registry, _ = load_registry(Path("registry"), cfg.tenant_domain or "tenant.example")
    scope = f"{registry.resources['res-sensitive-records'].identifier_uri}/.default"

    with httpx.Client(timeout=30.0) as http:
        result = check_gate(
            http, cfg.tenant_id, identity, client.client_id, client.resolved_cert_path(), scope
        )
    assert result.refused, f"expected AADSTS501051, got {result}"
