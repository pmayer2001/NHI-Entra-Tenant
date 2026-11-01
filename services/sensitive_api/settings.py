"""What the API needs to know to trust a token: which tenant, which audience, which version."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class ApiSettings:
    tenant_id: str
    # v2 tokens carry the API's appId (GUID) as `aud`; v1 tokens carry its identifier URI.
    audience: str
    # Set by the resource app's `api.requestedAccessTokenVersion`, not by the caller.
    token_version: Literal[1, 2] = 2
    usage_log: Path = Path("services/sensitive_api/usage.log")
    # Allowed clock skew between Entra and this host when checking exp/nbf.
    leeway_seconds: int = 60

    @property
    def issuer(self) -> str:
        if self.token_version == 1:
            return f"https://sts.windows.net/{self.tenant_id}/"
        return f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"

    @property
    def jwks_url(self) -> str:
        """The tenant's public signing keys (the same keys sign v1 and v2 tokens)."""
        return f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys"
