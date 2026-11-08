"""Credentials for the control-plane identities.

Uses the OAuth 2.0 client credentials grant with a *certificate* (ADR-005, P7):
azure-identity signs a short-lived JWT ("client assertion") with the private key,
and Entra checks it against the public key uploaded to the app registration.
No shared secret ever crosses the wire, so there is nothing to leak from logs.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Protocol

import httpx
from azure.core.exceptions import ClientAuthenticationError
from azure.identity import CertificateCredential
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from nhigov.agent_auth import TokenError, app_token, github_oidc_token, unverified_claims
from nhigov.config import Config, ControlPlaneApp

GRAPH_DEFAULT_SCOPE = "https://graph.microsoft.com/.default"


# Common AADSTS codes for app-only certificate auth, with what to check.
_AADSTS_HINTS = {
    "700027": "the certificate isn't uploaded to this app registration "
    "(or a different one is). Upload the .cer under Certificates & secrets > Certificates",
    "700016": "no app with this client ID exists in the tenant. Check client_id and tenant_id",
    "90002": "tenant not found. Check tenant_id in config.yaml",
    "500011": "the resource isn't available in this tenant",
}


class TokenAcquisitionError(Exception):
    """Entra refused to issue a token. The message says which identity and why."""


def _thumbprint(cert_path: Path) -> str:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return cert.fingerprint(hashes.SHA1()).hex().upper()  # noqa: S303


class TokenProvider(Protocol):
    """Anything that returns a bearer token string. Lets tests skip azure-identity."""

    def __call__(self) -> str: ...


class CertificateTokenProvider:
    """App-only Graph token for one control-plane app, backed by a PEM certificate.

    `.default` asks for every *application permission* already admin-consented to
    the app: app-only tokens cannot request a subset (ADR-007).
    """

    def __init__(
        self,
        tenant_id: str,
        app: ControlPlaneApp,
        name: str = "app",
        scope: str = GRAPH_DEFAULT_SCOPE,
    ):
        cert_path = app.resolved_cert_path()
        if not cert_path.exists():
            raise FileNotFoundError(
                f"Certificate not found at {cert_path}. Run `nhigov cert new` first "
                "(see scripts/bootstrap_tenant.md)."
            )
        self._credential = CertificateCredential(
            tenant_id=tenant_id, client_id=app.client_id, certificate_path=str(cert_path)
        )
        self._scope = scope
        self._name = name
        self._cert_path = cert_path

    def __call__(self) -> str:
        # azure-identity caches the token in memory and refreshes it near expiry.
        try:
            return self._credential.get_token(self._scope).token
        except ClientAuthenticationError as exc:
            match = re.search(r"AADSTS(\d+)", str(exc))
            code = match.group(1) if match else ""
            hint = _AADSTS_HINTS.get(code, "see the AADSTS message above")
            raise TokenAcquisitionError(
                f"{self._name} could not get a token (AADSTS{code or '?'}): {hint}.\n"
                f"  local cert : {self._cert_path}\n"
                f"  thumbprint : {_thumbprint(self._cert_path)}"
            ) from exc


class FederatedTokenProvider:
    """App-only Graph token in GitHub Actions: the job's OIDC token is the client
    assertion, accepted through a federated credential on the app (ADR-014). Nothing
    to store or leak: the GitHub token lives minutes and only that job can get one."""

    def __init__(self, tenant_id: str, client_id: str, name: str, scope: str = GRAPH_DEFAULT_SCOPE):
        self._tenant_id, self._client_id, self._name, self._scope = (
            tenant_id,
            client_id,
            name,
            scope,
        )
        self._token: tuple[str, float] | None = None

    def __call__(self) -> str:
        if self._token and self._token[1] - time.time() > 300:
            return self._token[0]
        with httpx.Client(timeout=30.0) as http:
            try:
                token = app_token(http, self._tenant_id, self._client_id,
                                  lambda: github_oidc_token(http), self._scope)  # fmt: skip
            except TokenError as exc:
                raise TokenAcquisitionError(f"{self._name} (GitHub OIDC): {exc}") from exc
        self._token = (token, float(unverified_claims(token).get("exp", 0)))
        return token


def _provider(config: Config, app: ControlPlaneApp, name: str) -> TokenProvider:
    """Certificate locally; GitHub OIDC in Actions when no certificate is configured."""
    if app.cert_path is None and os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"):
        return FederatedTokenProvider(config.tenant_id, app.client_id, name)
    return CertificateTokenProvider(config.tenant_id, app, name)


def provisioner_token(config: Config) -> TokenProvider:
    return _provider(config, config.cp.provisioner, "nhigov-provisioner")


def scanner_token(config: Config) -> TokenProvider:
    return _provider(config, config.cp.scanner, "nhigov-scanner")
