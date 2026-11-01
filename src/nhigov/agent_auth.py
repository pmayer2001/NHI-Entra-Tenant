"""Agent ID token flow for autonomous agents (ADR-003).

An agent identity has no credential of its own. To act as one:

  T1  the *blueprint* authenticates with its certificate (a signed client
      assertion) and asks for `api://AzureADTokenExchange/.default`, naming the
      agent identity in `fmi_path`.
  T2  the agent identity then authenticates with T1 *as its client assertion*
      and asks for the real resource (e.g. Graph, or our Sensitive API).

This talks to the Entra token endpoint, not Graph, so it doesn't go through
GraphClient. Reference: Microsoft Learn, "Authenticate and acquire tokens for
autonomous agents" (read 2026-10-31).
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"  # noqa: S105 (public endpoint)
TOKEN_EXCHANGE_SCOPE = "api://AzureADTokenExchange/.default"  # noqa: S105 (scope name)
JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class TokenError(Exception):
    """The token endpoint refused a request. `codes` are the AADSTS numbers."""

    def __init__(self, error: str, description: str, codes: list[int]) -> None:
        super().__init__(f"{error}: {description.splitlines()[0] if description else ''}")
        self.error = error
        self.description = description
        self.codes = codes


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def client_assertion(pem_path: Path, client_id: str, tenant_id: str) -> str:
    """A short-lived RS256 JWT proving possession of the certificate's private key.

    The `x5t#S256` header is the certificate's SHA-256 thumbprint: it's how Entra
    finds which of the app's uploaded keyCredentials to verify the signature with.
    """
    pem = pem_path.read_bytes()
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("expected an RSA private key")
    cert = x509.load_pem_x509_certificate(pem)
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "x5t#S256": _b64url(cert.fingerprint(hashes.SHA256())),
    }
    now = int(time.time())
    claims = {
        "aud": TOKEN_URL.format(tenant=tenant_id),
        "iss": client_id,
        "sub": client_id,
        "jti": str(uuid.uuid4()),  # unique per assertion, so it can't be replayed
        "iat": now,
        "nbf": now,
        "exp": now + 600,
    }
    signing_input = ".".join(
        _b64url(json.dumps(part, separators=(",", ":")).encode()) for part in (header, claims)
    )
    signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{_b64url(signature)}"


def request_token(http: httpx.Client, tenant_id: str, form: dict[str, str]) -> str:
    response = http.post(TOKEN_URL.format(tenant=tenant_id), data=form)
    body: dict[str, Any] = response.json()
    if response.is_success and "access_token" in body:
        return str(body["access_token"])
    raise TokenError(
        str(body.get("error", response.status_code)),
        str(body.get("error_description", "")),
        [int(c) for c in body.get("error_codes", [])],
    )


def app_token(http: httpx.Client, tenant_id: str, client_id: str, pem: Path, scope: str) -> str:
    """A classic app-only token: the app proves possession of its own certificate.
    Used by service-principal-backend NHIs, which have their own credential."""
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


def blueprint_exchange_token(
    http: httpx.Client,
    tenant_id: str,
    blueprint_app_id: str,
    blueprint_pem: Path,
    agent_client_id: str,
) -> str:
    """T1: the blueprint's token, scoped by fmi_path to one agent identity."""
    return request_token(
        http,
        tenant_id,
        {
            "client_id": blueprint_app_id,
            "scope": TOKEN_EXCHANGE_SCOPE,
            "grant_type": "client_credentials",
            "client_assertion_type": JWT_BEARER,
            "client_assertion": client_assertion(blueprint_pem, blueprint_app_id, tenant_id),
            "fmi_path": agent_client_id,
        },
    )


def agent_identity_token(
    http: httpx.Client, tenant_id: str, agent_client_id: str, t1: str, scope: str
) -> str:
    """T2: a token *as the agent identity*, using T1 as its client assertion."""
    return request_token(
        http,
        tenant_id,
        {
            "client_id": agent_client_id,
            "scope": scope,
            "grant_type": "client_credentials",
            "client_assertion_type": JWT_BEARER,
            "client_assertion": t1,
        },
    )


def unverified_claims(token: str) -> dict[str, Any]:
    """Decode a JWT payload WITHOUT checking its signature: for inspection only.

    Never use this to make an authorization decision; resources must validate
    the signature against the tenant's JWKS (ADR-004).
    """
    payload = token.split(".")[1]
    claims: dict[str, Any] = json.loads(
        base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    )
    return claims
