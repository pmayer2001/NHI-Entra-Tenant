from __future__ import annotations

import base64
import json
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from nhigov.agent_auth import (
    JWT_BEARER,
    TOKEN_EXCHANGE_SCOPE,
    TokenError,
    agent_identity_token,
    blueprint_exchange_token,
    client_assertion,
    unverified_claims,
)
from nhigov.certs import generate_self_signed

TENANT = "tenant-x"
TOKEN = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"


def _b64d(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def test_client_assertion_is_signed_and_well_formed(tmp_path: Path) -> None:
    cert = generate_self_signed("bp", tmp_path)
    jwt = client_assertion(cert.private_pem, "bp-app", TENANT)
    header_b64, claims_b64, sig_b64 = jwt.split(".")

    header = json.loads(_b64d(header_b64))
    claims = json.loads(_b64d(claims_b64))
    public = x509.load_pem_x509_certificate(cert.public_cer.read_bytes())

    assert header["alg"] == "RS256"
    assert _b64d(header["x5t#S256"]) == public.fingerprint(hashes.SHA256())
    assert claims["iss"] == claims["sub"] == "bp-app"
    assert claims["aud"] == TOKEN
    assert claims["exp"] - claims["nbf"] == 600
    # Raises InvalidSignature if the signature doesn't match the uploaded public key.
    public.public_key().verify(  # type: ignore[call-arg]
        _b64d(sig_b64),
        f"{header_b64}.{claims_b64}".encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


@respx.mock
def test_two_step_exchange_sends_documented_parameters(tmp_path: Path) -> None:
    cert = generate_self_signed("bp", tmp_path)
    route = respx.post(TOKEN).mock(
        side_effect=[
            httpx.Response(200, json={"access_token": "T1"}),
            httpx.Response(200, json={"access_token": "T2"}),
        ]
    )
    with httpx.Client() as http:
        t1 = blueprint_exchange_token(http, TENANT, "bp-app", cert.private_pem, "agent-a")
        t2 = agent_identity_token(
            http, TENANT, "agent-a", t1, "https://graph.microsoft.com/.default"
        )

    assert (t1, t2) == ("T1", "T2")
    step1 = parse_qs(route.calls[0].request.content.decode())
    step2 = parse_qs(route.calls[1].request.content.decode())
    assert step1["client_id"] == ["bp-app"]
    assert step1["fmi_path"] == ["agent-a"]
    assert step1["scope"] == [TOKEN_EXCHANGE_SCOPE]
    assert step1["client_assertion_type"] == [JWT_BEARER]
    assert step2["client_id"] == ["agent-a"]
    assert step2["client_assertion"] == ["T1"]
    assert "fmi_path" not in step2


@respx.mock
def test_token_error_carries_aadsts_codes() -> None:
    respx.post(TOKEN).respond(
        400,
        json={
            "error": "invalid_client",
            "error_description": "AADSTS700027: key not found\r\nTrace ID: x",
            "error_codes": [700027],
        },
    )
    with httpx.Client() as http, pytest.raises(TokenError) as exc:
        agent_identity_token(http, TENANT, "a", "T1", "s")
    assert exc.value.codes == [700027]
    assert exc.value.error == "invalid_client"


def test_unverified_claims_decodes_payload() -> None:
    payload = base64.urlsafe_b64encode(json.dumps({"idtyp": "app"}).encode()).rstrip(b"=")
    assert unverified_claims(f"h.{payload.decode()}.s") == {"idtyp": "app"}
