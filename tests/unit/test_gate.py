"""The first gate: Entra refuses API tokens to clients without a role (mocked token endpoint)."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import httpx
import pytest
import respx

from nhigov.agent_auth import TOKEN_URL
from nhigov.certs import generate_self_signed
from nhigov.probe.gate import NOT_ASSIGNED, GateResult, check_gate

TENANT = "11111111-1111-1111-1111-111111111111"
SCOPE = "api://nhigov-sensitive-records/.default"
URL = TOKEN_URL.format(tenant=TENANT)


@pytest.fixture(scope="module")
def pem(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return generate_self_signed("gate-test", tmp_path_factory.mktemp("certs"), 1, False).private_pem


def _check(pem: Path) -> GateResult:
    with httpx.Client() as http:
        return check_gate(http, TENANT, "nhigov-scanner", "client-id", pem, SCOPE)


@respx.mock
def test_unassigned_client_refusal_passes(pem: Path) -> None:
    route = respx.post(URL).respond(
        400,
        json={
            "error": "invalid_grant",
            "error_description": "AADSTS501051: Application 'x' is not assigned to a role.\nTrace",
            "error_codes": [NOT_ASSIGNED],
        },
    )
    result = _check(pem)
    assert result.refused is True
    sent = dict(httpx.QueryParams(route.calls[0].request.content.decode()))
    assert sent["scope"] == SCOPE
    assert sent["grant_type"] == "client_credentials"
    assert "client_secret" not in sent  # P7: certificate assertion only


@respx.mock
def test_refusal_for_another_reason_is_not_a_pass(pem: Path) -> None:
    respx.post(URL).respond(
        401,
        json={
            "error": "invalid_client",
            "error_description": "AADSTS700027",
            "error_codes": [700027],
        },
    )
    result = _check(pem)
    assert result.refused is False
    assert result.codes == (700027,)


@respx.mock
def test_issued_token_is_a_failure_and_reports_roles(pem: Path) -> None:
    payload = base64.urlsafe_b64encode(json.dumps({"roles": ["Records.Read.All"]}).encode())
    respx.post(URL).respond(json={"access_token": f"h.{payload.decode().rstrip('=')}.s"})
    result = _check(pem)
    assert result.refused is False
    assert result.granted_roles == ("Records.Read.All",)
