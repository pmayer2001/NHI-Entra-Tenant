"""Sensitive Records API: unit tests with locally signed tokens.

Tokens are signed with a throwaway RSA key whose public half is served as a
fake JWKS, so every check (signature, iss, aud, exp, roles) runs for real
without a tenant. tests/authz repeats the role checks with real Entra tokens.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from sensitive_api.app import DEFAULT_DATA, RecordStore, create_app
from sensitive_api.auth import InvalidToken, JwksCache, TokenValidator, http_jwks_fetcher
from sensitive_api.redaction import PII, REDACTED, VIEWS, render
from sensitive_api.settings import ApiSettings

TENANT = "11111111-1111-1111-1111-111111111111"
AUDIENCE = "22222222-2222-2222-2222-222222222222"  # the API's appId (v2 tokens)
AGENT = "33333333-3333-3333-3333-333333333333"  # agent identity: appid == oid
BLUEPRINT = "44444444-4444-4444-4444-444444444444"
USER = "55555555-5555-5555-5555-555555555555"
KID = "test-key-1"
SETTINGS = ApiSettings(tenant_id=TENANT, audience=AUDIENCE)
AGENT_ROLES = ["Records.Read.Metadata", "Records.Read.Redacted", "Records.Annotate"]
RECORDS: list[dict[str, Any]] = json.loads(DEFAULT_DATA.read_text(encoding="utf-8"))
REC = RECORDS[0]["id"]


def _new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


SIGNING_KEY = _new_key()
OTHER_KEY = _new_key()  # an attacker's key


def jwks(*pairs: tuple[str, rsa.RSAPrivateKey]) -> dict[str, Any]:
    keys = []
    for kid, key in pairs:
        jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
        keys.append({**jwk, "kid": kid, "use": "sig"})
    return {"keys": keys}


def claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    base: dict[str, Any] = {
        "iss": SETTINGS.issuer,
        "aud": AUDIENCE,
        "tid": TENANT,
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
        "azp": AGENT,
        "oid": AGENT,
        "idtyp": "app",
        "roles": AGENT_ROLES,
        "xms_par_app_azp": BLUEPRINT,
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not None}


def user_claims(**overrides: Any) -> dict[str, Any]:
    user: dict[str, Any] = {
        "oid": USER, "azp": "some-client-app", "idtyp": "user", "scp": "access_as_user",
        "roles": ["Records.Read.All"], "xms_par_app_azp": None,
    }  # fmt: skip
    return claims(**{**user, **overrides})


def token(payload: dict[str, Any], key: rsa.RSAPrivateKey = SIGNING_KEY, kid: str = KID) -> str:
    return jwt.encode(payload, key, algorithm="RS256", headers={"kid": kid})


def auth(tok: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {tok}"}


@pytest.fixture
def usage_path(tmp_path: Path) -> Path:
    return tmp_path / "usage.log"


@pytest.fixture
def client(usage_path: Path) -> Iterator[TestClient]:
    from sensitive_api.usage import UsageLog

    validator = TokenValidator(SETTINGS, JwksCache(lambda: jwks((KID, SIGNING_KEY))))
    app = create_app(validator, RecordStore.from_file(), UsageLog(usage_path))
    with TestClient(app) as c:
        yield c


def usage_lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# ------------------------------------------------------------------ positive: one per role


def test_metadata_role_lists_records_with_metadata_only(client: TestClient) -> None:
    r = client.get("/records", headers=auth(token(claims(roles=["Records.Read.Metadata"]))))
    assert r.status_code == 200
    assert len(r.json()) == len(RECORDS)
    assert set(r.json()[0]) == {"id", "status", "created_at", "updated_at"}


def test_redacted_role_reads_record_with_pii_masked(client: TestClient) -> None:
    r = client.get(f"/records/{REC}", headers=auth(token(claims(roles=["Records.Read.Redacted"]))))
    assert r.status_code == 200
    body = r.json()
    assert body["claim_type"] == RECORDS[0]["claim_type"]
    assert all(body[f] == REDACTED for f in PII)
    assert body["claimant_name"] == REDACTED  # who made the claim isn't triage data


def test_annotate_role_appends_a_note(client: TestClient) -> None:
    tok = token(claims(roles=["Records.Annotate"]))
    r = client.post(f"/records/{REC}/notes", json={"text": "looks routine"}, headers=auth(tok))
    assert r.status_code == 201
    assert set(r.json()) == {"at", "author_oid", "text"}  # the note, not the record
    assert r.json()["author_oid"] == AGENT


def test_human_full_read_sees_pii(client: TestClient) -> None:
    r = client.get(f"/records/{REC}/full", headers=auth(token(user_claims())))
    assert r.status_code == 200
    assert r.json()["ssn"] == RECORDS[0]["ssn"]
    assert r.json()["claimant_name"] == RECORDS[0]["claimant_name"]  # humans see it


# ------------------------------------------------------------------ 401: untrusted tokens


def _hs256_with_public_key() -> str:
    """Classic alg-confusion attack: HMAC-sign with the RSA *public* key as the secret."""
    pub = SIGNING_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    def b64(d: bytes) -> str:
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode()

    head = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": KID}).encode())
    body = b64(json.dumps(claims()).encode())
    sig = hmac.new(pub, f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64(sig)}"


UNTRUSTED: list[tuple[str, Any]] = [
    ("signed-by-other-key", lambda: token(claims(), key=OTHER_KEY)),
    ("unknown-kid", lambda: token(claims(), kid="not-published")),
    ("alg-none", lambda: jwt.encode(claims(), None, algorithm="none")),
    ("alg-confusion-hs256", _hs256_with_public_key),
    ("wrong-issuer", lambda: token(claims(iss="https://login.microsoftonline.com/evil/v2.0"))),
    ("v1-issuer-on-v2-api", lambda: token(claims(iss=f"https://sts.windows.net/{TENANT}/"))),
    ("wrong-audience-graph", lambda: token(claims(aud="https://graph.microsoft.com"))),
    ("expired", lambda: token(claims(exp=int(time.time()) - 3600))),
    ("not-yet-valid", lambda: token(claims(nbf=int(time.time()) + 3600))),
    ("no-exp", lambda: token(claims(exp=None))),
    ("other-tenant-tid", lambda: token(claims(tid="99999999-9999-9999-9999-999999999999"))),
    ("no-idtyp-or-scp", lambda: token(claims(idtyp=None))),
    ("malformed", lambda: "not.a.jwt"),
]


@pytest.mark.parametrize("make", [c[1] for c in UNTRUSTED], ids=[c[0] for c in UNTRUSTED])
def test_untrusted_token_is_401(client: TestClient, make: Any) -> None:
    r = client.get("/records", headers=auth(make()))
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"].startswith("Bearer")
    assert r.json() == {"detail": "invalid token"}  # the reason stays in the usage log


def test_missing_token_is_401(client: TestClient) -> None:
    assert client.get("/records").status_code == 401


def test_clock_skew_within_leeway_is_accepted(client: TestClient) -> None:
    tok = token(claims(exp=int(time.time()) - 30))  # expired 30s ago, leeway is 60s
    assert client.get("/records", headers=auth(tok)).status_code == 200


# ------------------------------------------------------------------ 403: trusted, not allowed

ROUTES = [
    ("GET", "/records", "Records.Read.Metadata"),
    ("GET", f"/records/{REC}", "Records.Read.Redacted"),
    ("POST", f"/records/{REC}/notes", "Records.Annotate"),
]


@pytest.mark.parametrize(("method", "path", "role"), ROUTES)
def test_every_other_role_is_403(client: TestClient, method: str, path: str, role: str) -> None:
    others = [r for r in AGENT_ROLES if r != role]
    r = client.request(method, path, json={"text": "x"}, headers=auth(token(claims(roles=others))))
    assert r.status_code == 403
    assert role in r.json()["detail"]


def test_agent_with_every_agent_role_cannot_read_full(client: TestClient) -> None:
    assert client.get(f"/records/{REC}/full", headers=auth(token(claims()))).status_code == 403


def test_agent_holding_human_role_still_cannot_read_full(client: TestClient) -> None:
    """Even if Records.Read.All were somehow on an app token, the route needs a user."""
    tok = token(claims(roles=["Records.Read.All"]))
    assert client.get(f"/records/{REC}/full", headers=auth(tok)).status_code == 403


def test_user_token_on_agent_route_is_403(client: TestClient) -> None:
    tok = token(user_claims(roles=AGENT_ROLES))
    assert client.get("/records", headers=auth(tok)).status_code == 403


# ------------------------------------------------------------------ redaction guarantees


def test_no_pii_in_any_agent_response(client: TestClient) -> None:
    """Search the raw bodies, so a PII value can't leak through a field we forgot about."""
    headers = auth(token(claims()))
    pii_values = {str(rec[f]) for rec in RECORDS for f in PII}
    bodies = [client.get("/records", headers=headers).text]
    bodies += [client.get(f"/records/{rec['id']}", headers=headers).text for rec in RECORDS]
    bodies.append(client.post(f"/records/{REC}/notes", json={"text": "x"}, headers=headers).text)
    leaked = {v for v in pii_values for body in bodies if v in body}
    assert leaked == set()


def test_annotator_cannot_modify_fields(client: TestClient) -> None:
    headers = auth(token(claims()))
    before = client.get(f"/records/{REC}", headers=headers).json()
    r = client.post(
        f"/records/{REC}/notes", json={"text": "x", "status": "approved"}, headers=headers
    )
    assert r.status_code == 422  # unknown field rejected, not ignored
    after = client.get(f"/records/{REC}", headers=headers).json()
    assert after["status"] == before["status"]


def test_auth_runs_before_body_validation(client: TestClient) -> None:
    """An unauthenticated caller learns nothing about the body schema."""
    assert client.post(f"/records/{REC}/notes", json={"bogus": 1}).status_code == 401


def test_unknown_role_and_unlisted_field_are_not_shown() -> None:
    record = {**RECORDS[0], "new_sensitive_field": "secret"}
    assert render(record, "Records.Delete") == {}
    assert all("new_sensitive_field" not in render(record, role) for role in VIEWS)


def test_missing_record_is_404_after_auth(client: TestClient) -> None:
    assert client.get("/records/rec-9999").status_code == 401
    assert client.get("/records/rec-9999", headers=auth(token(claims()))).status_code == 404


# ------------------------------------------------------------------ usage log (L3 evidence)


def test_usage_log_records_every_call_including_denials(
    client: TestClient, usage_path: Path
) -> None:
    client.get("/records", headers=auth(token(claims(roles=["Records.Read.Metadata"]))))
    client.get(f"/records/{REC}", headers=auth(token(claims(roles=["Records.Read.Metadata"]))))
    client.get("/records", headers=auth(token(claims(aud="wrong"))))
    client.get("/openapi.json")  # unprotected: not logged

    allowed, forbidden, unauth = usage_lines(usage_path)
    assert allowed["outcome"] == "allowed"
    assert allowed["role_used"] == "Records.Read.Metadata"
    assert allowed["appid"] == AGENT
    assert allowed["blueprint_appid"] == BLUEPRINT
    assert allowed["route"] == "/records"

    assert forbidden["outcome"] == "forbidden"
    assert forbidden["role_used"] is None
    assert forbidden["route"] == "/records/{record_id}"  # template, not the record ID
    assert forbidden["granted_roles"] == ["Records.Read.Metadata"]

    assert unauth["outcome"] == "unauthenticated"
    assert unauth["appid"] is None  # nothing from an untrusted token is recorded as fact
    assert "Audience" in unauth["reason"]


# ------------------------------------------------------------------ key rotation


def test_new_kid_triggers_one_refetch() -> None:
    published = [(KID, SIGNING_KEY)]
    clock = [0.0]
    cache = JwksCache(lambda: jwks(*published), min_refresh_seconds=300, clock=lambda: clock[0])
    validator = TokenValidator(SETTINGS, cache)

    validator.validate(token(claims()))
    validator.validate(token(claims()))
    assert cache.fetch_count == 1  # cached

    clock[0] = 1000.0
    published.append(("rotated-key", OTHER_KEY))  # Entra publishes a new key
    validator.validate(token(claims(), key=OTHER_KEY, kid="rotated-key"))
    assert cache.fetch_count == 2


def test_random_kids_cannot_force_refetches() -> None:
    clock = [1000.0]
    cache = JwksCache(lambda: jwks((KID, SIGNING_KEY)), clock=lambda: clock[0])
    validator = TokenValidator(SETTINGS, cache)
    for i in range(20):
        with pytest.raises(InvalidToken):
            validator.validate(token(claims(), kid=f"random-{i}"))
    assert cache.fetch_count == 1


@respx.mock
def test_http_jwks_fetcher_reads_tenant_keys() -> None:
    route = respx.get(SETTINGS.jwks_url).respond(json=jwks((KID, SIGNING_KEY)))
    assert http_jwks_fetcher(SETTINGS.jwks_url)()["keys"][0]["kid"] == KID
    assert route.called


@respx.mock
def test_jwks_endpoint_down_is_an_error_not_a_pass() -> None:
    respx.get(SETTINGS.jwks_url).respond(503)
    validator = TokenValidator(SETTINGS, JwksCache(http_jwks_fetcher(SETTINGS.jwks_url)))
    with pytest.raises(httpx.HTTPStatusError):
        validator.validate(token(claims()))


# ------------------------------------------------------------------ settings


def test_v1_settings_use_sts_issuer() -> None:
    v1 = ApiSettings(tenant_id=TENANT, audience="api://x", token_version=1)
    assert v1.issuer == f"https://sts.windows.net/{TENANT}/"
    assert SETTINGS.issuer == f"https://login.microsoftonline.com/{TENANT}/v2.0"
