"""Bearer token validation (ADR-004, ADR-009).

A token is trusted only if every check passes, in this order:

  1. header   alg is RS256 (rejects `alg: none` and HMAC-with-public-key tricks)
  2. key      `kid` is one of the tenant's published signing keys (JWKS)
  3. sig      the signature verifies with that key
  4. claims   iss = our tenant, aud = this API, exp/nbf within leeway, tid = our tenant
  5. caller   app-only (`idtyp == "app"`) or user (`scp` present), never ambiguous

Anything else is an InvalidToken (HTTP 401). Whether the caller may use a
route is a separate question answered by its `roles` claim (HTTP 403).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

from sensitive_api.settings import ApiSettings

ALGORITHMS = ["RS256"]  # what Entra signs access tokens with; nothing else is accepted

JwksFetcher = Callable[[], dict[str, Any]]


class InvalidToken(Exception):
    """The token can't be trusted. `reason` goes to the usage log, never to the caller."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def http_jwks_fetcher(url: str, timeout: float = 10.0) -> JwksFetcher:
    def fetch() -> dict[str, Any]:
        response = httpx.get(url, timeout=timeout)
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        return data

    return fetch


class JwksCache:
    """The tenant's signing keys, cached by `kid`.

    Entra rotates signing keys, so an unknown `kid` triggers a refetch, but at
    most once per `min_refresh_seconds`: otherwise anyone could make us hammer
    the JWKS endpoint by sending tokens with random `kid` values.
    """

    def __init__(
        self,
        fetch: JwksFetcher,
        min_refresh_seconds: float = 300,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._fetch = fetch
        self._min_refresh = min_refresh_seconds
        self._clock = clock
        self._keys: dict[str, Any] = {}
        self._last_fetch: float | None = None
        self.fetch_count = 0

    def _refresh(self) -> None:
        jwks = self._fetch()
        self.fetch_count += 1
        self._last_fetch = self._clock()
        self._keys = {
            jwk["kid"]: RSAAlgorithm.from_jwk(jwk)
            for jwk in jwks.get("keys", [])
            if jwk.get("kty") == "RSA" and "kid" in jwk
        }

    def key_for(self, kid: str) -> Any:
        if kid not in self._keys:
            stale = self._last_fetch is None or (
                self._clock() - self._last_fetch >= self._min_refresh
            )
            if stale:
                self._refresh()
        try:
            return self._keys[kid]
        except KeyError:
            raise InvalidToken(f"unknown signing key kid={kid}") from None


@dataclass(frozen=True)
class Caller:
    """Who is calling, from verified claims only."""

    app_id: str  # v1 `appid`, v2 `azp`: the client application (or agent identity)
    object_id: str  # `oid`: the service principal / agent identity / user object
    idtyp: str  # "app" for app-only tokens
    roles: frozenset[str]
    # Under Agent ID, the blueprint that obtained this agent's token (spike finding).
    blueprint_app_id: str | None = None
    claims: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @property
    def is_app(self) -> bool:
        return self.idtyp == "app"


class TokenValidator:
    def __init__(self, settings: ApiSettings, keys: JwksCache) -> None:
        self._settings = settings
        self._keys = keys

    def validate(self, token: str) -> Caller:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise InvalidToken(f"malformed token: {exc}") from None
        if header.get("alg") not in ALGORITHMS:
            raise InvalidToken(f"algorithm {header.get('alg')!r} not allowed")
        kid = header.get("kid")
        if not isinstance(kid, str):
            raise InvalidToken("no kid in header")

        key = self._keys.key_for(kid)
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=ALGORITHMS,
                audience=self._settings.audience,
                issuer=self._settings.issuer,
                leeway=self._settings.leeway_seconds,
                options={"require": ["exp", "iat", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise InvalidToken(f"{type(exc).__name__}: {exc}") from None

        if claims.get("tid") != self._settings.tenant_id:
            raise InvalidToken("tid is not this tenant")
        return _caller_from(claims)


def _caller_from(claims: dict[str, Any]) -> Caller:
    idtyp = claims.get("idtyp")
    if idtyp != "app" and "scp" in claims:
        idtyp = "user"  # delegated token: a user signed in through a client app
    if idtyp not in ("app", "user"):
        # The resource app requests the `idtyp` optional claim, so an app-only
        # token without it isn't one we issued for; fail closed.
        raise InvalidToken("can't tell app-only from user token (no idtyp or scp)")

    app_id = claims.get("azp") or claims.get("appid")
    object_id = claims.get("oid")
    if not isinstance(app_id, str) or not isinstance(object_id, str):
        raise InvalidToken("missing azp/appid or oid")
    roles = claims.get("roles", [])
    if not isinstance(roles, list):
        raise InvalidToken("roles claim is not a list")
    return Caller(
        app_id=app_id,
        object_id=object_id,
        idtyp=idtyp,
        roles=frozenset(str(r) for r in roles),
        blueprint_app_id=claims.get("xms_par_app_azp"),
        claims=claims,
    )
