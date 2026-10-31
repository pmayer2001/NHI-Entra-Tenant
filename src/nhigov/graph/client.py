"""Thin, typed Microsoft Graph client over httpx (ADR-002).

Every Graph call in the project goes through GraphClient. It handles:

* auth: a bearer token from a TokenProvider, fetched per request (azure-identity caches it)
* paging: follows `@odata.nextLink` until the collection is exhausted
* throttling: retries 429/503/504 honouring `Retry-After`, else exponential backoff
* eventual consistency: optionally retries 404 on reads right after a create, because a
  directory object written to one replica can take seconds to appear on the replica
  that serves the next read
* OData: adds `OData-Version: 4.0` when the call uses a typed-cast URL
  (`/applications/microsoft.graph.agentIdentityBlueprint`) or an `@odata.type` body,
  which Agent ID endpoints require
* logging: one structured line per HTTP attempt (method, path, status, request-id)
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import httpx
import structlog

from nhigov.graph.auth import TokenProvider

log = structlog.get_logger("nhigov.graph")

RETRYABLE_STATUS = frozenset({429, 503, 504})
JsonDict = dict[str, Any]


@dataclass
class GraphError(Exception):
    """A non-2xx Graph response, with the fields needed to debug it with Microsoft."""

    status: int
    code: str
    message: str
    request_id: str | None
    method: str
    path: str

    def __str__(self) -> str:
        return (
            f"{self.method} {self.path} -> {self.status} {self.code}: {self.message} "
            f"(request-id {self.request_id})"
        )

    @classmethod
    def from_response(cls, response: httpx.Response) -> GraphError:
        code, message = "unknown", response.text[:500]
        try:
            err = response.json().get("error", {})
            code = err.get("code", code)
            message = err.get("message", message)
        except ValueError:
            pass
        return cls(
            status=response.status_code,
            code=code,
            message=message,
            request_id=response.headers.get("request-id"),
            method=response.request.method,
            path=response.request.url.path,
        )


def _needs_odata_v4(path: str, body: JsonDict | None) -> bool:
    return "microsoft.graph." in path.lower() or (body is not None and "@odata.type" in body)


class GraphClient:
    def __init__(
        self,
        token_provider: TokenProvider,
        *,
        base_url: str = "https://graph.microsoft.com",
        version: str = "v1.0",
        max_retries: int = 5,
        not_found_retries: int = 5,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._token = token_provider
        self._base = base_url.rstrip("/")
        self._version = version
        self._max_retries = max_retries
        self._not_found_retries = not_found_retries
        self._sleep = sleep
        self._http = httpx.Client(transport=transport, timeout=30.0)

    def __enter__(self) -> GraphClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    # ------------------------------------------------------------------ core

    def url(self, path: str, version: str | None = None) -> str:
        if path.startswith("https://"):
            return path  # already absolute, e.g. an @odata.nextLink
        return f"{self._base}/{version or self._version}/{path.lstrip('/')}"

    def request(
        self,
        method: str,
        path: str,
        *,
        json: JsonDict | None = None,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        version: str | None = None,
        retry_not_found: bool = False,
        check: bool = True,
    ) -> httpx.Response:
        """Send one logical request, retrying transient failures.

        With check=False the final response is returned whatever its status;
        the probe uses this to record 403s and license errors instead of raising.
        """
        url = self.url(path, version)
        req_headers = {"Accept": "application/json"}
        if _needs_odata_v4(url, json):
            req_headers["OData-Version"] = "4.0"
        req_headers.update(headers or {})

        throttle_attempts = 0
        not_found_attempts = 0
        while True:
            req_headers["Authorization"] = f"Bearer {self._token()}"
            started = time.monotonic()
            response = self._http.request(
                method, url, json=json, params=params, headers=req_headers
            )
            log.info(
                "graph.request",
                method=method,
                path=response.request.url.path,
                status=response.status_code,
                request_id=response.headers.get("request-id"),
                elapsed_ms=round((time.monotonic() - started) * 1000),
            )

            if response.status_code in RETRYABLE_STATUS and throttle_attempts < self._max_retries:
                throttle_attempts += 1
                self._sleep(self._retry_delay(response, throttle_attempts))
                continue
            if (
                response.status_code == 404
                and retry_not_found
                and not_found_attempts < self._not_found_retries
            ):
                not_found_attempts += 1
                self._sleep(min(2.0**not_found_attempts, 30.0))
                continue
            break

        if check and response.is_error:
            raise GraphError.from_response(response)
        return response

    @staticmethod
    def _retry_delay(response: httpx.Response, attempt: int) -> float:
        retry_after = response.headers.get("Retry-After")
        if retry_after is not None:
            try:
                return max(float(retry_after), 0.0)
            except ValueError:
                pass  # HTTP-date form; Graph uses seconds in practice
        return float(min(2**attempt, 60))

    # --------------------------------------------------------------- helpers

    def get(self, path: str, **kwargs: Any) -> JsonDict:
        result: JsonDict = self.request("GET", path, **kwargs).json()
        return result

    def get_after_create(self, path: str, **kwargs: Any) -> JsonDict:
        """GET an object that was just created, tolerating replication lag (404s)."""
        return self.get(path, retry_not_found=True, **kwargs)

    def list_all(self, path: str, **kwargs: Any) -> Iterator[JsonDict]:
        """Yield every item of a collection, following @odata.nextLink.

        nextLink already carries the original query (including $skiptoken), so
        params are only sent on the first page.
        """
        next_url: str | None = path
        while next_url:
            page = self.get(next_url, **kwargs)
            yield from page.get("value", [])
            next_url = page.get("@odata.nextLink")
            kwargs.pop("params", None)

    def post(self, path: str, body: JsonDict, **kwargs: Any) -> JsonDict:
        response = self.request("POST", path, json=body, **kwargs)
        return response.json() if response.content else {}

    def patch(self, path: str, body: JsonDict, **kwargs: Any) -> None:
        self.request("PATCH", path, json=body, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> None:
        self.request("DELETE", path, **kwargs)
