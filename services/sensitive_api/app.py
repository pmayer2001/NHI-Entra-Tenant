"""FastAPI app: each route declares the one app role it requires (ADR-004).

401 = we can't trust the token (who are you?). 403 = trusted, but the token's
`roles` don't include the route's role, or it's the wrong kind of caller
(an agent on a human route or vice versa). The two are kept distinct on purpose:
a 403 proves authentication worked and authorization did its job.
"""

# No `from __future__ import annotations` here: FastAPI reads route annotations at
# runtime, and as strings it can't resolve names local to create_app (e.g. `bearer`).

import copy
import json
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from sensitive_api.auth import Caller, InvalidToken, TokenValidator
from sensitive_api.redaction import render
from sensitive_api.usage import UsageEvent, UsageLog, now_iso, outcome_for

DEFAULT_DATA = Path(__file__).parent / "data" / "records.json"

CallerKind = Literal["app", "user"]


class NoteIn(BaseModel):
    # extra="forbid": an annotator can't sneak `status` or `ssn` into the body.
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=2000)


class RecordStore:
    """In-memory copy of the fake records; notes don't survive a restart."""

    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._records = {r["id"]: copy.deepcopy(r) for r in records}

    @classmethod
    def from_file(cls, path: Path = DEFAULT_DATA) -> Self:
        records: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
        return cls(records)

    def all(self) -> list[dict[str, Any]]:
        return list(self._records.values())

    def get(self, record_id: str) -> dict[str, Any]:
        if record_id not in self._records:
            raise HTTPException(404, "record not found")
        return self._records[record_id]


def create_app(validator: TokenValidator, store: RecordStore, usage: UsageLog) -> FastAPI:
    app = FastAPI(title="Sensitive Records API (mock)", version="0.1.0")
    bearer = HTTPBearer(auto_error=False)

    def requires_role(role: str, kind: CallerKind = "app") -> Callable[..., Caller]:
        def dependency(
            request: Request,
            credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
        ) -> Caller:
            request.state.required_role = role
            if credentials is None:
                request.state.reason = "no bearer token"
                raise HTTPException(
                    401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"}
                )
            try:
                caller = validator.validate(credentials.credentials)
            except InvalidToken as exc:
                request.state.reason = exc.reason
                raise HTTPException(
                    401,
                    "invalid token",
                    headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                ) from None
            request.state.caller = caller
            if caller.idtyp != kind:
                request.state.reason = f"route needs a {kind} token, got {caller.idtyp}"
                raise HTTPException(403, f"this route is for {kind} callers")
            if role not in caller.roles:
                request.state.reason = "role not granted"
                raise HTTPException(403, f"requires app role {role}")
            return caller

        return dependency

    @app.middleware("http")
    async def log_usage(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        role = getattr(request.state, "required_role", None)
        if role is None:  # not a protected route (docs, unknown path)
            return response
        caller: Caller | None = getattr(request.state, "caller", None)
        outcome = outcome_for(response.status_code)
        route = request.scope.get("route")
        usage.write(
            UsageEvent(
                ts=now_iso(),
                route=getattr(route, "path", request.url.path),
                method=request.method,
                status=response.status_code,
                outcome=outcome,
                appid=caller.app_id if caller else None,
                oid=caller.object_id if caller else None,
                idtyp=caller.idtyp if caller else None,
                blueprint_appid=caller.blueprint_app_id if caller else None,
                role_used=role if outcome == "allowed" else None,
                granted_roles=tuple(sorted(caller.roles)) if caller else (),
                reason=getattr(request.state, "reason", None),
            )
        )
        return response

    Metadata = Annotated[Caller, Depends(requires_role("Records.Read.Metadata"))]
    Redacted = Annotated[Caller, Depends(requires_role("Records.Read.Redacted"))]
    Annotator = Annotated[Caller, Depends(requires_role("Records.Annotate"))]
    HumanFull = Annotated[Caller, Depends(requires_role("Records.Read.All", kind="user"))]

    @app.get("/records")
    def list_records(caller: Metadata) -> list[dict[str, Any]]:
        return [render(r, "Records.Read.Metadata") for r in store.all()]

    @app.get("/records/{record_id}")
    def read_record(record_id: str, caller: Redacted) -> dict[str, Any]:
        return render(store.get(record_id), "Records.Read.Redacted")

    @app.post("/records/{record_id}/notes", status_code=201)
    def annotate(record_id: str, note: NoteIn, caller: Annotator) -> dict[str, Any]:
        record = store.get(record_id)
        entry = {"at": now_iso(), "author_oid": caller.object_id, "text": note.text}
        record.setdefault("notes", []).append(entry)
        return entry  # the note only: an annotator gets no read access to the record

    @app.get("/records/{record_id}/full")
    def read_full(record_id: str, caller: HumanFull) -> dict[str, Any]:
        return render(store.get(record_id), "Records.Read.All")

    return app
