"""Usage log: one JSON line per request (CLAUDE.md section 9, L3).

An app-only token carries every granted role on every call, so only the
resource knows which role was actually exercised. This log is that evidence;
Phase 7 computes granted - used from it. Denied calls are logged too.
"""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

OUTCOMES = {200: "allowed", 201: "allowed", 401: "unauthenticated", 403: "forbidden"}


@dataclass(frozen=True)
class UsageEvent:
    ts: str
    route: str
    method: str
    status: int
    outcome: str  # allowed | unauthenticated | forbidden | not_found | invalid_request | error
    appid: str | None = None
    oid: str | None = None
    idtyp: str | None = None
    blueprint_appid: str | None = None  # xms_par_app_azp: ties an agent call to its blueprint
    role_used: str | None = None  # the route's required role, only when allowed
    granted_roles: tuple[str, ...] = ()
    reason: str | None = None  # why a token was rejected (never sent to the caller)


def outcome_for(status: int) -> str:
    if status in OUTCOMES:
        return OUTCOMES[status]
    if status == 404:
        return "not_found"
    if status == 422:
        return "invalid_request"
    return "allowed" if status < 400 else "error"


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


class UsageLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def write(self, event: UsageEvent) -> None:
        line = json.dumps(asdict(event), separators=(",", ":"))
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
