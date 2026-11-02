"""state/lifecycle.json: *when* things started, which Entra doesn't tell us.

Grace periods need a start date: "sponsor disabled since 3 Nov, so disable the
NHI on 17 Nov". Entra exposes an account's current `accountEnabled`, not when it
changed (the audit log has it, but only for 7-30 days on Free), so the engine
records the first day it saw each condition. Git-ignored, like tenant-state.json.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from pydantic import BaseModel, Field

LIFECYCLE_PATH = Path("state/lifecycle.json")


class LifecycleRecord(BaseModel):
    conditions: dict[str, date] = Field(default_factory=dict)  # condition -> first seen
    # While set, the NHI stays disabled even though the registry says `active`;
    # `apply` honours it. Cleared when the cause is fixed (renewal, new sponsor).
    hold: str | None = None
    disabled_on: date | None = None
    deleted_on: date | None = None
    notices: dict[str, date] = Field(default_factory=dict)  # notice key -> date sent


class LifecycleState(BaseModel):
    version: int = 1
    nhis: dict[str, LifecycleRecord] = Field(default_factory=dict)

    def holds(self) -> dict[str, str]:
        return {k: r.hold for k, r in self.nhis.items() if r.hold}


def load_lifecycle(path: Path = LIFECYCLE_PATH) -> LifecycleState:
    if not path.exists():
        return LifecycleState()
    return LifecycleState.model_validate_json(path.read_text(encoding="utf-8"))


def save_lifecycle(state: LifecycleState, path: Path = LIFECYCLE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = state.model_dump(mode="json")
    path.write_bytes((json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8"))
