"""state/tenant-state.json: registry ID -> Entra object IDs (ADR-006).

This is how the reconciler finds "its" objects again. Display names aren't
unique in Entra and agent identities can't be tagged, so the object ID recorded
at creation time is the authoritative link. No secrets are ever stored here.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field

STATE_PATH = Path("state/tenant-state.json")


class ResourceRecord(BaseModel):
    application_object_id: str  # the app registration's `id`
    app_id: str  # its `appId` (client ID): the `aud` of v2 tokens for this API
    service_principal_id: str | None = None


class BlueprintRecord(BaseModel):
    """An agent identity blueprint (Agent ID backend), keyed by agent definition ID."""

    application_object_id: str
    app_id: str
    principal_id: str | None = None  # the blueprint principal, created after the blueprint


class NhiRecord(BaseModel):
    """One (workflow, agent) NHI, keyed "<workflow>/<agent>"."""

    backend: str  # agent_id | service_principal
    # The service principal (or agent identity) that holds app role assignments.
    principal_id: str | None = None
    app_id: str | None = None
    application_object_id: str | None = None  # service_principal backend only
    blueprint: str | None = None  # agent_id backend: the agent definition's blueprint
    # When `apply` created it (Phase 7): usage analytics doesn't judge an NHI on time
    # before it existed. None for NHIs created before this field was added.
    created_at: datetime | None = None


class TenantState(BaseModel):
    version: int = 1
    resources: dict[str, ResourceRecord] = Field(default_factory=dict)
    blueprints: dict[str, BlueprintRecord] = Field(default_factory=dict)
    nhis: dict[str, NhiRecord] = Field(default_factory=dict)


def load_state(path: Path = STATE_PATH) -> TenantState:
    if not path.exists():
        return TenantState()
    return TenantState.model_validate_json(path.read_text(encoding="utf-8"))


def save_state(state: TenantState, path: Path = STATE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = state.model_dump(mode="json")
    path.write_bytes((json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8"))
