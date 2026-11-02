"""Registry -> the identities that should exist in Entra (pure, no Graph calls).

ADR-003's mapping:
  agent definition        -> blueprint `bp-<agent>` (Agent ID backend only)
  (workflow, agent) pair  -> one NHI `nhi-<workflow>-<agent>` (P3), on the workflow's
                             backend: an agent identity, or an app registration + SP
  permissions             -> app role assignments on that NHI
Control-plane identities (identity_type: application) aren't provisioned: they were
bootstrapped by hand, and `plan` only reports their Graph grants (report-only).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from nhigov.registry.loader import Registry
from nhigov.registry.models import Backend, IdentityType, WorkflowStatus


@dataclass(frozen=True, order=True)
class Grant:
    resource_id: str
    role: str


@dataclass(frozen=True)
class DesiredBlueprint:
    agent_id: str
    sponsor_upns: tuple[str, ...]  # every sponsor of a workflow using this agent

    @property
    def name(self) -> str:
        return f"bp-{self.agent_id}"


@dataclass(frozen=True)
class DesiredNhi:
    workflow_id: str
    agent_id: str
    backend: Backend
    status: WorkflowStatus
    sponsor_upn: str
    grants: tuple[Grant, ...]
    # A lifecycle hold (sponsor left, expired): keep it disabled even if `active`.
    hold: str | None = None

    @property
    def key(self) -> str:
        return f"{self.workflow_id}/{self.agent_id}"

    @property
    def name(self) -> str:
        return f"nhi-{self.workflow_id}-{self.agent_id}"

    @property
    def should_exist(self) -> bool:
        """`requested` means not yet approved: nothing is created for it."""
        return self.status is not WorkflowStatus.REQUESTED

    @property
    def should_be_enabled(self) -> bool:
        return self.status is WorkflowStatus.ACTIVE and self.hold is None


@dataclass(frozen=True)
class ControlPlaneGrants:
    agent_id: str
    graph_roles: tuple[str, ...]


@dataclass
class Desired:
    blueprints: dict[str, DesiredBlueprint] = field(default_factory=dict)
    nhis: dict[str, DesiredNhi] = field(default_factory=dict)
    control_plane: list[ControlPlaneGrants] = field(default_factory=list)


def build_desired(
    registry: Registry, default_backend: Backend, holds: dict[str, str] | None = None
) -> Desired:
    desired = Desired()
    blueprint_sponsors: dict[str, set[str]] = {}
    for wf in registry.workflows.values():
        backend = wf.backend or default_backend
        for wa in wf.agents:
            agent = registry.agents[wa.ref]
            if agent.identity_type is IdentityType.APPLICATION:
                roles = tuple(sorted(r for p in wa.permissions for r in p.app_roles))
                desired.control_plane.append(ControlPlaneGrants(agent.id, roles))
                continue
            nhi = DesiredNhi(
                workflow_id=wf.id,
                agent_id=agent.id,
                backend=backend,
                status=wf.status,
                sponsor_upn=wf.sponsor,
                grants=tuple(
                    sorted(Grant(p.resource, r) for p in wa.permissions for r in p.app_roles)
                ),
                hold=(holds or {}).get(f"{wf.id}/{agent.id}"),
            )
            desired.nhis[nhi.key] = nhi
            if backend is Backend.AGENT_ID and nhi.should_exist:
                blueprint_sponsors.setdefault(agent.id, set()).add(wf.sponsor)
    desired.blueprints = {
        agent_id: DesiredBlueprint(agent_id, tuple(sorted(sponsors)))
        for agent_id, sponsors in sorted(blueprint_sponsors.items())
    }
    return desired
