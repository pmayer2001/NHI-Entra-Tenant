"""Registry schema (CLAUDE.md §6, ADR-008).

Every model forbids unknown fields: a typo like `sponsr:` must fail validation,
not be silently ignored, because an ignored governance field is a missing control.
Single-file rules (types, required fields, review_by <= expires) live here;
rules that span files live in `validate.py`.
"""

from __future__ import annotations

from datetime import date
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

RegistryId = Annotated[
    str, StringConstraints(pattern=r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$", max_length=64)
]
Upn = Annotated[str, StringConstraints(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")]
RoleValue = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._-]+$")]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @property
    def rank(self) -> int:
        return list(DataClassification).index(self)


class IdentityType(StrEnum):
    # An Entra Agent ID agent identity (or an SP under the fallback backend, ADR-003).
    AGENT = "agent"
    # A classic app registration + service principal on every backend. Used for the
    # control plane, which isn't an AI agent and needs Graph permissions (P9).
    APPLICATION = "application"


class Backend(StrEnum):
    """How a (workflow, agent) pair is materialized in Entra (ADR-003)."""

    AGENT_ID = "agent_id"  # agent identity under a blueprint
    SERVICE_PRINCIPAL = "service_principal"  # its own app registration + SP


class Runtime(StrEnum):
    LOCAL = "local"
    GITHUB_ACTIONS = "github-actions"


class Cadence(StrEnum):
    """How often the agent is expected to run; dormancy rules use it (§9)."""

    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    ON_DEMAND = "on-demand"


class WorkflowStatus(StrEnum):
    REQUESTED = "requested"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    RETIRED = "retired"


class Permission(_Strict):
    resource: RegistryId
    app_roles: list[RoleValue] = Field(min_length=1)


class AppRole(_Strict):
    value: RoleValue
    # Mirrors Entra's allowedMemberTypes: who Entra will let this role be assigned to.
    member_types: list[Literal["User", "Application"]] = Field(min_length=1)
    description: str


class Resource(_Strict):
    kind: Literal["Resource"]
    id: RegistryId
    identifier_uri: str
    data_classification: DataClassification
    # False for APIs we don't own (Microsoft Graph). Their roles are listed so grants
    # can be checked, but the reconciler never creates or edits them.
    managed: bool = True
    app_roles: list[AppRole] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_roles(self) -> Resource:
        values = [r.value for r in self.app_roles]
        dupes = {v for v in values if values.count(v) > 1}
        if dupes:
            raise ValueError(f"duplicate app role values: {sorted(dupes)}")
        return self

    def role(self, value: str) -> AppRole | None:
        return next((r for r in self.app_roles if r.value == value), None)


class AgentDefinition(_Strict):
    """A reusable agent (P2). Maps to an agent identity blueprint under Agent ID."""

    kind: Literal["AgentDefinition"]
    id: RegistryId
    description: str
    identity_type: IdentityType = IdentityType.AGENT
    # Under Agent ID each agent definition gets one blueprint (bp-<id>), and that
    # blueprint's credential can act as every agent identity created from it (ADR-003).
    # The zone is recorded for blast-radius findings (NHI-011).
    trust_zone: RegistryId = "default"
    # P5: skills are plain names. They can't carry permissions; a skill runs under the
    # identity of the agent that calls it.
    skills: list[RegistryId] = Field(default_factory=list)
    max_permissions: list[Permission] = Field(default_factory=list)


class WorkflowAgent(_Strict):
    """One (workflow, agent) pair, which becomes exactly one NHI (P3)."""

    ref: RegistryId
    runtimes: list[Runtime] = Field(min_length=1)
    expected_cadence: Cadence
    permissions: list[Permission] = Field(default_factory=list)


class RiskException(_Strict):
    """Written justification for high-risk permissions (CLAUDE.md §6)."""

    reason: str = Field(min_length=20)
    approved_by: Upn
    expires: date
    covers: list[RoleValue] = Field(min_length=1)


class Workflow(_Strict):
    """One AI use case, registered as an application (P1)."""

    kind: Literal["Workflow"]
    id: RegistryId
    name: str
    business_owner: Upn
    sponsor: Upn  # P6: the accountable human; required
    data_classification: DataClassification
    status: WorkflowStatus
    expires: date
    review_by: date
    agents: list[WorkflowAgent] = Field(min_length=1)
    exception: RiskException | None = None
    # Overrides config.yaml's identity_backend for this workflow only, so both
    # backends can run side by side without giving one pair two NHIs (P3).
    backend: Backend | None = None

    @model_validator(mode="after")
    def _review_before_expiry(self) -> Workflow:
        if self.review_by > self.expires:
            raise ValueError(f"review_by {self.review_by} is after expires {self.expires}")
        return self


class Policy(_Strict):
    """Global rules (registry/policy.yaml)."""

    kind: Literal["Policy"]
    high_risk_permissions: list[RoleValue]
    max_workflow_lifetime_days: int = Field(default=365, gt=0)
    max_credential_lifetime_days: int = Field(default=180, gt=0)
    sponsor_grace_days: int = Field(default=14, ge=0)
    retirement_grace_days: int = Field(default=14, ge=0)
    expiry_notice_days: int = Field(default=14, ge=0)
    # P9: these identities must be registered like any other NHI.
    control_plane: list[RegistryId] = Field(
        default_factory=lambda: ["nhigov-provisioner", "nhigov-scanner"]
    )
