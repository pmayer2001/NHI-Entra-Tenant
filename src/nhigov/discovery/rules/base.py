"""What a discovery rule is: a pure function `inventory -> findings`, plus why and how to fix.

Rules never call Graph. They read a saved inventory, so they're tested offline
and a scan can be re-evaluated later without touching the tenant.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import StrEnum

from pydantic import BaseModel

from nhigov.discovery.inventory import GRAPH_APP_ID, Grant, Inventory, Nhi
from nhigov.registry.loader import Registry
from nhigov.registry.models import Policy, RiskException, Workflow


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class Finding(BaseModel):
    rule: str
    severity: Severity
    object_id: str
    display_name: str
    classification: str
    message: str
    rationale: str
    remediation: str

    @property
    def key(self) -> str:
        """Stable identity for dedupe (one GitHub issue per key)."""
        return f"{self.rule}:{self.object_id}"


@dataclass(frozen=True)
class ScanContext:
    registry: Registry
    now: datetime
    # resource service principal ID -> registry resource ID (from the state file)
    resource_sps: dict[str, str] = field(default_factory=dict)

    @property
    def today(self) -> date:
        return self.now.date()

    @property
    def policy(self) -> Policy:
        if self.registry.policy is None:
            raise ValueError("the registry has no policy; run `nhigov validate`")
        return self.registry.policy

    def workflow_of(self, nhi: Nhi) -> list[tuple[Workflow, str]]:
        """(workflow, agent ID) for each registry pair this NHI implements."""
        out = []
        for key in nhi.registry_keys:
            kind, _, ref = key.partition(":")
            if kind == "workflow":
                wf_id, agent = ref.split("/", 1)
            elif kind == "control":
                wf_id, agent = "wf-control-plane", ref
            else:
                continue
            wf = self.registry.workflows.get(wf_id)
            if wf is not None:
                out.append((wf, agent))
        return out

    @property
    def graph_resource_id(self) -> str:
        return next(
            (r.id for r in self.registry.resources.values()
             if r.identifier_uri.rstrip("/") == "https://graph.microsoft.com"),
            "microsoft-graph",
        )  # fmt: skip

    def registry_resource(self, grant: Grant) -> str:
        if grant.resource_app_id == GRAPH_APP_ID:
            return self.graph_resource_id
        return self.resource_sps.get(grant.resource_id, f"unregistered:{grant.resource_name}")

    def declared(self, nhi: Nhi) -> set[tuple[str, str]] | None:
        """(registry resource, role) the registry grants this NHI, or None if the
        registry says nothing about its grants (shadow NHIs, resources)."""
        pairs = self.workflow_of(nhi)
        if not pairs:
            if any(k.startswith("blueprint:") for k in nhi.registry_keys):
                graph = self.graph_resource_id
                return {(graph, role) for role in self.policy.blueprint_graph_grants}
            return None
        return {
            (p.resource, role)
            for wf, agent in pairs
            for wa in wf.agents if wa.ref == agent
            for p in wa.permissions
            for role in p.app_roles
        }  # fmt: skip

    def exception_covering(self, nhi: Nhi, role: str) -> RiskException | None:
        for wf, _ in self.workflow_of(nhi):
            exc = wf.exception
            if exc is not None and role in exc.covers and exc.expires >= self.today:
                return exc
        return None


Check = Callable[[Inventory, ScanContext], Iterator[tuple[Nhi, str]]]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    rationale: str
    remediation: str
    check: Check

    def run(self, inventory: Inventory, ctx: ScanContext) -> list[Finding]:
        return [
            Finding(
                rule=self.id,
                severity=self.severity,
                object_id=nhi.id,
                display_name=nhi.display_name,
                classification=nhi.classification,
                message=message,
                rationale=self.rationale,
                remediation=self.remediation,
            )
            for nhi, message in self.check(inventory, ctx)
        ]
