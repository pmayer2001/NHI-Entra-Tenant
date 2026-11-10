"""Load registry/**/*.yaml into one Registry, collecting (not raising) problems.

Every problem becomes a Finding so `nhigov validate` can report all of them in
one run instead of stopping at the first broken file.

UPNs are written as `{owner}@{tenant_domain}` in committed files. The real domain
reveals the tenant (its ID is one public lookup away) and the owner is whoever
runs this tenant, so both are substituted at load time from config/env and never
committed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import ValidationError

from nhigov.registry.findings import Finding, Severity
from nhigov.registry.models import AgentDefinition, Policy, Resource, Workflow

if TYPE_CHECKING:
    from nhigov.config import Config

TENANT_DOMAIN_VAR = "{tenant_domain}"
PLACEHOLDER_DOMAIN = "tenant.example"  # offline default: valid UPN shape, never a real tenant
OWNER_VAR = "{owner}"
PLACEHOLDER_OWNER = "owner"  # offline default for the human who sponsors the examples

_KINDS: dict[str, type[AgentDefinition | Resource | Workflow | Policy]] = {
    "AgentDefinition": AgentDefinition,
    "Resource": Resource,
    "Workflow": Workflow,
    "Policy": Policy,
}


@dataclass
class Registry:
    agents: dict[str, AgentDefinition] = field(default_factory=dict)
    resources: dict[str, Resource] = field(default_factory=dict)
    workflows: dict[str, Workflow] = field(default_factory=dict)
    policy: Policy | None = None
    sources: dict[str, Path] = field(default_factory=dict)  # registry ID -> file

    def summary(self) -> str:
        return (
            f"{len(self.workflows)} workflows, {len(self.agents)} agent definitions, "
            f"{len(self.resources)} resources, policy {'present' if self.policy else 'MISSING'}"
        )


def _schema_errors(exc: ValidationError) -> str:
    return "; ".join(
        f"{'.'.join(str(p) for p in err['loc']) or '(root)'}: {err['msg']}" for err in exc.errors()
    )


def load_registry(
    root: Path, tenant_domain: str = PLACEHOLDER_DOMAIN, owner: str = PLACEHOLDER_OWNER
) -> tuple[Registry, list[Finding]]:
    registry = Registry()
    findings: list[Finding] = []

    def err(rule: str, message: str, subject: str) -> None:
        findings.append(Finding(rule, Severity.ERROR, message, subject))

    for path in sorted(root.rglob("*.yaml")):
        where = path.as_posix()
        text = (
            path.read_text(encoding="utf-8")
            .replace(TENANT_DOMAIN_VAR, tenant_domain)
            .replace(OWNER_VAR, owner)
        )
        try:
            data: Any = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            err("REG-000", f"YAML parse error: {exc}", where)
            continue
        if not isinstance(data, dict) or data.get("kind") not in _KINDS:
            err("REG-000", f"missing or unknown `kind` (expected one of {list(_KINDS)})", where)
            continue
        try:
            obj = _KINDS[data["kind"]].model_validate(data)
        except ValidationError as exc:
            err("REG-000", f"schema: {_schema_errors(exc)}", where)
            continue

        if isinstance(obj, Policy):
            if registry.policy is not None:
                err("REG-001", "more than one Policy file", where)
                continue
            registry.policy = obj
            registry.sources["policy"] = path
            continue

        # IDs are unique across ALL kinds: they become Entra display names and
        # state-file keys (ADR-006), where a collision would be ambiguous.
        if obj.id in registry.sources:
            err("REG-001", f"duplicate id (also in {registry.sources[obj.id].as_posix()})", obj.id)
            continue
        registry.sources[obj.id] = path
        if isinstance(obj, AgentDefinition):
            registry.agents[obj.id] = obj
        elif isinstance(obj, Resource):
            registry.resources[obj.id] = obj
        else:
            registry.workflows[obj.id] = obj

    return registry, findings


def load_registry_for(cfg: Config, root: Path) -> tuple[Registry, list[Finding]]:
    """The registry with this tenant's domain and owner filled in (placeholders if unset)."""
    return load_registry(
        root, cfg.tenant_domain or PLACEHOLDER_DOMAIN, cfg.owner or PLACEHOLDER_OWNER
    )
