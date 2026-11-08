"""Cross-file registry rules (ADR-008).

Each rule is a pure function `(registry, context) -> findings`, so it can be
tested in isolation and run offline in CI. REG-000/001 come from the loader.

| Rule    | Checks                                                        | Principle |
|---------|---------------------------------------------------------------|-----------|
| REG-002 | exactly one policy file                                       |           |
| REG-003 | workflow agent refs exist                                     | P2        |
| REG-004 | referenced resources exist                                    |           |
| REG-005 | referenced app roles exist on the resource                    |           |
| REG-006 | roles given to agents are Application-only                    | P4        |
| REG-007 | a workflow's grants are within the agent's max_permissions    | P2        |
| REG-008 | an agent appears at most once per workflow                    | P3        |
| REG-009 | expires within policy lifetime; past dates flagged            | P6        |
| REG-010 | high-risk permissions covered by an unexpired exception       |           |
| REG-011 | naming conventions (bp-/nhi- names derive from these IDs)     |           |
| REG-012 | control-plane identities registered in an active workflow     | P9        |
| REG-013 | workflow classification not below its resources'              | P4        |
| REG-014 | agent definition used by no workflow (warning)                |           |
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import date, timedelta

from nhigov.registry.findings import Finding, Severity
from nhigov.registry.loader import Registry
from nhigov.registry.models import IdentityType, Permission, Workflow, WorkflowStatus

E, W = Severity.ERROR, Severity.WARNING


@dataclass(frozen=True)
class Context:
    today: date


Rule = Callable[[Registry, Context], Iterator[Finding]]


def _all_permissions(reg: Registry) -> Iterator[tuple[str, str, Permission]]:
    """(owner id, label, permission) for agent max_permissions and workflow grants."""
    for agent in reg.agents.values():
        for perm in agent.max_permissions:
            yield agent.id, f"{agent.id} max_permissions", perm
    for wf in reg.workflows.values():
        for wa in wf.agents:
            for perm in wa.permissions:
                yield wf.id, f"{wf.id}/{wa.ref}", perm


def _granted_roles(wf: Workflow) -> set[str]:
    return {role for wa in wf.agents for p in wa.permissions for role in p.app_roles}


def reg_002_policy_present(reg: Registry, ctx: Context) -> Iterator[Finding]:
    if reg.policy is None:
        yield Finding("REG-002", E, "registry/policy.yaml (kind: Policy) is missing", "policy")


def reg_003_agent_refs(reg: Registry, ctx: Context) -> Iterator[Finding]:
    for wf in reg.workflows.values():
        for wa in wf.agents:
            if wa.ref not in reg.agents:
                yield Finding("REG-003", E, f"unknown agent definition '{wa.ref}'", wf.id)


def reg_004_resource_refs(reg: Registry, ctx: Context) -> Iterator[Finding]:
    for owner, label, perm in _all_permissions(reg):
        if perm.resource not in reg.resources:
            yield Finding("REG-004", E, f"{label}: unknown resource '{perm.resource}'", owner)


def reg_005_roles_exist(reg: Registry, ctx: Context) -> Iterator[Finding]:
    for owner, label, perm in _all_permissions(reg):
        resource = reg.resources.get(perm.resource)
        if resource is None:
            continue  # REG-004 already reported it
        for role in perm.app_roles:
            if resource.role(role) is None:
                yield Finding(
                    "REG-005", E, f"{label}: role '{role}' not defined on {resource.id}", owner
                )


def reg_006_agent_roles_application_only(reg: Registry, ctx: Context) -> Iterator[Finding]:
    """P4: Entra's allowedMemberTypes must keep human roles away from NHIs."""
    for owner, label, perm in _all_permissions(reg):
        resource = reg.resources.get(perm.resource)
        for value in perm.app_roles:
            role = resource.role(value) if resource else None
            if role and (role.member_types != ["Application"]):
                yield Finding(
                    "REG-006",
                    E,
                    f"{label}: '{value}' has member_types {role.member_types}; roles held by "
                    "NHIs must be Application-only (P4)",
                    owner,
                )


def reg_007_within_max_permissions(reg: Registry, ctx: Context) -> Iterator[Finding]:
    for wf in reg.workflows.values():
        for wa in wf.agents:
            agent = reg.agents.get(wa.ref)
            if agent is None:
                continue
            allowed = {(p.resource, r) for p in agent.max_permissions for r in p.app_roles}
            for perm in wa.permissions:
                for role in perm.app_roles:
                    if (perm.resource, role) not in allowed:
                        yield Finding(
                            "REG-007",
                            E,
                            f"{wa.ref} is granted {perm.resource}:{role}, which exceeds its "
                            "max_permissions",
                            wf.id,
                        )


def reg_008_one_nhi_per_pair(reg: Registry, ctx: Context) -> Iterator[Finding]:
    for wf in reg.workflows.values():
        refs = [wa.ref for wa in wf.agents]
        for ref in sorted({r for r in refs if refs.count(r) > 1}):
            yield Finding(
                "REG-008", E, f"agent '{ref}' listed more than once; one NHI per pair (P3)", wf.id
            )


def reg_009_lifetime(reg: Registry, ctx: Context) -> Iterator[Finding]:
    max_days = reg.policy.max_workflow_lifetime_days if reg.policy else 365
    limit = ctx.today + timedelta(days=max_days)
    for wf in reg.workflows.values():
        if wf.expires > limit:
            yield Finding(
                "REG-009", E, f"expires {wf.expires} is more than {max_days} days out", wf.id
            )
        if wf.status is WorkflowStatus.ACTIVE and wf.expires < ctx.today:
            yield Finding(
                "REG-009", W, f"expired on {wf.expires}; lifecycle will disable it", wf.id
            )
        elif wf.status is WorkflowStatus.ACTIVE and wf.review_by < ctx.today:
            yield Finding("REG-009", W, f"review overdue since {wf.review_by}", wf.id)


def reg_010_high_risk_exception(reg: Registry, ctx: Context) -> Iterator[Finding]:
    if reg.policy is None:
        return
    high_risk = set(reg.policy.high_risk_permissions)
    for wf in reg.workflows.values():
        risky = _granted_roles(wf) & high_risk
        exc = wf.exception
        covered = set(exc.covers) if exc else set()
        for role in sorted(risky - covered):
            yield Finding(
                "REG-010", E, f"high-risk '{role}' granted without an exception block", wf.id
            )
        if exc is None:
            continue
        if risky and exc.expires < ctx.today:
            yield Finding("REG-010", E, f"exception expired on {exc.expires}", wf.id)
        if exc.expires > wf.expires:
            yield Finding("REG-010", W, "exception outlives the workflow's expires date", wf.id)
        for role in sorted(covered - risky):
            yield Finding(
                "REG-010", W, f"exception covers '{role}', which isn't a granted high-risk role",
                wf.id,
            )  # fmt: skip


def reg_011_naming(reg: Registry, ctx: Context) -> Iterator[Finding]:
    for wf in reg.workflows.values():
        if not wf.id.startswith("wf-"):
            yield Finding("REG-011", E, "workflow ids must start with 'wf-'", wf.id)
    for agent in reg.agents.values():
        prefix = "agent-" if agent.identity_type is IdentityType.AGENT else "nhigov-"
        if not agent.id.startswith(prefix):
            yield Finding(
                "REG-011", E, f"{agent.identity_type} definitions must start with '{prefix}'",
                agent.id,
            )  # fmt: skip
    for res in reg.resources.values():
        if res.managed and not res.id.startswith("res-"):
            yield Finding("REG-011", E, "managed resource ids must start with 'res-'", res.id)


def reg_012_control_plane_registered(reg: Registry, ctx: Context) -> Iterator[Finding]:
    if reg.policy is None:
        return
    active_refs = {
        wa.ref
        for wf in reg.workflows.values()
        if wf.status is WorkflowStatus.ACTIVE
        for wa in wf.agents
    }
    for cp in reg.policy.control_plane:
        agent = reg.agents.get(cp)
        if agent is None or cp not in active_refs:
            yield Finding(
                "REG-012", E, f"control-plane identity '{cp}' isn't registered in an active "
                "workflow (P9)", cp,
            )  # fmt: skip
        elif agent.identity_type is not IdentityType.APPLICATION:
            yield Finding("REG-012", E, "control-plane identities must be 'application'", cp)


def reg_013_classification(reg: Registry, ctx: Context) -> Iterator[Finding]:
    for wf in reg.workflows.values():
        for wa in wf.agents:
            for perm in wa.permissions:
                res = reg.resources.get(perm.resource)
                if res and res.data_classification.rank > wf.data_classification.rank:
                    yield Finding(
                        "REG-013",
                        E,
                        f"classified '{wf.data_classification}' but accesses {res.id} "
                        f"('{res.data_classification}')",
                        wf.id,
                    )


def reg_014_unused_agents(reg: Registry, ctx: Context) -> Iterator[Finding]:
    used = {wa.ref for wf in reg.workflows.values() for wa in wf.agents}
    for agent_id in sorted(set(reg.agents) - used):
        yield Finding("REG-014", W, "agent definition isn't used by any workflow", agent_id)


RULES: tuple[Rule, ...] = (
    reg_002_policy_present,
    reg_003_agent_refs,
    reg_004_resource_refs,
    reg_005_roles_exist,
    reg_006_agent_roles_application_only,
    reg_007_within_max_permissions,
    reg_008_one_nhi_per_pair,
    reg_009_lifetime,
    reg_010_high_risk_exception,
    reg_011_naming,
    reg_012_control_plane_registered,
    reg_013_classification,
    reg_014_unused_agents,
)


def validate_registry(reg: Registry, today: date | None = None) -> list[Finding]:
    ctx = Context(today=today or date.today())
    return [finding for rule in RULES for finding in rule(reg, ctx)]
