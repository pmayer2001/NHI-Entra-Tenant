"""Carry out a lifecycle plan as the provisioner. Only called with --execute.

Disable before delete (ADR-006): a hold disables and stays until its cause is
fixed; only a retired workflow's NHIs are ever deleted, after the grace period.
Entra keeps them restorable for 30 days after that.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import date
from pathlib import Path

from nhigov.graph.client import GraphClient
from nhigov.lifecycle.engine import Action, LifecyclePlan
from nhigov.lifecycle.state import LifecycleRecord, LifecycleState
from nhigov.reconcile.state import NhiRecord, TenantState

RETIRED = "workflow retired"


def _disable(graph: GraphClient, rec: NhiRecord) -> None:
    if rec.backend == "agent_id":
        path = f"servicePrincipals/{rec.principal_id}/microsoft.graph.agentIdentity"
    else:
        path = f"servicePrincipals/{rec.principal_id}"
    graph.patch(path, {"accountEnabled": False})


def _delete(graph: GraphClient, rec: NhiRecord) -> None:
    if rec.backend == "agent_id":
        graph.delete(f"servicePrincipals/{rec.principal_id}")
    else:  # deleting the app registration removes its service principal too
        graph.delete(f"applications/{rec.application_object_id}")


def execute(
    graph: GraphClient,
    plan: LifecyclePlan,
    tenant: TenantState,
    today: date,
    save: Callable[[TenantState, LifecycleState], None],
    notices_dir: Path,
) -> list[str]:
    log: list[str] = []
    lifecycle = plan.state
    for action in plan.actions:
        rec = lifecycle.nhis.setdefault(action.key, LifecycleRecord())
        log.append(_one(graph, action, rec, tenant, today, notices_dir))
        save(tenant, lifecycle)
    return log


def _one(
    graph: GraphClient,
    action: Action,
    rec: LifecycleRecord,
    tenant: TenantState,
    today: date,
    notices_dir: Path,
) -> str:
    target = tenant.nhis.get(action.key)
    if action.kind == "notice":
        notices_dir.mkdir(parents=True, exist_ok=True)
        path = notices_dir / f"notices-{today}.md"
        with path.open("a", encoding="utf-8") as f:
            f.write(f"- **{action.name}**: {action.reason}\n")
        rec.notices[action.ref] = today
        return f"notice for {action.name}: {action.reason}"
    if action.kind == "release":
        rec.hold = None
        return f"released hold on {action.name}: {action.reason}"
    if target is None or target.principal_id is None:
        return f"skipped {action.kind} for {action.name}: not in state"
    if action.kind == "disable":
        _disable(graph, target)
        rec.disabled_on = rec.disabled_on or today
        if action.reason != RETIRED:  # retired NHIs stay off because the registry says so
            rec.hold = action.reason
        return f"disabled {action.name}: {action.reason}"
    _delete(graph, target)
    tenant.nhis.pop(action.key, None)
    rec.deleted_on, rec.hold = today, None
    return f"soft-deleted {action.name} (restorable for 30 days): {action.reason}"
