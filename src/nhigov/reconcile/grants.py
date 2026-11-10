"""App role assignments: grant what the registry declares, revoke the rest (P4, P8).

Both backends end in a service principal (an agent identity is one), so this is
backend-agnostic. Only roles on resources nhigov manages are reconciled: those
role IDs are derived from the registry (stable UUID5s), and anything else an NHI
holds there is revoked, because revoking can only ever reduce access (decided
2026-11-01). Grants on unmanaged resources (Microsoft Graph) are
reported, not changed.
"""

from __future__ import annotations

from nhigov.backends.base import Principals
from nhigov.reconcile.desired import Desired
from nhigov.reconcile.engine import IdentityPlan, PlanContext, Step
from nhigov.reconcile.resources import role_id


def plan_grants(
    ctx: PlanContext, desired: Desired, principals: Principals, plan: IdentityPlan
) -> None:
    managed = {rid: r for rid, r in ctx.registry.resources.items() if r.managed}
    # resource SP object ID -> resource registry ID, for resources that exist already
    resource_sps = {
        rec.service_principal_id: rid
        for rid, rec in ctx.state.resources.items()
        if rec.service_principal_id and rid in managed
    }
    for key, principal in sorted(principals.items()):
        nhi = desired.nhis[key]
        wanted = {g for g in nhi.grants if g.resource_id in managed}
        for g in sorted(set(nhi.grants) - wanted):
            plan.notes.append(
                f"{nhi.name}: {g.resource_id}:{g.role} is on an unmanaged resource; not reconciled"
            )

        held: dict[tuple[str, str], str] = {}  # (resource, appRoleId) -> assignment ID
        if principal is not None:
            for a in ctx.graph.list_all(f"servicePrincipals/{principal}/appRoleAssignments"):
                if a.get("resourceId") in resource_sps:
                    held[(resource_sps[a["resourceId"]], a["appRoleId"])] = a["id"]

        wanted_ids = {(g.resource_id, role_id(g.resource_id, g.role)): g for g in wanted}
        for (res, rid), g in sorted(wanted_ids.items(), key=lambda kv: kv[1]):
            if (res, rid) not in held:
                plan.steps.append(
                    Step(
                        "grant.add",
                        key,
                        f"{g.role} on {res} to {nhi.name}",
                        f"POST /v1.0/servicePrincipals/<{nhi.name}.id>/appRoleAssignments",
                        {"resource": res, "role": g.role, "appRoleId": rid},
                    )
                )
        for (res, rid), assignment_id in sorted(held.items()):
            if (res, rid) not in wanted_ids:
                roles = {role_id(res, r.value): r.value for r in managed[res].app_roles}
                role = roles.get(rid, f"unknown role {rid}")
                plan.steps.append(
                    Step(
                        "grant.revoke",
                        key,
                        f"{role} on {res} from {nhi.name} (not in registry)",
                        f"DELETE /v1.0/servicePrincipals/{principal}"
                        f"/appRoleAssignments/{assignment_id}",
                        {"resource": res, "role": role, "assignmentId": assignment_id},
                    )
                )
