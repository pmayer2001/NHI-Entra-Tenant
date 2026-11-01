"""Plan every NHI in the registry: backends first, then role grants, then control-plane report."""

from __future__ import annotations

from nhigov.backends.agent_id import AgentIdBackend
from nhigov.backends.base import IdentityBackend, Principals
from nhigov.backends.service_principal import ServicePrincipalBackend
from nhigov.reconcile.control_plane import control_plane_notes
from nhigov.reconcile.desired import build_desired
from nhigov.reconcile.engine import IdentityPlan, PlanContext
from nhigov.reconcile.grants import plan_grants
from nhigov.registry.models import Backend

BACKENDS: tuple[IdentityBackend, ...] = (AgentIdBackend(), ServicePrincipalBackend())


def plan_identities(
    ctx: PlanContext, default_backend: Backend, control_plane_client_ids: dict[str, str]
) -> IdentityPlan:
    desired = build_desired(ctx.registry, default_backend)
    plan = IdentityPlan()
    principals: Principals = {}
    for backend in BACKENDS:
        principals |= backend.plan(ctx, desired, plan)
    plan_grants(ctx, desired, principals, plan)
    plan.notes += control_plane_notes(ctx.graph, desired.control_plane, control_plane_client_ids)
    return plan
