"""The IdentityBackend protocol (ADR-003).

Each backend plans the creation, adoption and enabling/disabling of its NHIs.
Role assignments are backend-agnostic (both backends end in a service
principal), so `reconcile.grants` plans those for every backend.
"""

from __future__ import annotations

from typing import Protocol

from nhigov.reconcile.desired import Desired
from nhigov.reconcile.engine import IdentityPlan, PlanContext
from nhigov.registry.models import Backend

# NHI key -> its principal's object ID if it exists now, or None if this plan
# creates it. NHIs that won't exist after apply are left out (no grants planned).
Principals = dict[str, str | None]


class IdentityBackend(Protocol):
    kind: Backend

    def plan(self, ctx: PlanContext, desired: Desired, plan: IdentityPlan) -> Principals: ...
