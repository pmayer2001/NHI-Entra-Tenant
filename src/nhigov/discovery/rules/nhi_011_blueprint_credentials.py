"""NHI-011: a blueprint with more credentials than runtimes allow (ADR-003 blast radius)."""

from __future__ import annotations

from collections.abc import Iterator

from nhigov.discovery.inventory import Inventory, Nhi
from nhigov.discovery.rules.base import Rule, ScanContext, Severity


def check(inv: Inventory, ctx: ScanContext) -> Iterator[tuple[Nhi, str]]:
    limit = ctx.policy.max_blueprint_credentials
    for nhi in inv.nhis:
        if nhi.kind == "blueprint" and len(nhi.credentials) > limit:
            yield nhi, f"{len(nhi.credentials)} credentials (policy: {limit})"


RULE = Rule(
    "NHI-011", "Blueprint with too many credentials", Severity.MEDIUM,
    "Whoever holds any blueprint credential can get tokens for every agent identity under "
    "it (verified in Phase 0). Each extra credential is another place that key can leak.",
    "Keep one credential per runtime; remove the rest. Split agents into separate "
    "blueprints if they run in different trust zones.",
    check,
)  # fmt: skip
