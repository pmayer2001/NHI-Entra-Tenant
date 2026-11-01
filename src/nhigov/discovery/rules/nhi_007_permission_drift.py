"""NHI-007: a managed NHI holds permissions the registry doesn't declare (drift)."""

from __future__ import annotations

from collections.abc import Iterator

from nhigov.discovery.inventory import Inventory, Nhi
from nhigov.discovery.rules.base import Rule, ScanContext, Severity


def check(inv: Inventory, ctx: ScanContext) -> Iterator[tuple[Nhi, str]]:
    for nhi in inv.nhis:
        if nhi.classification != "managed":
            continue
        declared = ctx.declared(nhi)
        if declared is None:
            continue
        extra = sorted(
            f"{ctx.registry_resource(g)}:{g.role}"
            for g in nhi.grants
            if (ctx.registry_resource(g), g.role) not in declared
        )
        if extra:
            yield nhi, f"holds undeclared {', '.join(extra)}"


RULE = Rule(
    "NHI-007", "Permissions beyond what the registry declares", Severity.HIGH,
    "The registry is the reviewed record of what each NHI may do. Anything granted outside "
    "it skipped review, and least-privilege tests (P8) don't cover it.",
    "Declare it in the registry (if it's needed) or revoke it. For roles on managed "
    "resources, `nhigov apply` revokes undeclared grants.",
    check,
)  # fmt: skip
