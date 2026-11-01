"""NHI-008: one NHI used by more than one workflow (P3)."""

from __future__ import annotations

from collections.abc import Iterator

from nhigov.discovery.inventory import Inventory, Nhi
from nhigov.discovery.rules.base import Rule, ScanContext, Severity


def check(inv: Inventory, ctx: ScanContext) -> Iterator[tuple[Nhi, str]]:
    for nhi in inv.nhis:
        if len(nhi.workflows) > 1:
            yield nhi, f"used by {len(nhi.workflows)} workflows: {', '.join(nhi.workflows)}"


RULE = Rule(
    "NHI-008", "One NHI shared by several workflows", Severity.HIGH,
    "A shared identity holds the union of every workflow's permissions, and its activity "
    "can't be attributed to one use case. Retiring one workflow can't remove its access (P3).",
    "Give each (workflow, agent) pair its own NHI and split the permissions.",
    check,
)  # fmt: skip
