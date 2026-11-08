"""NHI-013: an agent identity whose blueprint no longer exists."""

from __future__ import annotations

from collections.abc import Iterator

from nhigov.discovery.inventory import Inventory, Nhi
from nhigov.discovery.rules.base import Rule, ScanContext, Severity


def check(inv: Inventory, ctx: ScanContext) -> Iterator[tuple[Nhi, str]]:
    for nhi in inv.nhis:
        if nhi.kind == "agent_identity" and nhi.blueprint_exists is False:
            yield nhi, "its blueprint was deleted, but the agent identity remains"


RULE = Rule(
    "NHI-013", "Orphaned agent identity", Severity.HIGH,
    "Deleting a blueprint didn't cascade to its agent identities (Agent ID token spike). The "
    "orphans can't get tokens, but they keep their role assignments and sponsors, and "
    "would work again if the blueprint were restored.",
    "Delete the orphaned agent identity (agents first, then the blueprint, when retiring).",
    check,
)  # fmt: skip
