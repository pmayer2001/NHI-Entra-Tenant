"""NHI-001: an NHI created in this tenant that the registry doesn't know (P1)."""

from __future__ import annotations

from collections.abc import Iterator

from nhigov.discovery.inventory import Inventory, Nhi
from nhigov.discovery.rules.base import Rule, ScanContext, Severity


def check(inv: Inventory, ctx: ScanContext) -> Iterator[tuple[Nhi, str]]:
    for nhi in inv.nhis:
        if nhi.classification == "shadow":
            yield nhi, f"{nhi.kind} '{nhi.display_name}' isn't in the registry"


RULE = Rule(
    "NHI-001", "Shadow NHI (not in the registry)", Severity.HIGH,
    "Every use of AI must be a registered workflow (P1). An unregistered identity has no "
    "owner of record, no expiry and no declared permissions to check against.",
    "Register it (a workflow + agent in registry/) and adopt it, or disable and delete it.",
    check,
)  # fmt: skip
