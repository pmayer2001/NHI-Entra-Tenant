"""NHI-009: an NHI holds an app role that humans can hold (P4)."""

from __future__ import annotations

from collections.abc import Iterator

from nhigov.discovery.inventory import Inventory, Nhi
from nhigov.discovery.rules.base import Rule, ScanContext, Severity


def check(inv: Inventory, ctx: ScanContext) -> Iterator[tuple[Nhi, str]]:
    for nhi in inv.nhis:
        if nhi.classification == "microsoft-first-party":
            continue
        for g in nhi.grants:
            if "User" in g.member_types:
                yield nhi, f"holds {g.resource_name}:{g.role}, a role assignable to users"


RULE = Rule(
    "NHI-009", "NHI holds a human-assignable role", Severity.HIGH,
    "Roles designed for people usually mean broad data access (e.g. full records). NHI "
    "roles should be Application-only, so they can be scoped for agents separately (P4).",
    "Define an Application-only role with the narrower access the agent needs and move the "
    "NHI to it. Entra already refuses User-only roles for apps; this catches mixed ones.",
    check,
)  # fmt: skip
