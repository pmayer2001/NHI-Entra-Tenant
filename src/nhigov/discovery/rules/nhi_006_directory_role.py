"""NHI-006: an NHI holding an Entra directory role."""

from __future__ import annotations

from collections.abc import Iterator

from nhigov.discovery.inventory import Inventory, Nhi
from nhigov.discovery.rules.base import Rule, ScanContext, Severity


def check(inv: Inventory, ctx: ScanContext) -> Iterator[tuple[Nhi, str]]:
    for nhi in inv.nhis:
        if nhi.classification != "microsoft-first-party" and nhi.directory_roles:
            yield nhi, f"holds directory role(s): {', '.join(nhi.directory_roles)}"


RULE = Rule(
    "NHI-006", "NHI holds an Entra directory role", Severity.CRITICAL,
    "Directory roles administer Entra itself. On an NHI they're standing admin rights with "
    "no MFA and no human in the loop; even read roles expose the whole directory.",
    "Remove the role assignment and grant the narrowest Graph application permission the "
    "workload actually needs.",
    check,
)  # fmt: skip
