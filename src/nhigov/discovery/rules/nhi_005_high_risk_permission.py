"""NHI-005: a high-risk Microsoft Graph permission without a valid registry exception."""

from __future__ import annotations

from collections.abc import Iterator

from nhigov.discovery.inventory import GRAPH_APP_ID, Inventory, Nhi
from nhigov.discovery.rules.base import Rule, ScanContext, Severity


def check(inv: Inventory, ctx: ScanContext) -> Iterator[tuple[Nhi, str]]:
    high_risk = set(ctx.policy.high_risk_permissions)
    for nhi in inv.nhis:
        if nhi.classification == "microsoft-first-party":
            continue
        for g in nhi.grants:
            risky = g.resource_app_id == GRAPH_APP_ID and g.role in high_risk
            if risky and ctx.exception_covering(nhi, g.role) is None:
                yield nhi, f"holds {g.role} on Microsoft Graph with no valid exception"


RULE = Rule(
    "NHI-005", "High-risk Graph permission without an exception", Severity.CRITICAL,
    "These permissions let an NHI take over the tenant or its data (grant itself anything, "
    "add credentials to any app, read every mailbox). Each one needs a written, expiring "
    "justification in the registry.",
    "Remove the permission, or add an `exception:` block (reason, approver, expiry, covers) "
    "to the workflow that needs it.",
    check,
)  # fmt: skip
