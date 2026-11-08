"""NHI-010: past the workflow's `expires` or `review_by` date and still enabled (P6)."""

from __future__ import annotations

from collections.abc import Iterator

from nhigov.discovery.inventory import Inventory, Nhi
from nhigov.discovery.rules.base import Rule, ScanContext, Severity


def check(inv: Inventory, ctx: ScanContext) -> Iterator[tuple[Nhi, str]]:
    for nhi in inv.nhis:
        if nhi.enabled is False:
            continue
        for wf, _ in ctx.workflow_of(nhi):
            if wf.expires < ctx.today:
                yield nhi, f"{wf.id} expired on {wf.expires}"
            elif wf.review_by < ctx.today:
                yield nhi, f"{wf.id} review was due {wf.review_by}"


RULE = Rule(
    "NHI-010", "Past expiry or review date and still enabled", Severity.MEDIUM,
    "Expiry and review dates are how temporary access stays temporary. An NHI working past "
    "them is running on an approval that has lapsed (P6).",
    "Review and renew the workflow in the registry (new dates), or retire it; the lifecycle "
    "engine (`nhigov lifecycle run`) disables it after the grace period.",
    check,
)  # fmt: skip
