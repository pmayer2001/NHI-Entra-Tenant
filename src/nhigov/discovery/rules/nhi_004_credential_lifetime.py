"""NHI-004: credential valid longer than policy allows, or expired but still present."""

from __future__ import annotations

from collections.abc import Iterator

from nhigov.discovery.inventory import Inventory, Nhi
from nhigov.discovery.rules.base import Rule, ScanContext, Severity


def check(inv: Inventory, ctx: ScanContext) -> Iterator[tuple[Nhi, str]]:
    max_days = ctx.policy.max_credential_lifetime_days
    for nhi in inv.nhis:
        if not nhi.tenant_owned:
            continue
        for c in nhi.credentials:
            label = f"{c.kind} '{c.name or '?'}'"
            if c.lifetime_days is not None and c.lifetime_days > max_days:
                yield nhi, f"{label} is valid {c.lifetime_days} days (policy: {max_days})"
            if c.end is not None and c.end < ctx.now:
                yield nhi, f"{label} expired on {c.end.date()} but is still present"


RULE = Rule(
    "NHI-004", "Credential lifetime over policy, or expired and not removed", Severity.MEDIUM,
    "Long-lived credentials stay useful to an attacker for longer and are rarely rotated. "
    "Expired ones left in place hide which credential is really in use.",
    "Rotate to a credential within the policy lifetime (create, verify, then remove the old "
    "one), and delete expired credentials.",
    check,
)  # fmt: skip
