"""NHI-002: no accountable, enabled human behind the NHI (P6)."""

from __future__ import annotations

from collections.abc import Iterator

from nhigov.discovery.inventory import Inventory, Nhi
from nhigov.discovery.rules.base import Rule, ScanContext, Severity
from nhigov.registry.models import WorkflowStatus


def check(inv: Inventory, ctx: ScanContext) -> Iterator[tuple[Nhi, str]]:
    for nhi in inv.nhis:
        if not nhi.tenant_owned or nhi.kind == "resource":
            continue  # resources hold no credentials and can't act on their own
        pairs = ctx.workflow_of(nhi)
        if (
            nhi.enabled is False
            and pairs
            and all(wf.status is WorkflowStatus.RETIRED for wf, _ in pairs)
        ):
            continue  # retired and off: the lifecycle is deleting it; nobody needs to answer
        if pairs:  # managed: the registry's sponsor is the accountable human
            for wf, _ in pairs:
                person = inv.people.get(wf.sponsor.lower())
                if person is None:
                    yield nhi, f"registry sponsor {wf.sponsor} of {wf.id} doesn't exist"
                elif not person.enabled:
                    yield nhi, f"registry sponsor {wf.sponsor} of {wf.id} is disabled"
            continue
        humans = [
            p for p in [*nhi.owners, *nhi.sponsors]
            if p.kind == "user" and p.enabled and p.member is not False
        ]  # fmt: skip
        if not humans:
            others = sorted({p.kind for p in [*nhi.owners, *nhi.sponsors]})
            held_by = f" (only {', '.join(others)} owners)" if others else ""
            yield nhi, f"no enabled human owner or sponsor{held_by}"


RULE = Rule(
    "NHI-002", "No accountable human owner or sponsor", Severity.HIGH,
    "An NHI nobody answers for keeps working after its people leave: nobody reviews it, "
    "renews it or notices when it's misused (P6). A service principal owner isn't a person.",
    "Name an enabled member user as sponsor (registry `sponsor:` for managed NHIs, Entra "
    "owner/sponsor otherwise), or retire the NHI.",
    check,
)  # fmt: skip
