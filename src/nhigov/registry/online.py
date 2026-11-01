"""`nhigov validate --online`: checks that need the tenant (read-only, as the scanner).

REG-020: every sponsor, business owner and exception approver must be a real,
enabled user. A sponsor who left the company is the classic orphaned-NHI cause
(NHI-002), so catch it at review time, not just in the nightly scan.
"""

from __future__ import annotations

from collections.abc import Iterator

from nhigov.graph.client import GraphClient, GraphError
from nhigov.registry.findings import Finding, Severity
from nhigov.registry.loader import Registry


def _people(reg: Registry) -> Iterator[tuple[str, str, str]]:
    """(workflow id, role, upn) for every human the registry names."""
    for wf in reg.workflows.values():
        yield wf.id, "sponsor", wf.sponsor
        yield wf.id, "business_owner", wf.business_owner
        if wf.exception:
            yield wf.id, "exception approver", wf.exception.approved_by


def validate_online(reg: Registry, graph: GraphClient) -> list[Finding]:
    findings: list[Finding] = []
    seen: dict[str, dict[str, object] | None] = {}
    for wf_id, role, upn in _people(reg):
        if upn not in seen:
            try:
                seen[upn] = graph.get(f"users/{upn}", params={"$select": "accountEnabled,userType"})
            except GraphError as exc:
                if exc.status != 404:
                    raise
                seen[upn] = None
        user = seen[upn]
        if user is None:
            findings.append(
                Finding("REG-020", Severity.ERROR, f"{role} {upn} not found in tenant", wf_id)
            )
        elif user.get("accountEnabled") is False:
            findings.append(Finding("REG-020", Severity.ERROR, f"{role} {upn} is disabled", wf_id))
        elif user.get("userType") == "Guest":
            findings.append(
                Finding(
                    "REG-020",
                    Severity.WARNING,
                    f"{role} {upn} is a guest; accountability should sit with a member user",
                    wf_id,
                )
            )
    return findings
