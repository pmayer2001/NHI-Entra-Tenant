"""Probe check definitions and response classification.

A free tenant fails in different ways depending on *why* a call is refused, and
the difference matters for what we build:

* 403 Authorization_RequestDenied     -> missing Graph permission: fixable for free
* 403 ...NonPremiumTenant... / license -> feature needs P1/P2: emulate it or use the trial
* 400/404 on a typed-cast segment      -> the API/type isn't available in this tenant
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal

import httpx

Identity = Literal["scanner", "provisioner"]


class Outcome(StrEnum):
    OK = "OK"
    FORBIDDEN = "403 permission"
    LICENSE = "license required"
    NOT_FOUND = "not found"
    UNAVAILABLE = "unavailable (400)"
    ERROR = "error"
    PLANNED = "planned (dry run)"
    SKIPPED = "skipped"


# Error codes and message fragments Entra uses when a feature needs a premium SKU.
_LICENSE_MARKERS = (
    "nonpremiumtenant",
    "premium",
    "license",
    "aad_premium",
    "b2ctenant",
)


@dataclass(frozen=True)
class Check:
    id: str
    capability: str
    identity: Identity
    method: str
    path: str
    decides: str
    version: str = "v1.0"
    params: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] | None = None

    @property
    def request_line(self) -> str:
        return f"{self.method} /{self.version}/{self.path.lstrip('/')}"


@dataclass(frozen=True)
class Result:
    check: Check
    outcome: Outcome
    status: int | None = None
    code: str = ""
    detail: str = ""
    request_id: str | None = None


def classify(response: httpx.Response) -> tuple[Outcome, str, str]:
    """Map a Graph response to (outcome, error code, short message)."""
    if response.is_success:
        return Outcome.OK, "", ""
    code, message = "", response.text[:300]
    try:
        err = response.json().get("error", {})
        code = str(err.get("code", ""))
        message = str(err.get("message", message))
    except ValueError:
        pass
    haystack = f"{code} {message}".lower()
    status = response.status_code
    if status in (401, 403) and any(m in haystack for m in _LICENSE_MARKERS):
        return Outcome.LICENSE, code, message
    if status in (401, 403):
        return Outcome.FORBIDDEN, code, message
    if status == 404:
        return Outcome.NOT_FOUND, code, message
    if status == 400:
        return Outcome.UNAVAILABLE, code, message
    return Outcome.ERROR, code, message


TOP1 = {"$top": "1"}

READ_CHECKS: tuple[Check, ...] = (
    Check(
        "R01",
        "List applications",
        "scanner",
        "GET",
        "applications",
        "Baseline: scanner can read app registrations",
        params=TOP1,
    ),
    Check(
        "R02",
        "List service principals",
        "scanner",
        "GET",
        "servicePrincipals",
        "Baseline: scanner can read enterprise apps / SPs",
        params=TOP1,
    ),
    Check(
        "R03",
        "Subscribed SKUs (tenant licenses)",
        "scanner",
        "GET",
        "subscribedSkus",
        "Records which licenses the tenant actually has",
    ),
    Check(
        "R04",
        "List agent identity blueprints",
        "scanner",
        "GET",
        "applications/microsoft.graph.agentIdentityBlueprint",
        "Agent ID types exist in this tenant (ADR-003)",
        params=TOP1,
    ),
    Check(
        "R05",
        "List agent identity blueprint principals",
        "scanner",
        "GET",
        "servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal",
        "Agent ID collectors for discovery",
        params=TOP1,
    ),
    Check(
        "R06",
        "List agent identities",
        "scanner",
        "GET",
        "servicePrincipals/microsoft.graph.agentIdentity",
        "Agent ID collectors for discovery",
        params=TOP1,
    ),
    Check(
        "R07",
        "Directory role assignments",
        "scanner",
        "GET",
        "roleManagement/directory/roleAssignments",
        "NHI-006 (NHI holds a directory role)",
        params=TOP1,
    ),
    Check(
        "R08",
        "Directory audit log",
        "scanner",
        "GET",
        "auditLogs/directoryAudits",
        "Who-changed-what evidence for lifecycle",
        params=TOP1,
    ),
    Check(
        "R09",
        "Service principal sign-in logs",
        "scanner",
        "GET",
        "auditLogs/signIns",
        "L2 unused-resource detection (§9)",
        version="beta",
        params={"$top": "1", "$filter": "signInEventTypes/any(t: t eq 'servicePrincipal')"},
    ),
    Check(
        "R10",
        "servicePrincipalSignInActivities report",
        "scanner",
        "GET",
        "reports/servicePrincipalSignInActivities",
        "L1 dormant-identity detection (§9)",
        version="beta",
        params=TOP1,
    ),
    Check(
        "R11",
        "appCredentialSignInActivities report",
        "scanner",
        "GET",
        "reports/appCredentialSignInActivities",
        "L1 unused-credential detection (§9)",
        version="beta",
        params=TOP1,
    ),
    Check(
        "R12",
        "Default app management policy (read)",
        "scanner",
        "GET",
        "policies/defaultAppManagementPolicy",
        "Whether tenant-wide credential restrictions are available (§8)",
    ),
    Check(
        "R13",
        "Directory extension properties",
        "scanner",
        "POST",
        "directoryObjects/getAvailableExtensionProperties",
        "Fallback place to tag objects if Agent ID tags fail (ADR-006)",
        body={"isSyncedFromOnPremises": False},
    ),
)
