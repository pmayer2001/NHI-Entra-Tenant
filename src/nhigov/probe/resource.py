"""Read-only checks before registering a resource API (Phase 2, Part A).

Runs as `nhigov-scanner`, so it can't change anything. It answers the questions
that decide whether `apply` will work, before any write is attempted:

  A01  Will the tenant's identifier URI policy accept our URI?
  A02  Is the URI unused? (identifier URIs must be unique in a tenant)
  A03  Does an app with this name already exist? (create vs. adopt)
  A04  Does the provisioner hold the permission that creates the app and its SP?
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from nhigov.graph.client import GraphClient
from nhigov.probe.checks import classify
from nhigov.probe.report import redact
from nhigov.registry.models import Resource

MICROSOFT_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
CREATE_PERMISSION = "Application.ReadWrite.OwnedBy"  # least privileged for both creates (docs)
BROADER_THAN_NEEDED = ("Application.ReadWrite.All", "Directory.ReadWrite.All")

_GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"


class Verdict(StrEnum):
    GO = "go"
    BLOCKED = "blocked"
    WARN = "check"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Answer:
    id: str
    question: str
    verdict: Verdict
    detail: str


# ------------------------------------------------------------------ A01 (pure)


def _contains_unique_id(uri: str, tenant_id: str) -> bool:
    """`uriAdditionWithoutUniqueTenantIdentifier` allows URIs carrying the tenant ID or
    a GUID (we can't know the appId before creation). Verified domains aren't checked
    here; our URIs don't use them."""
    return tenant_id.lower() in uri.lower() or re.search(_GUID, uri) is not None


def uri_policy_verdict(
    policy: dict[str, Any],
    uri: str,
    token_version: int,
    tenant_id: str,
    now: datetime | None = None,
) -> tuple[Verdict, str]:
    """Would adding `uri` to a new app be allowed by the default app management policy?"""
    now = now or datetime.now(UTC)
    restrictions = (policy.get("applicationRestrictions") or {}).get("identifierUris") or {}
    blocking: list[str] = []
    notes: list[str] = []
    for name in ("nonDefaultUriAddition", "uriAdditionWithoutUniqueTenantIdentifier"):
        r = restrictions.get(name)
        if not r or r.get("state") != "enabled":
            notes.append(f"{name}: not enabled")
            continue
        after = r.get("restrictForAppsCreatedAfterDateTime")
        if after and datetime.fromisoformat(after.replace("Z", "+00:00")) > now:
            notes.append(f"{name}: enabled only for apps created after {after}")
            continue
        if token_version == 2 and r.get("excludeAppsReceivingV2Tokens"):
            notes.append(f"{name}: enabled, but v2-token apps are exempt")
            continue
        allowed: bool
        if name == "nonDefaultUriAddition":
            default_form = rf"api://({_GUID}|{re.escape(tenant_id)}/{_GUID})"
            allowed = re.fullmatch(default_form, uri) is not None
        else:
            allowed = _contains_unique_id(uri, tenant_id)
        if allowed:
            notes.append(f"{name}: enabled, URI complies")
        else:
            blocking.append(name)
    if not policy.get("isEnabled", True) and not blocking:
        notes.append("default policy isEnabled=false")
    if blocking:
        return Verdict.BLOCKED, (
            f"{', '.join(blocking)} would reject {uri} (v{token_version} tokens); "
            "fall back to api://<appId>, set after creation. " + "; ".join(notes)
        )
    return Verdict.GO, "; ".join(notes) or "no identifier URI restrictions configured"


# ------------------------------------------------------------------ live checks


def _get(graph: GraphClient, path: str, params: dict[str, str]) -> tuple[dict[str, Any], str]:
    """(body, error) without raising, so one failed check doesn't stop the others."""
    response = graph.request("GET", path, params=params, check=False)
    if response.is_success:
        body: dict[str, Any] = response.json()
        return body, ""
    outcome, code, message = classify(response)
    return {}, f"{outcome.value}: {code} {message}".strip()


def check_uri_policy(graph: GraphClient, uri: str, tenant_id: str) -> Answer:
    q = f"Identifier URI policy allows {uri}"
    policy, err = _get(graph, "policies/defaultAppManagementPolicy", {})
    if err:
        return Answer("A01", q, Verdict.UNKNOWN, err)
    verdict, detail = uri_policy_verdict(policy, uri, 2, tenant_id)
    return Answer("A01", q, verdict, detail)


def check_uri_unused(graph: GraphClient, uri: str, display_name: str) -> Answer:
    q = "Identifier URI is unused in the tenant"
    body, err = _get(
        graph,
        "applications",
        {"$filter": f"identifierUris/any(x:x eq '{uri}')", "$select": "id,displayName"},
    )
    if err:
        return Answer("A02", q, Verdict.UNKNOWN, err)
    owners = [a.get("displayName", "?") for a in body.get("value", [])]
    if not owners:
        return Answer("A02", q, Verdict.GO, "no application uses it")
    if owners == [display_name]:
        return Answer("A02", q, Verdict.WARN, f"already on {display_name}: apply would adopt it")
    return Answer("A02", q, Verdict.BLOCKED, f"already used by {', '.join(owners)}")


def check_name_free(graph: GraphClient, display_name: str) -> Answer:
    q = f"No existing app named {display_name}"
    body, err = _get(
        graph,
        "applications",
        {"$filter": f"displayName eq '{display_name}'", "$select": "id,appId,tags"},
    )
    if err:
        return Answer("A03", q, Verdict.UNKNOWN, err)
    found = body.get("value", [])
    if not found:
        return Answer("A03", q, Verdict.GO, "apply will create it")
    managed = all("nhigov:managed" in a.get("tags", []) for a in found)
    detail = f"{len(found)} found ({'tagged nhigov:managed' if managed else 'NOT tagged'})"
    return Answer("A03", q, Verdict.WARN, detail + "; apply must adopt or rename, not duplicate")


def check_provisioner_permissions(graph: GraphClient, provisioner_app_id: str) -> Answer:
    q = f"Provisioner holds {CREATE_PERMISSION}"
    sps, err = _get(
        graph, "servicePrincipals", {"$filter": f"appId eq '{provisioner_app_id}'", "$select": "id"}
    )
    if err or not sps.get("value"):
        return Answer("A04", q, Verdict.UNKNOWN, err or "provisioner service principal not found")
    graph_sp, err = _get(
        graph,
        "servicePrincipals",
        {"$filter": f"appId eq '{MICROSOFT_GRAPH_APP_ID}'", "$select": "id,appRoles"},
    )
    if err or not graph_sp.get("value"):
        return Answer("A04", q, Verdict.UNKNOWN, err or "Microsoft Graph SP not found")
    names: dict[str, str] = {
        str(r["id"]): str(r["value"]) for r in graph_sp["value"][0].get("appRoles", [])
    }
    assignments = list(
        graph.list_all(f"servicePrincipals/{sps['value'][0]['id']}/appRoleAssignments")
    )
    held = sorted(
        names.get(str(a["appRoleId"]), str(a["appRoleId"]))
        for a in assignments
        if a.get("resourceId") == graph_sp["value"][0]["id"]
    )
    if CREATE_PERMISSION not in held:
        return Answer("A04", q, Verdict.BLOCKED, f"holds: {', '.join(held) or 'nothing'}")
    broader = [p for p in BROADER_THAN_NEEDED if p in held]
    if broader:
        return Answer("A04", q, Verdict.WARN, f"also holds {', '.join(broader)} (more than §14.3)")
    return Answer("A04", q, Verdict.GO, f"{len(held)} Graph roles: {', '.join(held)}")


def run_resource_probe(
    graph: GraphClient, resource: Resource, tenant_id: str, provisioner_app_id: str
) -> list[Answer]:
    return [
        check_uri_policy(graph, resource.identifier_uri, tenant_id),
        check_uri_unused(graph, resource.identifier_uri, resource.id),
        check_name_free(graph, resource.id),
        check_provisioner_permissions(graph, provisioner_app_id),
    ]


def render_resource_probe(
    answers: list[Answer], application: dict[str, Any], service_principal: dict[str, Any]
) -> str:
    """Markdown for docs/spikes/. Details are redacted; the planned bodies hold only
    registry data (role IDs are derived from role names, not from the tenant)."""
    ready = all(a.verdict in (Verdict.GO, Verdict.WARN) for a in answers)
    lines = [
        "# Resource registration probe (Phase 2, Part A)",
        "",
        f"_Generated by `nhigov api probe` on {datetime.now(UTC):%Y-%m-%d}. Read-only, as "
        "nhigov-scanner. Re-run it rather than editing._",
        "",
        "| ID | Question | Verdict | Detail |",
        "|---|---|---|---|",
    ]
    for a in answers:
        detail = redact(" ".join(a.detail.split())).replace("|", r"\|")
        lines.append(f"| {a.id} | {a.question} | **{a.verdict.value}** | {detail} |")
    lines += [
        "",
        f"**Ready to plan `apply`:** {'yes' if ready else 'no, resolve the blocked rows first'}",
        "",
        "## What `apply` would send (as nhigov-provisioner)",
        "",
        "1. `POST /v1.0/applications`",
        "",
        "```json",
        json.dumps(application, indent=2),
        "```",
        "",
        "2. `POST /v1.0/servicePrincipals` (after the app replicates)",
        "",
        "```json",
        json.dumps({**service_principal, "appId": "<appId from step 1>"}, indent=2),
        "```",
        "",
        "Not checkable read-only: whether `idtyp` actually appears in issued tokens, and "
        "whether `appRoleAssignmentRequired` refuses unassigned clients. Phase 4's live "
        "tests cover both.",
        "",
    ]
    return "\n".join(lines)
