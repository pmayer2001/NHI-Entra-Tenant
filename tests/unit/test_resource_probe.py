"""Part A: resource request bodies and the read-only registration probe."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import respx

from nhigov.graph.client import GraphClient
from nhigov.probe.resource import (
    Verdict,
    render_resource_probe,
    run_resource_probe,
    uri_policy_verdict,
)
from nhigov.reconcile.control_plane import MICROSOFT_GRAPH_APP_ID
from nhigov.reconcile.resources import desired_application, desired_service_principal, role_id
from nhigov.registry.loader import load_registry

TENANT = "11111111-1111-1111-1111-111111111111"
URI = "api://nhigov-sensitive-records"
NOW = datetime(2026, 10, 31, tzinfo=UTC)
REGISTRY, _ = load_registry(Path(__file__).parents[2] / "registry")
RESOURCE = REGISTRY.resources["res-sensitive-records"]


# ------------------------------------------------------------------ desired bodies


def test_role_ids_are_stable_and_distinct() -> None:
    assert role_id("res-x", "A") == role_id("res-x", "A")
    assert role_id("res-x", "A") != role_id("res-x", "B")
    assert role_id("res-x", "A") != role_id("res-y", "A")


def test_desired_application_mirrors_registry() -> None:
    app = desired_application(RESOURCE)
    assert app["identifierUris"] == [URI]
    assert app["signInAudience"] == "AzureADMyOrg"
    assert app["api"]["requestedAccessTokenVersion"] == 2
    roles = {r["value"]: r for r in app["appRoles"]}
    assert roles["Records.Read.All"]["allowedMemberTypes"] == ["User"]  # P4 reaches Entra
    assert roles["Records.Read.Redacted"]["allowedMemberTypes"] == ["Application"]
    assert roles["Records.Annotate"]["id"] == role_id(RESOURCE.id, "Records.Annotate")
    assert [c["name"] for c in app["optionalClaims"]["accessToken"]] == ["idtyp"]
    assert "passwordCredentials" not in app and "keyCredentials" not in app  # API needs none


def test_unmanaged_resource_is_never_built() -> None:
    with pytest.raises(ValueError, match="not managed"):
        desired_application(REGISTRY.resources["microsoft-graph"])


def test_service_principal_requires_assignment() -> None:
    assert desired_service_principal("x", "res-x")["appRoleAssignmentRequired"] is True


# ------------------------------------------------------------------ A01 policy evaluation


def _policy(**restrictions: dict[str, Any]) -> dict[str, Any]:
    return {"isEnabled": True, "applicationRestrictions": {"identifierUris": restrictions}}


ENABLED = {"state": "enabled", "excludeAppsReceivingV2Tokens": True}
ENABLED_NO_V2_EXEMPTION = {"state": "enabled", "excludeAppsReceivingV2Tokens": False}

POLICY_CASES: list[tuple[str, dict[str, Any], str, int, Verdict]] = [
    ("no-restrictions", {"isEnabled": True}, URI, 2, Verdict.GO),
    ("disabled", _policy(nonDefaultUriAddition={"state": "disabled"}), URI, 2, Verdict.GO),
    ("v2-exempt", _policy(nonDefaultUriAddition=ENABLED,
                          uriAdditionWithoutUniqueTenantIdentifier=ENABLED), URI, 2, Verdict.GO),
    ("v1-blocked", _policy(uriAdditionWithoutUniqueTenantIdentifier=ENABLED), URI, 1,
     Verdict.BLOCKED),
    ("no-v2-exemption", _policy(nonDefaultUriAddition=ENABLED_NO_V2_EXEMPTION), URI, 2,
     Verdict.BLOCKED),
    ("default-uri-ok", _policy(nonDefaultUriAddition=ENABLED_NO_V2_EXEMPTION),
     "api://22222222-2222-2222-2222-222222222222", 2, Verdict.GO),
    ("tenant-id-uri-ok", _policy(uriAdditionWithoutUniqueTenantIdentifier=ENABLED_NO_V2_EXEMPTION),
     f"api://{TENANT}/records", 2, Verdict.GO),
    ("future-start-date", _policy(nonDefaultUriAddition={
        **ENABLED_NO_V2_EXEMPTION, "restrictForAppsCreatedAfterDateTime": "2027-01-01T00:00:00Z"}),
     URI, 2, Verdict.GO),
    ("past-start-date", _policy(nonDefaultUriAddition={
        **ENABLED_NO_V2_EXEMPTION, "restrictForAppsCreatedAfterDateTime": "2025-01-01T00:00:00Z"}),
     URI, 2, Verdict.BLOCKED),
]  # fmt: skip


@pytest.mark.parametrize(
    ("policy", "uri", "version", "expected"),
    [c[1:] for c in POLICY_CASES],
    ids=[c[0] for c in POLICY_CASES],
)
def test_uri_policy_verdict(
    policy: dict[str, Any], uri: str, version: int, expected: Verdict
) -> None:
    assert uri_policy_verdict(policy, uri, version, TENANT, now=NOW)[0] is expected


# ------------------------------------------------------------------ live checks (mocked)

G = "https://graph.microsoft.com/v1.0/"
PROV_APP_ID = "33333333-3333-3333-3333-333333333333"
OWNED_BY = {"id": "role-ownedby", "value": "Application.ReadWrite.OwnedBy"}
ASSIGN = {"id": "role-assign", "value": "AppRoleAssignment.ReadWrite.All"}


def _mock_tenant(*, existing_uri_owner: str | None = None, held: list[str] | None = None) -> None:
    respx.get(f"{G}policies/defaultAppManagementPolicy").respond(
        json=_policy(nonDefaultUriAddition=ENABLED)
    )

    def applications(request: Any) -> Any:
        flt = request.url.params["$filter"]
        if flt.startswith("identifierUris") and existing_uri_owner:
            return respx.MockResponse(json={"value": [{"displayName": existing_uri_owner}]})
        return respx.MockResponse(json={"value": []})

    respx.get(f"{G}applications").mock(side_effect=applications)

    def service_principals(request: Any) -> Any:
        if MICROSOFT_GRAPH_APP_ID in request.url.params["$filter"]:
            return respx.MockResponse(
                json={"value": [{"id": "graph-sp", "appRoles": [OWNED_BY, ASSIGN]}]}
            )
        return respx.MockResponse(json={"value": [{"id": "prov-sp"}]})

    respx.get(f"{G}servicePrincipals").mock(side_effect=service_principals)
    respx.get(f"{G}servicePrincipals/prov-sp/appRoleAssignments").respond(
        json={
            "value": [
                {"appRoleId": r, "resourceId": "graph-sp"}
                for r in (held if held is not None else ["role-ownedby", "role-assign"])
            ]
        }
    )


def _run() -> dict[str, Verdict]:
    with GraphClient(lambda: "t", sleep=lambda _: None) as graph:
        return {a.id: a.verdict for a in run_resource_probe(graph, RESOURCE, TENANT, PROV_APP_ID)}


@respx.mock
def test_clean_tenant_is_go() -> None:
    _mock_tenant()
    assert _run() == dict.fromkeys(("A01", "A02", "A03", "A04"), Verdict.GO)


@respx.mock
def test_uri_taken_by_another_app_blocks() -> None:
    _mock_tenant(existing_uri_owner="someone-else")
    assert _run()["A02"] is Verdict.BLOCKED


@respx.mock
def test_provisioner_without_create_permission_blocks() -> None:
    _mock_tenant(held=["role-assign"])
    assert _run()["A04"] is Verdict.BLOCKED


@respx.mock
def test_policy_unreadable_is_unknown_not_go() -> None:
    _mock_tenant()
    respx.get(f"{G}policies/defaultAppManagementPolicy").respond(
        403, json={"error": {"code": "Authorization_RequestDenied", "message": "no"}}
    )
    assert _run()["A01"] is Verdict.UNKNOWN


@respx.mock
def test_report_redacts_ids_but_keeps_planned_body() -> None:
    _mock_tenant(existing_uri_owner=f"app-{TENANT}")
    with GraphClient(lambda: "t", sleep=lambda _: None) as graph:
        answers = run_resource_probe(graph, RESOURCE, TENANT, PROV_APP_ID)
    md = render_resource_probe(
        answers, desired_application(RESOURCE), desired_service_principal("", RESOURCE.id)
    )
    assert TENANT not in md
    assert role_id(RESOURCE.id, "Records.Annotate") in md  # registry-derived, safe to commit
    assert "no, resolve the blocked rows first" in md
