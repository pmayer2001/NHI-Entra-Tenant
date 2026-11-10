"""Discovery: inventory + rules on a synthetic tenant, and the collectors against a fake Graph.

The synthetic tenant plants one example of every rule plus look-alikes that must
NOT fire (a Microsoft first-party SP with a directory role, a managed NHI with
exactly its declared roles...), so each rule is shown to be both sensitive and
specific: the offline version of seed_mess's "every problem, and nothing else".
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import respx

from nhigov.discovery.collectors import RawTenant, collect_all
from nhigov.discovery.inventory import GRAPH_APP_ID, Inventory, build_inventory
from nhigov.discovery.rules import RULES, run_rules
from nhigov.discovery.rules.base import ScanContext
from nhigov.graph.client import GraphClient
from nhigov.reconcile.resources import role_id
from nhigov.reconcile.state import BlueprintRecord, NhiRecord, ResourceRecord, TenantState
from nhigov.registry.loader import load_registry
from nhigov.registry.models import WorkflowStatus

REGISTRY, _ = load_registry(Path(__file__).parents[2] / "registry")
TENANT = "11111111-1111-1111-1111-111111111111"
MS = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
NOW = datetime(2026, 11, 1, 12, tzinfo=UTC)
OWNER = {"id": "owner", "@odata.type": "#microsoft.graph.user"}
PROVISIONER = {"id": "prov-sp", "@odata.type": "#microsoft.graph.servicePrincipal"}
RES = "res-sensitive-records"


def _graph_role(value: str) -> dict[str, Any]:
    return {"id": f"g-{value}", "value": value, "allowedMemberTypes": ["Application"]}


def sp(id_: str, name: str, *, local: bool = True, **extra: Any) -> dict[str, Any]:
    return {
        "id": id_, "appId": f"{id_}-app", "displayName": name,
        "servicePrincipalType": "Application",
        "appOwnerOrganizationId": TENANT if local else MS, "accountEnabled": True, "tags": [],
        "passwordCredentials": [], "keyCredentials": [], "appRoles": [], "local": local,
        "agentKind": None, "owners": [], "appRoleAssignments": [], **extra,
    }  # fmt: skip


def app(sp_: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "id": f"{sp_['id']}-obj", "appId": sp_["appId"], "displayName": sp_["displayName"],
        "tags": [], "passwordCredentials": [], "keyCredentials": [], "owners": [OWNER],
        "federatedIdentityCredentials": [], **extra,
    }  # fmt: skip


def assign(resource: str, role: str) -> dict[str, Any]:
    return {"id": f"a-{resource}-{role}", "resourceId": resource, "appRoleId": role}


def cert(days: int, end_offset: int = 30) -> dict[str, Any]:
    end = NOW + timedelta(days=end_offset)
    return {"displayName": f"{days}d", "startDateTime": (end - timedelta(days=days)).isoformat(),
            "endDateTime": end.isoformat()}  # fmt: skip


def synthetic_tenant() -> tuple[RawTenant, TenantState, dict[str, str]]:
    records_roles = [
        {"id": role_id(RES, r.value), "value": r.value, "allowedMemberTypes": r.member_types}
        for r in REGISTRY.resources[RES].app_roles
    ]
    graph = sp("graph", "Microsoft Graph", local=False, appId=GRAPH_APP_ID, appRoles=[
        _graph_role(v) for v in ("Directory.ReadWrite.All", "AppRoleAssignment.ReadWrite.All",
                                 "Application.Read.All", "AgentIdentity.CreateAsManager")
    ])  # fmt: skip
    resource = sp("res", RES, appRoles=records_roles, owners=[PROVISIONER])
    summarizer = sp(
        "summ", "nhi-wf-claims-triage-agent-summarizer", agentKind="agentIdentity",
        servicePrincipalType="ServiceIdentity", agentIdentityBlueprintId="bp-summ-app",
        sponsors=[OWNER], appRoleAssignments=[
            assign("res", role_id(RES, "Records.Read.Redacted")),
            assign("res", role_id(RES, "Records.Annotate")),  # drift -> NHI-007
        ],
    )  # fmt: skip
    bp_principal = sp("bp-summ", "bp-agent-summarizer", agentKind="blueprintPrincipal",
                      appId="bp-summ-app", owners=[PROVISIONER])  # fmt: skip
    control = sp("scanner-sp", "nhigov-scanner", appId="scanner-app", appRoleAssignments=[
        assign("graph", "g-Application.Read.All")])  # fmt: skip
    provisioner = sp(
        "prov-sp",
        "nhigov-provisioner",
        appId="prov-app",
        appRoleAssignments=[assign("graph", "g-AppRoleAssignment.ReadWrite.All")],
    )  # covered by its exception
    secret_app = sp("secret", "seed-secret-app", owners=[PROVISIONER])
    long_cert = sp("longcert", "seed-longcert-app", owners=[PROVISIONER])
    graph_admin = sp(
        "gadmin",
        "seed-graph-admin",
        owners=[PROVISIONER],
        appRoleAssignments=[assign("graph", "g-Directory.ReadWrite.All")],
    )
    dir_role = sp("dirrole", "seed-dir-role", owners=[PROVISIONER])
    shared = sp(
        "shared",
        "seed-shared-sp",
        owners=[OWNER],
        tags=["nhigov:workflow=wf-claims-triage", "nhigov:workflow=wf-sp-backend-demo"],
    )
    mixed_role = sp("mixed", "seed-mixed-role", owners=[OWNER], appRoleAssignments=[
        assign("res", role_id(RES, "Records.Read.All"))])  # fmt: skip
    orphan = sp("orphan", "seed-orphan-agent", agentKind="agentIdentity", sponsors=[OWNER],
                agentIdentityBlueprintId="deleted-bp-app")  # fmt: skip
    ms_with_role = sp("ms-admin", "Some Microsoft service", local=False)

    sps = [graph, resource, summarizer, bp_principal, control, provisioner, secret_app,
           long_cert, graph_admin, dir_role, shared, mixed_role, orphan, ms_with_role]  # fmt: skip
    apps = [
        app(resource, owners=[PROVISIONER]),
        app(bp_principal, id="bp-summ-obj", keyCredentials=[cert(180)], owners=[PROVISIONER],
            sponsors=[OWNER]),
        app(control, id="scanner-obj", keyCredentials=[cert(180)], owners=[]),
        app(provisioner, id="prov-obj", keyCredentials=[cert(180)], owners=[]),
        app(secret_app, owners=[PROVISIONER], passwordCredentials=[cert(6)]),
        app(long_cert, owners=[PROVISIONER], keyCredentials=[cert(730)]),
        app(graph_admin, owners=[PROVISIONER]),
        app(dir_role, owners=[PROVISIONER]),
        {**app(sp("x", "seed-bp-many-creds"), keyCredentials=[cert(90), cert(90), cert(90)],
               owners=[PROVISIONER], sponsors=[OWNER]), "id": "bp-many-obj", "appId": "bp-many"},
    ]  # fmt: skip
    raw = RawTenant(
        tenant_id=TENANT, applications=apps, blueprint_ids={"bp-summ-obj", "bp-many-obj"},
        service_principals=sps,
        directory_roles={"dirrole": ["Directory Readers"], "ms-admin": ["Global Reader"]},
        users={"owner": {"id": "owner", "userPrincipalName": "owner@tenant.example",
                        "accountEnabled": True, "userType": "Member"},
               "owner@tenant.example": {"id": "owner", "userPrincipalName": "owner@tenant.example",
                                       "accountEnabled": True, "userType": "Member"}},
    )  # fmt: skip
    state = TenantState(
        resources={RES: ResourceRecord(application_object_id="res-obj", app_id="res-app",
                                       service_principal_id="res")},
        blueprints={"agent-summarizer": BlueprintRecord(
            application_object_id="bp-summ-obj", app_id="bp-summ-app", principal_id="bp-summ")},
        nhis={"wf-claims-triage/agent-summarizer": NhiRecord(
            backend="agent_id", principal_id="summ", app_id="summ", blueprint="agent-summarizer")},
    )  # fmt: skip
    return raw, state, {"nhigov-scanner": "scanner-app", "nhigov-provisioner": "prov-app"}


def scan(raw: RawTenant, state: TenantState, clients: dict[str, str]) -> set[tuple[str, str]]:
    inventory = build_inventory(raw, state, clients, NOW)
    ctx = ScanContext(REGISTRY, NOW, {"res": RES})
    return {(f.rule, f.display_name) for f in run_rules(inventory, ctx)}


EXPECTED = {
    ("NHI-007", "nhi-wf-claims-triage-agent-summarizer"),  # undeclared Records.Annotate
    ("NHI-007", "bp-agent-summarizer"),  # a Graph role beyond policy.blueprint_graph_grants
    *{("NHI-001", n) for n in ("seed-secret-app", "seed-longcert-app", "seed-graph-admin",
                               "seed-dir-role", "seed-shared-sp", "seed-mixed-role",
                               "seed-orphan-agent", "seed-bp-many-creds")},
    *{("NHI-002", n) for n in ("seed-secret-app", "seed-longcert-app", "seed-graph-admin",
                               "seed-dir-role")},
    ("NHI-003", "seed-secret-app"),
    ("NHI-004", "seed-longcert-app"),
    ("NHI-005", "seed-graph-admin"),
    ("NHI-006", "seed-dir-role"),
    ("NHI-008", "seed-shared-sp"),
    ("NHI-009", "seed-mixed-role"),
    ("NHI-011", "seed-bp-many-creds"),
    ("NHI-013", "seed-orphan-agent"),
}  # fmt: skip


def test_every_planted_problem_is_found_and_nothing_else() -> None:
    raw, state, clients = synthetic_tenant()
    raw.service_principals[3]["appRoleAssignments"] = [
        assign("graph", "g-AgentIdentity.CreateAsManager"),  # Entra's own: accepted by policy
        assign("graph", "g-Application.Read.All"),  # added by someone: drift
    ]
    assert scan(raw, state, clients) == EXPECTED


def test_every_rule_except_010_is_exercised_by_the_synthetic_tenant() -> None:
    covered = {rule for rule, _ in EXPECTED}
    assert {r.id for r in RULES} - covered == {"NHI-010"}  # dates: tested below


def test_classification() -> None:
    raw, state, clients = synthetic_tenant()
    inv = build_inventory(raw, state, clients, NOW)
    by_name = {n.display_name: n for n in inv.nhis}
    assert by_name["Microsoft Graph"].classification == "microsoft-first-party"
    assert by_name["nhigov-scanner"].classification == "managed"  # via config client ID
    assert by_name["nhigov-scanner"].registry_keys == ["control:nhigov-scanner"]
    assert by_name["seed-secret-app"].classification == "shadow"
    assert by_name["bp-agent-summarizer"].kind == "blueprint"
    assert by_name[RES].kind == "resource"
    assert by_name["seed-bp-many-creds"].kind == "blueprint"  # app with no principal
    assert by_name["seed-orphan-agent"].blueprint_exists is False
    secret = by_name["seed-secret-app"].credentials
    assert [(c.kind, c.on) for c in secret] == [("secret", "application")]


def test_expired_workflow_still_enabled_is_nhi_010() -> None:
    raw, state, clients = synthetic_tenant()
    inventory = build_inventory(raw, state, clients, NOW)
    later = datetime(2027, 6, 1, tzinfo=UTC)  # after wf-claims-triage expires (2027-03-31)
    findings = run_rules(inventory, ScanContext(REGISTRY, later, {"res": RES}))
    assert ("NHI-010", "nhi-wf-claims-triage-agent-summarizer") in {
        (f.rule, f.display_name) for f in findings
    }


def test_disabled_sponsor_is_nhi_002_for_managed_nhis() -> None:
    raw, state, clients = synthetic_tenant()
    for user in raw.users.values():
        user["accountEnabled"] = False
    assert ("NHI-002", "nhi-wf-claims-triage-agent-summarizer") in scan(raw, state, clients)


def test_a_retired_disabled_nhi_needs_no_sponsor() -> None:
    # Retired and already off: the lifecycle is deleting it, so a departed sponsor isn't
    # a finding (it would keep the nightly scan red until the soft-delete).
    raw, state, clients = synthetic_tenant()
    for user in raw.users.values():
        user["accountEnabled"] = False
    nhi = next(
        s for s in raw.service_principals
        if s["displayName"] == "nhi-wf-claims-triage-agent-summarizer"
    )  # fmt: skip
    nhi["accountEnabled"] = False
    wf = REGISTRY.workflows["wf-claims-triage"]
    retired = replace(
        REGISTRY,
        workflows={**REGISTRY.workflows,
                   wf.id: wf.model_copy(update={"status": WorkflowStatus.RETIRED})},
    )  # fmt: skip
    ctx = ScanContext(retired, NOW, {"res": RES})

    def found() -> set[tuple[str, str]]:
        inv = build_inventory(raw, state, clients, NOW)
        return {(f.rule, f.display_name) for f in run_rules(inv, ctx)}

    assert ("NHI-002", "nhi-wf-claims-triage-agent-summarizer") not in found()
    # Still enabled while retired: someone must answer for it, so it's still flagged.
    nhi["accountEnabled"] = True
    assert ("NHI-002", "nhi-wf-claims-triage-agent-summarizer") in found()


def test_inventory_round_trips(tmp_path: Path) -> None:
    raw, state, clients = synthetic_tenant()
    inv = build_inventory(raw, state, clients, NOW)
    inv.save(tmp_path / "inv.json")
    assert Inventory.load(tmp_path / "inv.json") == inv


def test_finding_keys_are_stable_for_dedupe() -> None:
    raw, state, clients = synthetic_tenant()
    inventory = build_inventory(raw, state, clients, NOW)
    findings = run_rules(inventory, ScanContext(REGISTRY, NOW, {"res": RES}))
    assert any(f.key == "NHI-003:secret" for f in findings)


# ------------------------------------------------------------------ collectors


@respx.mock
def test_collectors_expand_local_objects_only() -> None:
    g = "https://graph.microsoft.com/v1.0/"
    empty = {"value": []}
    respx.get(f"{g}applications/microsoft.graph.agentIdentityBlueprint").respond(json=empty)
    # Page 2 first: respx matches routes in order, and the page-1 route would match both.
    respx.get(f"{g}applications", params={"$skiptoken": "2"}).respond(json={
        "value": [{"id": "a2", "appId": "app2", "displayName": "mine too"}]})  # fmt: skip
    respx.get(f"{g}applications").respond(json={
        "value": [{"id": "a1", "appId": "app1", "displayName": "mine"}],
        "@odata.nextLink": f"{g}applications?$skiptoken=2",
    })  # fmt: skip
    respx.get(url__regex=rf"{g}applications/a\d/owners.*").respond(json={"value": [OWNER]})
    respx.get(url__regex=rf"{g}applications/a\d/federatedIdentityCredentials").respond(json=empty)
    respx.get(f"{g}servicePrincipals/microsoft.graph.agentIdentity").respond(json=empty)
    respx.get(f"{g}servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal").respond(
        json=empty
    )
    respx.get(f"{g}servicePrincipals").respond(json={"value": [
        sp("s1", "mine", appId="app1"), sp("ms", "Microsoft thing", local=False),
    ]})  # fmt: skip
    expanded = respx.get(url__regex=rf"{g}servicePrincipals/s1/(owners|appRoleAssignments).*")
    expanded.respond(json=empty)
    not_expanded = respx.get(url__regex=rf"{g}servicePrincipals/ms/.*").respond(json=empty)
    respx.get(f"{g}oauth2PermissionGrants").respond(json=empty)
    respx.get(f"{g}roleManagement/directory/roleDefinitions").respond(json=empty)
    respx.get(f"{g}roleManagement/directory/roleAssignments").respond(json=empty)
    respx.get(f"{g}users/owner").respond(json={
        "id": "owner", "userPrincipalName": "p@t.example", "accountEnabled": True})  # fmt: skip

    with GraphClient(lambda: "t", sleep=lambda _: None) as graph:
        raw = collect_all(graph, TENANT, set())
    assert [a["id"] for a in raw.applications] == ["a1", "a2"]  # followed nextLink
    assert expanded.call_count == 2 and not not_expanded.called
    assert raw.users["p@t.example"]["id"] == "owner"


def test_policy_listed_blueprint_grant_is_not_drift() -> None:
    raw, state, clients = synthetic_tenant()
    raw.service_principals[3]["appRoleAssignments"] = [
        assign("graph", "g-AgentIdentity.CreateAsManager")
    ]
    findings = scan(raw, state, clients)
    assert ("NHI-007", "bp-agent-summarizer") not in findings
