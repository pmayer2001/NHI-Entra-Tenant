"""Phase 3: blueprints, agent identities, SP-backend NHIs and role grants (fake tenant).

Acceptance (CLAUDE.md §12): after apply, a second plan shows no changes.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest
import respx
from fake_tenant import FakeTenant

from nhigov.certs import generate_self_signed
from nhigov.graph.client import GraphClient
from nhigov.reconcile.desired import build_desired
from nhigov.reconcile.engine import IdentityPlan, PlanContext, PlanError, apply_steps
from nhigov.reconcile.identities import plan_identities
from nhigov.reconcile.plan import apply_plan, plan_resource
from nhigov.reconcile.resources import role_id
from nhigov.reconcile.state import TenantState
from nhigov.registry.loader import Registry, load_registry
from nhigov.registry.models import Backend, WorkflowStatus

REGISTRY, _ = load_registry(Path(__file__).parents[2] / "registry")
RESOURCE = REGISTRY.resources["res-sensitive-records"]
TODAY = date(2026, 11, 1)
SPONSOR = "paul@tenant.example"  # the loader's offline placeholder domain
DEPARTING = "test-departing-sponsor@tenant.example"  # wf-lifecycle-test (Phase 6)
CLIENTS = {"nhigov-scanner": "scanner-app", "nhigov-provisioner": "provisioner-app"}
SUMMARIZER = "wf-claims-triage/agent-summarizer"
ROUTER = "wf-claims-triage/agent-router"
DEMO = "wf-sp-backend-demo/agent-router"
CERT_NAMES = ("bp-agent-summarizer", "bp-agent-router", "nhi-wf-sp-backend-demo-agent-router")


def _control_plane_roles(agent: str) -> list[str]:
    wf = REGISTRY.workflows["wf-control-plane"]
    return [r for wa in wf.agents if wa.ref == agent for p in wa.permissions for r in p.app_roles]


@pytest.fixture(scope="module")
def cert_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("certs")
    for name in CERT_NAMES:
        generate_self_signed(name, path, 180)
    return path


def tenant(**kwargs: int) -> FakeTenant:
    t = FakeTenant(**kwargs)
    t.add_user(SPONSOR)
    t.add_user(DEPARTING)
    scanner, provisioner = (
        _control_plane_roles("nhigov-scanner"),
        _control_plane_roles("nhigov-provisioner"),
    )
    t.add_graph_sp(
        sorted({*scanner, *provisioner, "Directory.ReadWrite.All", "AgentIdentity.CreateAsManager"})
    )
    t.add_client("scanner-sp", "scanner-app", scanner)
    t.add_client("provisioner-sp", "provisioner-app", provisioner)
    t.install()
    return t


def _graph() -> GraphClient:
    return GraphClient(lambda: "t", sleep=lambda _: None)


def plan(state: TenantState, cert_dir: Path, registry: Registry = REGISTRY) -> IdentityPlan:
    with _graph() as g:
        ctx = PlanContext(graph=g, registry=registry, state=state, today=TODAY, cert_dir=cert_dir)
        return plan_identities(ctx, Backend.AGENT_ID, CLIENTS)


def apply(state: TenantState, cert_dir: Path, registry: Registry = REGISTRY) -> IdentityPlan:
    """What `nhigov apply` does: resources first, then identities."""
    with _graph() as g:
        resource_plan = plan_resource(g, RESOURCE, state)
        if not resource_plan.is_noop:
            apply_plan(g, resource_plan, state, save=lambda s: None, sleep=lambda _: None)
    identity_plan = plan(state, cert_dir, registry)
    with _graph() as g:
        apply_steps(g, identity_plan.steps, state, save=lambda s: None, sleep=lambda _: None)
    return identity_plan


def with_workflow(registry: Registry, wf_id: str, **changes: object) -> Registry:
    workflows = dict(registry.workflows)
    workflows[wf_id] = workflows[wf_id].model_copy(update=changes)
    return replace(registry, workflows=workflows)


def kinds(p: IdentityPlan) -> list[tuple[str, str]]:
    return [(s.kind, s.key) for s in p.steps]


# ------------------------------------------------------------------ desired state (pure)


def test_desired_maps_registry_to_backends() -> None:
    d = build_desired(REGISTRY, Backend.AGENT_ID)
    assert set(d.blueprints) == {"agent-summarizer", "agent-router"}
    assert d.blueprints["agent-router"].sponsor_upns == (SPONSOR, DEPARTING)
    assert d.nhis[DEMO].backend is Backend.SERVICE_PRINCIPAL  # per-workflow override
    assert d.nhis[ROUTER].backend is Backend.AGENT_ID
    assert d.nhis[ROUTER].name == "nhi-wf-claims-triage-agent-router"
    assert {cp.agent_id for cp in d.control_plane} == {"nhigov-scanner", "nhigov-provisioner"}
    assert not any(k.startswith("wf-control-plane/") for k in d.nhis)  # report-only (P9)


# ------------------------------------------------------------------ first apply


@respx.mock
def test_first_plan_creates_in_dependency_order(cert_dir: Path) -> None:
    tenant()
    state = TenantState()
    with _graph() as g:
        apply_plan(g, plan_resource(g, RESOURCE, state), state, lambda s: None, lambda _: None)
    order = [k for k, _ in kinds(plan(state, cert_dir))]
    assert order.index("blueprint.create") < order.index("blueprint.principal")
    assert order.index("blueprint.principal") < order.index("agent.create")
    assert order.index("agent.create") < order.index("grant.add")
    assert order.count("blueprint.credential") == 2
    assert order.count("agent.create") == 3  # claims triage x2, lifecycle test
    assert order.count("spnhi.create") == 1
    assert order.count("grant.add") == 5  # summarizer 1, router 2, demo 1, lifecycle 1


@respx.mock
def test_apply_then_plan_again_is_a_noop(cert_dir: Path) -> None:
    t = tenant(agent_lag_failures=2, sp_lag_failures=1)  # replication lag on creates
    state = TenantState()
    apply(state, cert_dir)
    writes = len(t.writes)

    again = plan(state, cert_dir)
    assert again.steps == []
    assert len(t.writes) == writes
    assert any("sponsors not verifiable read-only" in n for n in again.notes)

    def roles_of(key: str) -> set[str]:
        principal = state.nhis[key].principal_id
        assert principal is not None
        names = {role_id(RESOURCE.id, r.value): r.value for r in RESOURCE.app_roles}
        return {names[a["appRoleId"]] for a in t.assignments[principal]}

    assert roles_of(SUMMARIZER) == {"Records.Read.Redacted"}
    assert roles_of(ROUTER) == {"Records.Read.Metadata", "Records.Annotate"}
    assert roles_of(DEMO) == {"Records.Read.Metadata"}
    assert all(bp["keyCredentials"] for bp in t.blueprints())  # public certs uploaded
    for bp in state.blueprints.values():  # only Entra's own grant, accepted by policy
        assert bp.principal_id is not None
        assert [a["appRoleId"] for a in t.assignments[bp.principal_id]] == [
            "role-AgentIdentity.CreateAsManager"
        ]
    agents = {a["displayName"]: a for a in t.agents()}
    assert agents["nhi-wf-claims-triage-agent-router"]["agentIdentityBlueprintId"] == (
        state.blueprints["agent-router"].app_id
    )


# ------------------------------------------------------------------ least privilege


@respx.mock
def test_undeclared_role_is_revoked(cert_dir: Path) -> None:
    t = tenant()
    state = TenantState()
    apply(state, cert_dir)
    principal = state.nhis[SUMMARIZER].principal_id
    assert principal is not None
    t.assignments[principal].append({
        "id": "sneaky", "resourceId": state.resources[RESOURCE.id].service_principal_id,
        "appRoleId": role_id(RESOURCE.id, "Records.Annotate"),
    })  # fmt: skip

    p = plan(state, cert_dir)
    assert kinds(p) == [("grant.revoke", SUMMARIZER)]
    assert p.steps[0].body["role"] == "Records.Annotate"
    apply(state, cert_dir)
    assert plan(state, cert_dir).steps == []
    assert all(a["id"] != "sneaky" for a in t.assignments[principal])


# ------------------------------------------------------------------ status lifecycle


@respx.mock
def test_suspend_disables_and_reactivate_enables(cert_dir: Path) -> None:
    t = tenant()
    state = TenantState()
    apply(state, cert_dir)

    suspended = with_workflow(REGISTRY, "wf-claims-triage", status=WorkflowStatus.SUSPENDED)
    p = plan(state, cert_dir, suspended)
    assert sorted(kinds(p)) == [("agent.disable", ROUTER), ("agent.disable", SUMMARIZER)]
    apply(state, cert_dir, suspended)
    claims = [a for a in t.agents() if a["displayName"].startswith("nhi-wf-claims-triage-")]
    assert len(claims) == 2 and all(a["accountEnabled"] is False for a in claims)
    assert plan(state, cert_dir, suspended).steps == []

    p = plan(state, cert_dir)  # back to active
    assert sorted(kinds(p)) == [("agent.enable", ROUTER), ("agent.enable", SUMMARIZER)]


@respx.mock
def test_requested_workflow_creates_nothing(cert_dir: Path) -> None:
    tenant()
    requested = with_workflow(REGISTRY, "wf-claims-triage", status=WorkflowStatus.REQUESTED)
    p = plan(TenantState(), cert_dir, requested)
    assert not any(k.startswith("wf-claims-triage/") for _, k in kinds(p))
    # agent-summarizer is only used by claims triage, so its blueprint isn't created
    assert not any(k.startswith("blueprint.") and key == "agent-summarizer" for k, key in kinds(p))


# ------------------------------------------------------------------ refusing to guess


@respx.mock
def test_lost_state_is_adopted_without_writes(cert_dir: Path) -> None:
    t = tenant()
    state = TenantState()
    apply(state, cert_dir)
    writes = len(t.writes)

    fresh = TenantState(resources=state.resources)  # blueprints/NHIs forgotten
    p = plan(fresh, cert_dir)
    assert {k for k, _ in kinds(p)} == {"blueprint.adopt", "agent.adopt", "spnhi.adopt"}
    apply(fresh, cert_dir)
    assert len(t.writes) == writes
    assert fresh.nhis == state.nhis and fresh.blueprints == state.blueprints


@respx.mock
def test_untagged_blueprint_with_our_name_is_not_adopted(cert_dir: Path) -> None:
    t = tenant()
    t.apps["x"] = {"id": "x", "appId": "y", "displayName": "bp-agent-router", "tags": [],
                   "@odata.type": "Microsoft.Graph.AgentIdentityBlueprint"}  # fmt: skip
    with pytest.raises(PlanError, match="isn't tagged"):
        plan(TenantState(), cert_dir)


@respx.mock
def test_agent_with_our_name_from_another_blueprint_is_not_adopted(cert_dir: Path) -> None:
    t = tenant()
    state = TenantState()
    apply(state, cert_dir)
    del state.nhis[ROUTER]
    agent = next(a for a in t.agents() if a["displayName"] == "nhi-wf-claims-triage-agent-router")
    agent["agentIdentityBlueprintId"] = "someone-elses-blueprint"
    with pytest.raises(PlanError, match="name match alone"):
        plan(state, cert_dir)


@respx.mock
def test_stale_state_refuses_instead_of_recreating(cert_dir: Path) -> None:
    tenant()
    state = TenantState()
    apply(state, cert_dir)
    state.nhis[ROUTER] = state.nhis[ROUTER].model_copy(update={"principal_id": "gone"})
    with pytest.raises(PlanError, match="won't recreate"):
        plan(state, cert_dir)


# ------------------------------------------------------------------ credentials


@respx.mock
def test_foreign_credential_is_reported_not_replaced(cert_dir: Path, tmp_path: Path) -> None:
    t = tenant()
    state = TenantState()
    apply(state, cert_dir)
    bp = t.apps[state.blueprints["agent-router"].application_object_id]
    bp["keyCredentials"] = [{"customKeyIdentifier": "c29tZW9uZSBlbHNl", "displayName": "?"}]
    p = plan(state, cert_dir)
    assert p.steps == []
    assert any("rotation is a Phase 6" in n for n in p.notes)


@respx.mock
def test_missing_local_cert_is_a_note_and_nothing_is_uploaded(tmp_path: Path) -> None:
    tenant()
    p = plan(TenantState(), tmp_path / "no-certs")
    assert not any(kind.endswith(".credential") for kind, _ in kinds(p))
    assert any("nhigov cert new bp-agent-router" in n for n in p.notes)
    demo_create = next(s for s in p.steps if s.kind == "spnhi.create")
    assert "keyCredentials" not in demo_create.body


def test_cert_longer_than_policy_is_flagged(tmp_path: Path) -> None:
    generate_self_signed("bp-agent-router", tmp_path, 400)
    from nhigov.backends.agent_id import credential_notes

    with _graph() as g:
        ctx = PlanContext(graph=g, registry=REGISTRY, state=TenantState(), today=TODAY,
                          cert_dir=tmp_path)  # fmt: skip
        body, notes = credential_notes(ctx, "bp-agent-router", [], "bp-agent-router")
    assert body is not None
    assert any("valid 400 days, over the 180-day policy" in n for n in notes)


@pytest.mark.parametrize("today", [date(2026, 11, 1), date(2027, 4, 29)])
def test_cert_at_exactly_the_policy_limit_is_not_flagged(tmp_path: Path, today: date) -> None:
    """Regression: the live run flagged 180-day certs when UTC was a day ahead."""
    generate_self_signed("bp-agent-router", tmp_path, 180)
    from nhigov.backends.agent_id import credential_notes

    with _graph() as g:
        ctx = PlanContext(graph=g, registry=REGISTRY, state=TenantState(), today=today,
                          cert_dir=tmp_path)  # fmt: skip
        _, notes = credential_notes(ctx, "bp-agent-router", [], "bp-agent-router")
    assert notes == []


# ------------------------------------------------------------------ control plane (report-only)


@respx.mock
def test_control_plane_drift_is_reported_never_planned(cert_dir: Path) -> None:
    t = tenant()
    t.assignments["scanner-sp"].append(
        {"id": "x", "resourceId": "graph-sp", "appRoleId": "role-Directory.ReadWrite.All"}
    )
    t.assignments["provisioner-sp"].pop()
    p = plan(TenantState(), cert_dir)
    notes = "\n".join(p.notes)
    assert "nhigov-scanner: holds undeclared Directory.ReadWrite.All" in notes
    assert "nhigov-provisioner: registry declares but tenant lacks" in notes
    assert not any(s.key.startswith("wf-control-plane") for s in p.steps)


# ------------------------------------------------------------------ registry


def test_unknown_backend_is_rejected(tmp_path: Path) -> None:
    import shutil

    reg = Path(shutil.copytree(Path(__file__).parents[2] / "registry", tmp_path / "registry"))
    demo = reg / "workflows" / "wf-sp-backend-demo.yaml"
    demo.write_text(
        demo.read_text(encoding="utf-8").replace("service_principal", "terraform"), "utf-8"
    )
    _, findings = load_registry(reg)
    assert any(f.rule == "REG-000" and "backend" in f.message for f in findings)


# ------------------------------------------------------------------ blueprint Graph grants


@respx.mock
def test_other_graph_grant_on_a_blueprint_is_revoked(cert_dir: Path) -> None:
    """Policy accepts Entra's system-managed grant; anything else on a blueprint goes."""
    t = tenant()
    state = TenantState()
    apply(state, cert_dir)
    principal = state.blueprints["agent-router"].principal_id
    assert principal is not None
    t.assignments[principal].append(
        {"id": "added", "resourceId": "graph-sp", "appRoleId": "role-Directory.ReadWrite.All"}
    )

    p = plan(state, cert_dir)
    assert kinds(p) == [("blueprint.revoke", "agent-router")]
    assert p.steps[0].body["role"] == "Directory.ReadWrite.All"
    apply(state, cert_dir)
    assert [a["id"] for a in t.assignments[principal]][-1] != "added"
    assert plan(state, cert_dir).steps == []


@respx.mock
def test_without_policy_acceptance_the_system_grant_would_be_planned(cert_dir: Path) -> None:
    """Why the policy lists it: an empty list plans a revoke Entra will refuse."""
    tenant()
    state = TenantState()
    apply(state, cert_dir)
    policy = REGISTRY.policy
    assert policy is not None
    strict = replace(REGISTRY, policy=policy.model_copy(update={"blueprint_graph_grants": []}))
    revokes = [s for s in plan(state, cert_dir, strict).steps if s.kind == "blueprint.revoke"]
    assert {s.body["role"] for s in revokes} == {"AgentIdentity.CreateAsManager"}
