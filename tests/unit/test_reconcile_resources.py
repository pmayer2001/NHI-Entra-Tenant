"""Resource plan/apply against an in-memory fake tenant.

The Phase 3 acceptance test in miniature: apply, then plan again -> no changes.
The fake returns objects the way Graph does (extra fields, defaults filled in),
so a diff that compares naively would never converge.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import respx
from fake_tenant import FakeTenant

from nhigov.cli import _set_api_audience
from nhigov.graph.client import GraphClient
from nhigov.reconcile.engine import PlanError
from nhigov.reconcile.plan import apply_plan, plan_resource
from nhigov.reconcile.resources import desired_application
from nhigov.reconcile.state import ResourceRecord, TenantState, load_state, save_state
from nhigov.registry.loader import load_registry

REGISTRY, _ = load_registry(Path(__file__).parents[2] / "registry")
RESOURCE = REGISTRY.resources["res-sensitive-records"]


def _graph() -> GraphClient:
    return GraphClient(lambda: "t", sleep=lambda _: None)


def _plan_and_apply(state: TenantState) -> list[str]:
    with _graph() as g:
        plan = plan_resource(g, RESOURCE, state)
        return apply_plan(g, plan, state, save=lambda s: None, sleep=lambda _: None)


@respx.mock
def test_empty_tenant_plans_app_then_sp() -> None:
    FakeTenant().install()
    with _graph() as g:
        plan = plan_resource(g, RESOURCE, TenantState())
    assert [(a.op, a.target) for a in plan.actions] == [
        ("create", "application"),
        ("create", "servicePrincipal"),
    ]


@respx.mock
def test_apply_then_plan_again_is_a_noop() -> None:
    tenant = FakeTenant(sp_lag_failures=2)  # SP create hits replication lag twice
    tenant.install()
    state = TenantState()
    log = _plan_and_apply(state)
    assert tenant.writes == ["POST applications", "POST servicePrincipals"]
    assert len(log) == 2

    record = state.resources[RESOURCE.id]
    sp = next(iter(tenant.sps.values()))
    assert sp["appRoleAssignmentRequired"] is True
    assert record.service_principal_id == sp["id"]

    with _graph() as g:
        assert plan_resource(g, RESOURCE, state).is_noop
    assert len(tenant.writes) == 2


@respx.mock
def test_existing_tagged_app_is_adopted_into_state_without_writes() -> None:
    tenant = FakeTenant()
    tenant.install()
    _plan_and_apply(TenantState())  # created, but state lost
    writes = len(tenant.writes)

    fresh = TenantState()
    with _graph() as g:
        plan = plan_resource(g, RESOURCE, fresh)
    assert plan.actions == [] and plan.record is not None
    _plan_and_apply(fresh)
    assert len(tenant.writes) == writes
    assert fresh.resources[RESOURCE.id].service_principal_id is not None


@respx.mock
def test_untagged_app_with_our_name_is_never_adopted() -> None:
    tenant = FakeTenant()
    tenant.install()
    tenant.apps["x"] = {"id": "x", "appId": "y", "displayName": RESOURCE.id, "tags": []}
    with _graph() as g, pytest.raises(PlanError, match="isn't tagged"):
        plan_resource(g, RESOURCE, TenantState())


@respx.mock
def test_stale_state_refuses_instead_of_duplicating() -> None:
    FakeTenant().install()
    state = TenantState(
        resources={RESOURCE.id: ResourceRecord(application_object_id="gone", app_id="gone")}
    )
    with _graph() as g, pytest.raises(PlanError, match="won't create a duplicate"):
        plan_resource(g, RESOURCE, state)


@respx.mock
def test_drift_is_patched_and_keeps_other_api_fields() -> None:
    tenant = FakeTenant()
    tenant.install()
    state = TenantState()
    _plan_and_apply(state)
    app = tenant.apps[state.resources[RESOURCE.id].application_object_id]
    app["api"]["requestedAccessTokenVersion"] = 1  # someone changed it in the portal
    app["api"]["knownClientApplications"] = ["keep-me"]
    app["optionalClaims"]["accessToken"] = []

    with _graph() as g:
        plan = plan_resource(g, RESOURCE, state)
    (action,) = plan.actions
    assert action.body["api"]["knownClientApplications"] == ["keep-me"]
    assert set(action.body) == {"api", "optionalClaims"}
    _plan_and_apply(state)
    with _graph() as g:
        assert plan_resource(g, RESOURCE, state).is_noop


@respx.mock
def test_removed_role_is_disabled_then_deleted_over_two_applies() -> None:
    tenant = FakeTenant()
    tenant.install()
    state = TenantState()
    _plan_and_apply(state)
    app = tenant.apps[state.resources[RESOURCE.id].application_object_id]
    extra = {**desired_application(RESOURCE)["appRoles"][0], "id": "old-role", "value": "Old.Role"}
    app["appRoles"].append(extra)

    with _graph() as g:
        first = plan_resource(g, RESOURCE, state)
    assert first.actions[0].changes == ("disable role Old.Role",)
    _plan_and_apply(state)

    with _graph() as g:
        second = plan_resource(g, RESOURCE, state)
    assert second.actions[0].changes == ("remove disabled role Old.Role",)
    _plan_and_apply(state)  # would 400 in the fake if the role were still enabled

    with _graph() as g:
        assert plan_resource(g, RESOURCE, state).is_noop


def test_state_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "state" / "tenant-state.json"
    state = TenantState(resources={"r": ResourceRecord(application_object_id="a", app_id="b")})
    save_state(state, path)
    assert load_state(path) == state
    assert load_state(tmp_path / "missing.json") == TenantState()


def test_api_audience_is_appended_once_keeping_comments(tmp_path: Path) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text("# keep this comment\ntenant_id: x\n", encoding="utf-8")
    assert _set_api_audience(cfg, "app-guid") is True
    assert _set_api_audience(cfg, "other") is False
    text = cfg.read_text(encoding="utf-8")
    assert "# keep this comment" in text and 'audience: "app-guid"' in text


@respx.mock
def test_missing_sp_tag_is_added_keeping_entra_tags() -> None:
    tenant = FakeTenant()
    tenant.install()
    state = TenantState()
    _plan_and_apply(state)
    sp = next(iter(tenant.sps.values()))
    sp["tags"] = ["WindowsAzureActiveDirectoryIntegratedApp"]  # ours removed by hand

    with _graph() as g:
        (action,) = plan_resource(g, RESOURCE, state).actions
    assert action.body["tags"][0] == "WindowsAzureActiveDirectoryIntegratedApp"
    assert {"nhigov:managed", f"nhigov:resource={RESOURCE.id}"} <= set(action.body["tags"])
