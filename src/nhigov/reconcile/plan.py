"""Plan and apply for resource APIs (Phase 2 slice of the reconciler, ADR-006).

`plan_resource` only reads (run it as the scanner). `apply_plan` executes the
actions (run it as the provisioner). Applying a plan, then planning again,
must produce no actions.

Safety rules built in:
* If the state file names an object the tenant doesn't return, stop. Never
  "fix" it by creating a duplicate; it may have been deleted, or be replicating.
* An app with our name but without the `nhigov:managed` tag is never adopted.
* App roles are removed in two applies: first disabled (Entra refuses to delete
  an enabled role), then dropped. Disabling first is reversible.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from nhigov.graph.client import GraphClient, GraphError
from nhigov.reconcile.resources import desired_application, desired_service_principal
from nhigov.reconcile.state import ResourceRecord, TenantState
from nhigov.registry.models import Resource

APP_SELECT = "id,appId,displayName,identifierUris,signInAudience,tags,api,appRoles,optionalClaims"
SP_SELECT = "id,appId,appRoleAssignmentRequired,tags"
APP_ID_PLACEHOLDER = "<appId from create>"
# A just-created app (or its owner link) may not have replicated yet (Phase 0 finding).
LAG_BACKOFF = (2.0, 4.0, 8.0, 16.0)

JsonDict = dict[str, Any]


class PlanError(Exception):
    """The tenant is in a state the reconciler won't guess its way out of."""


@dataclass(frozen=True)
class Action:
    op: Literal["create", "update"]
    target: Literal["application", "servicePrincipal"]
    method: str
    path: str
    body: JsonDict
    changes: tuple[str, ...] = ()


@dataclass
class ResourcePlan:
    resource_id: str
    actions: list[Action] = field(default_factory=list)
    # Set when the objects already exist; apply records them in the state file.
    record: ResourceRecord | None = None

    @property
    def is_noop(self) -> bool:
        return not self.actions and self.record is None


# ------------------------------------------------------------------ reading


def _find_application(
    graph: GraphClient, resource: Resource, record: ResourceRecord | None
) -> JsonDict | None:
    if record is not None:
        response = graph.request(
            "GET",
            f"applications/{record.application_object_id}",
            params={"$select": APP_SELECT},
            retry_not_found=True,
            check=False,
        )
        if response.status_code == 404:
            raise PlanError(
                f"state says {resource.id} is application {record.application_object_id}, but "
                "the tenant doesn't return it. Check Entra (deleted? soft-deleted?) before "
                "editing state/tenant-state.json; plan won't create a duplicate."
            )
        if response.is_error:
            raise GraphError.from_response(response)
        found: JsonDict = response.json()
        return found

    matches = graph.get(
        "applications",
        params={"$filter": f"displayName eq '{resource.id}'", "$select": APP_SELECT},
    ).get("value", [])
    if len(matches) > 1:
        raise PlanError(f"{len(matches)} applications are named {resource.id}; resolve by hand")
    if not matches:
        return None
    app: JsonDict = matches[0]
    if "nhigov:managed" not in app.get("tags", []):
        raise PlanError(
            f"an application named {resource.id} exists but isn't tagged nhigov:managed; "
            "refusing to adopt something nhigov didn't create"
        )
    return app


def _find_service_principal(graph: GraphClient, app_id: str) -> JsonDict | None:
    matches = graph.get(
        "servicePrincipals",
        params={"$filter": f"appId eq '{app_id}'", "$select": SP_SELECT},
    ).get("value", [])
    return matches[0] if matches else None


# ------------------------------------------------------------------ diffing (pure)

_ROLE_FIELDS = ("id", "value", "displayName", "description", "allowedMemberTypes", "isEnabled")


def _role(r: JsonDict) -> JsonDict:
    return {k: r.get(k) for k in _ROLE_FIELDS}


def _role_key(r: JsonDict) -> tuple[Any, ...]:
    return tuple(
        tuple(sorted(r.get(k) or [])) if k == "allowedMemberTypes" else r.get(k)
        for k in _ROLE_FIELDS
    )


def merge_app_roles(desired: list[JsonDict], current: list[JsonDict]) -> list[JsonDict]:
    """Desired roles, plus roles to retire: enabled extras are disabled, disabled ones dropped."""
    wanted = {r["id"] for r in desired}
    retiring = [
        {**_role(r), "isEnabled": False}
        for r in current
        if r["id"] not in wanted and r.get("isEnabled", True)
    ]
    return [*desired, *retiring]


def _describe_roles(merged: list[JsonDict], current: list[JsonDict]) -> list[str]:
    before = {r["id"]: r for r in current}
    after = {r["id"]: r for r in merged}
    notes = []
    for rid, r in after.items():
        if rid not in before:
            notes.append(f"add role {r['value']}")
        elif _role_key(r) != _role_key(before[rid]):
            verb = "disable" if before[rid].get("isEnabled") and not r["isEnabled"] else "update"
            notes.append(f"{verb} role {r['value']}")
    notes += [f"remove disabled role {before[rid]['value']}" for rid in before if rid not in after]
    return notes


def _claim_names(app: JsonDict) -> list[str]:
    claims = (app.get("optionalClaims") or {}).get("accessToken") or []
    return sorted(c["name"] for c in claims)


def diff_application(desired: JsonDict, current: JsonDict) -> tuple[JsonDict, list[str]]:
    """The PATCH body that turns `current` into `desired`, and what it changes."""
    patch: JsonDict = {}
    changes: list[str] = []
    for key in ("identifierUris", "tags"):
        if sorted(current.get(key) or []) != sorted(desired[key]):
            patch[key] = desired[key]
            changes.append(f"{key}: {current.get(key)} -> {desired[key]}")
    if current.get("signInAudience") != desired["signInAudience"]:
        patch["signInAudience"] = desired["signInAudience"]
        changes.append(f"signInAudience -> {desired['signInAudience']}")

    current_api = current.get("api") or {}
    if any(current_api.get(k) != v for k, v in desired["api"].items()):
        # `api` is a complex property: PATCH replaces it whole, so keep its other fields.
        patch["api"] = {**current_api, **desired["api"]}
        changes.append(f"api: {desired['api']}")

    current_roles = current.get("appRoles") or []
    merged = merge_app_roles(desired["appRoles"], current_roles)
    if sorted(map(_role_key, merged), key=str) != sorted(map(_role_key, current_roles), key=str):
        patch["appRoles"] = merged
        changes += _describe_roles(merged, current_roles)

    if _claim_names(current) != _claim_names(desired):
        patch["optionalClaims"] = desired["optionalClaims"]
        changes.append(f"access token optional claims -> {_claim_names(desired)}")
    return patch, changes


def plan_resource(graph: GraphClient, resource: Resource, state: TenantState) -> ResourcePlan:
    desired = desired_application(resource)
    record = state.resources.get(resource.id)
    app = _find_application(graph, resource, record)
    plan = ResourcePlan(resource.id)

    if app is None:
        plan.actions += [
            Action("create", "application", "POST", "applications", desired),
            Action(
                "create", "servicePrincipal", "POST", "servicePrincipals",
                desired_service_principal(APP_ID_PLACEHOLDER, resource.id),
            ),
        ]  # fmt: skip
        return plan

    patch, changes = diff_application(desired, app)
    if patch:
        plan.actions.append(
            Action("update", "application", "PATCH", f"applications/{app['id']}", patch,
                   tuple(changes))
        )  # fmt: skip

    sp = _find_service_principal(graph, app["appId"])
    desired_sp = desired_service_principal(app["appId"], resource.id)
    if sp is None:
        plan.actions.append(
            Action("create", "servicePrincipal", "POST", "servicePrincipals", desired_sp)
        )
    else:
        sp_patch: JsonDict = {}
        if sp.get("appRoleAssignmentRequired") is not True:
            sp_patch["appRoleAssignmentRequired"] = True
        current_tags = sp.get("tags") or []
        missing = [t for t in desired_sp["tags"] if t not in current_tags]
        if missing:
            # Add ours; keep tags Entra or an admin put there (they aren't drift).
            sp_patch["tags"] = [*current_tags, *missing]
        if sp_patch:
            plan.actions.append(
                Action("update", "servicePrincipal", "PATCH", f"servicePrincipals/{sp['id']}",
                       sp_patch, tuple(sorted(sp_patch)))
            )  # fmt: skip

    found = ResourceRecord(
        application_object_id=app["id"],
        app_id=app["appId"],
        service_principal_id=sp["id"] if sp else None,
    )
    if found != record:
        plan.record = found  # adopt / refresh state even if nothing else changes
    return plan


# ------------------------------------------------------------------ applying


def _post_with_lag_retry(
    graph: GraphClient, path: str, body: JsonDict, sleep: Callable[[float], None]
) -> JsonDict:
    """POST that tolerates the 403/404 a just-created parent object can cause."""
    for delay in (*LAG_BACKOFF, None):
        response = graph.request("POST", path, json=body, check=False)
        if response.is_success:
            result: JsonDict = response.json()
            return result
        if response.status_code not in (403, 404) or delay is None:
            raise GraphError.from_response(response)
        sleep(delay)
    raise AssertionError("unreachable")


def apply_plan(
    graph: GraphClient,
    plan: ResourcePlan,
    state: TenantState,
    save: Callable[[TenantState], None],
    sleep: Callable[[float], None] = time.sleep,
) -> list[str]:
    """Execute the actions in order. State is saved after every create, so a failure
    half-way leaves a record the next plan resumes from instead of duplicating."""
    log: list[str] = []
    record = plan.record or state.resources.get(plan.resource_id)
    if plan.record is not None:
        state.resources[plan.resource_id] = plan.record
        save(state)
        log.append(f"recorded existing objects for {plan.resource_id} in state")

    for action in plan.actions:
        if action.op == "create" and action.target == "application":
            app = graph.post(action.path, action.body)
            record = ResourceRecord(application_object_id=app["id"], app_id=app["appId"])
            state.resources[plan.resource_id] = record
            save(state)
            log.append(f"created application {plan.resource_id} (appId {app['appId']})")
        elif action.op == "create":
            if record is None:
                raise PlanError("service principal planned before its application exists")
            body = {**action.body, "appId": record.app_id}
            sp = _post_with_lag_retry(graph, action.path, body, sleep)
            record = record.model_copy(update={"service_principal_id": sp["id"]})
            state.resources[plan.resource_id] = record
            save(state)
            log.append(f"created service principal for {plan.resource_id}")
        else:
            graph.patch(action.path, action.body)
            log.append(f"updated {action.target} {plan.resource_id}: {', '.join(action.changes)}")
    return log
