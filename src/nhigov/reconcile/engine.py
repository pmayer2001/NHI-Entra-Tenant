"""Steps, plan context and the executor shared by both identity backends (ADR-006, ADR-010).

A plan is a list of `Step`s. A step names *what* to change by registry key
("agent-summarizer", "wf-claims-triage/agent-router"), not by object ID,
because objects created earlier in the same apply don't have IDs at plan time.
The executor looks IDs up in the state file when it runs each step, and saves
state after every step, so a failure half-way is resumable.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from nhigov.certs import DEFAULT_CERT_DIR
from nhigov.graph.client import GraphClient, GraphError
from nhigov.reconcile.state import BlueprintRecord, NhiRecord, TenantState
from nhigov.registry.loader import Registry

JsonDict = dict[str, Any]
GRAPH_USERS = "https://graph.microsoft.com/v1.0/users/"
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
# Just-created objects (and their owner links) replicate for a few seconds (ADR-002).
LAG_BACKOFF = (2.0, 4.0, 8.0, 16.0)
_LAG_MESSAGES = ("does not exist", "not found", "resourcenotfound")


class PlanError(Exception):
    """The tenant is in a state the reconciler won't guess its way out of."""


@dataclass(frozen=True)
class Step:
    kind: str  # "<object>.<op>", e.g. "blueprint.create", "grant.revoke"
    key: str  # registry key: agent ID for blueprints, "<workflow>/<agent>" for NHIs
    summary: str
    request: str  # for display; IDs not known yet appear as <placeholders>
    body: JsonDict = field(default_factory=dict)
    changes: tuple[str, ...] = ()

    @property
    def op(self) -> str:
        return self.kind.split(".", 1)[1]


@dataclass
class IdentityPlan:
    steps: list[Step] = field(default_factory=list)
    # Things plan noticed but won't act on (report-only), shown with the plan.
    notes: list[str] = field(default_factory=list)


@dataclass
class PlanContext:
    graph: GraphClient  # the scanner: plan can't write even if it wanted to
    registry: Registry
    state: TenantState
    today: date
    cert_dir: Path = DEFAULT_CERT_DIR
    _user_ids: dict[str, str] = field(default_factory=dict)
    _graph_sp: tuple[str, dict[str, str]] | None = None

    def user_id(self, upn: str) -> str:
        if upn not in self._user_ids:
            self._user_ids[upn] = self.graph.get(f"users/{upn}", params={"$select": "id"})["id"]
        return self._user_ids[upn]

    def graph_sp(self) -> tuple[str, dict[str, str]]:
        """Microsoft Graph's service principal ID and its app roles (role ID -> value)."""
        if self._graph_sp is None:
            sp = self.graph.get(
                "servicePrincipals",
                params={"$filter": f"appId eq '{GRAPH_APP_ID}'", "$select": "id,appRoles"},
            )["value"][0]
            self._graph_sp = (sp["id"], {r["id"]: r["value"] for r in sp.get("appRoles", [])})
        return self._graph_sp

    def sponsor_bind(self, upns: tuple[str, ...]) -> list[str]:
        return [f"{GRAPH_USERS}{self.user_id(u)}" for u in upns]

    def get_or_none(self, path: str, select: str, *, after_create: bool = False) -> JsonDict | None:
        response = self.graph.request(
            "GET", path, params={"$select": select}, retry_not_found=after_create, check=False
        )
        if response.status_code == 404:
            return None
        if response.is_error:
            raise GraphError.from_response(response)
        found: JsonDict = response.json()
        return found

    def find_by_name(self, collection: str, name: str, select: str) -> JsonDict | None:
        matches = self.graph.get(
            collection, params={"$filter": f"displayName eq '{name}'", "$select": select}
        ).get("value", [])
        if len(matches) > 1:
            raise PlanError(
                f"{len(matches)} objects are named {name} in {collection}; resolve by hand"
            )
        return matches[0] if matches else None

    def sponsors_note(self, path: str, expected_upns: tuple[str, ...], label: str) -> str | None:
        """Sponsors are set at create. The docs say reading them back needs
        AgentIdentity.ReadWrite.All, but the read-only scanner could read them on the
        live tenant; a 403 is still reported rather than fatal, in case that changes."""
        response = self.graph.request("GET", path, params={"$select": "id"}, check=False)
        if response.status_code in (401, 403):
            return f"{label}: sponsors not verifiable read-only ({response.status_code})"
        if response.is_error:
            return f"{label}: sponsors read failed ({response.status_code})"
        found = {o["id"] for o in response.json().get("value", [])}
        expected = {self.user_id(u) for u in expected_upns}
        if found != expected:
            return (
                f"{label}: sponsors differ from the registry "
                "(nhigov sets sponsors only when it creates an object)"
            )
        return None


# ------------------------------------------------------------------ executing


def send(
    graph: GraphClient,
    method: str,
    path: str,
    body: JsonDict | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> JsonDict:
    """One write that tolerates replication lag: a parent created seconds ago can
    show up as 403, 404, or a 400 saying it doesn't exist."""
    for delay in (*LAG_BACKOFF, None):
        response = graph.request(method, path, json=body, check=False)
        if response.is_success:
            return response.json() if response.content else {}
        lag = response.status_code in (403, 404) or (
            response.status_code == 400 and any(m in response.text.lower() for m in _LAG_MESSAGES)
        )
        if not lag or delay is None:
            raise GraphError.from_response(response)
        sleep(delay)
    raise AssertionError("unreachable")


Handler = Callable[[GraphClient, Step, TenantState, Callable[[float], None]], str]


def _agent_of(key: str) -> str:
    return key.split("/", 1)[1]


def _nhi(state: TenantState, key: str) -> NhiRecord:
    if key not in state.nhis:
        raise PlanError(f"{key} isn't in state; its create step must run first")
    return state.nhis[key]


def _blueprint(state: TenantState, agent_id: str) -> BlueprintRecord:
    if agent_id not in state.blueprints:
        raise PlanError(f"blueprint for {agent_id} isn't in state; its create step must run first")
    return state.blueprints[agent_id]


def _bp_path(rec: BlueprintRecord) -> str:
    return f"applications/{rec.application_object_id}/microsoft.graph.agentIdentityBlueprint"


def _agent_path(rec: NhiRecord) -> str:
    return f"servicePrincipals/{rec.principal_id}/microsoft.graph.agentIdentity"


def _blueprint_create(g: GraphClient, s: Step, st: TenantState, sl: Any) -> str:
    bp = g.post("applications", s.body)
    st.blueprints[s.key] = BlueprintRecord(application_object_id=bp["id"], app_id=bp["appId"])
    return f"created blueprint bp-{s.key}"


def _blueprint_principal(g: GraphClient, s: Step, st: TenantState, sl: Any) -> str:
    rec = _blueprint(st, s.key)
    sp = send(
        g,
        "POST",
        "servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal",
        {"appId": rec.app_id},
        sl,
    )
    st.blueprints[s.key] = rec.model_copy(update={"principal_id": sp["id"]})
    return f"created blueprint principal for bp-{s.key}"


def _blueprint_grant_revoke(g: GraphClient, s: Step, st: TenantState, sl: Any) -> str:
    principal = _blueprint(st, s.key).principal_id
    g.delete(f"servicePrincipals/{principal}/appRoleAssignments/{s.body['assignmentId']}")
    return f"revoked {s.body['role']} from the principal of bp-{s.key}"


def _blueprint_credential(g: GraphClient, s: Step, st: TenantState, sl: Any) -> str:
    send(g, "PATCH", _bp_path(_blueprint(st, s.key)), s.body, sl)
    return f"uploaded certificate (public key only) to bp-{s.key}"


def _agent_create(g: GraphClient, s: Step, st: TenantState, sl: Any) -> str:
    bp = _blueprint(st, _agent_of(s.key))
    body = {**s.body, "agentIdentityBlueprintId": bp.app_id}
    agent = send(g, "POST", "servicePrincipals/microsoft.graph.agentIdentity", body, sl)
    st.nhis[s.key] = NhiRecord(
        backend="agent_id",
        principal_id=agent["id"],
        app_id=agent["appId"],
        blueprint=_agent_of(s.key),
        created_at=datetime.now(UTC),
    )
    return f"created agent identity {s.body['displayName']}"


def _agent_set_enabled(g: GraphClient, s: Step, st: TenantState, sl: Any) -> str:
    send(g, "PATCH", _agent_path(_nhi(st, s.key)), s.body, sl)
    return f"{s.op}d agent identity for {s.key}"


def _spnhi_create(g: GraphClient, s: Step, st: TenantState, sl: Any) -> str:
    app = g.post("applications", s.body)
    st.nhis[s.key] = NhiRecord(
        backend="service_principal",
        app_id=app["appId"],
        application_object_id=app["id"],
        created_at=datetime.now(UTC),
    )
    return f"created app registration {s.body['displayName']}"


def _spnhi_principal(g: GraphClient, s: Step, st: TenantState, sl: Any) -> str:
    rec = _nhi(st, s.key)
    sp = send(g, "POST", "servicePrincipals", {**s.body, "appId": rec.app_id}, sl)
    st.nhis[s.key] = rec.model_copy(update={"principal_id": sp["id"]})
    return f"created service principal for {s.key}"


def _spnhi_patch_app(g: GraphClient, s: Step, st: TenantState, sl: Any) -> str:
    send(g, "PATCH", f"applications/{_nhi(st, s.key).application_object_id}", s.body, sl)
    return f"updated app registration for {s.key}: {', '.join(s.changes) or s.op}"


def _spnhi_set_enabled(g: GraphClient, s: Step, st: TenantState, sl: Any) -> str:
    send(g, "PATCH", f"servicePrincipals/{_nhi(st, s.key).principal_id}", s.body, sl)
    return f"{s.op}d service principal for {s.key}"


def _adopt(g: GraphClient, s: Step, st: TenantState, sl: Any) -> str:
    if s.kind == "blueprint.adopt":
        st.blueprints[s.key] = BlueprintRecord.model_validate(s.body)
    else:
        old = st.nhis.get(s.key)  # a refresh keeps when apply created it
        st.nhis[s.key] = NhiRecord.model_validate(s.body).model_copy(
            update={"created_at": old.created_at if old else None}
        )
    return f"recorded existing objects for {s.key} in state"


def _grant(g: GraphClient, s: Step, st: TenantState, sl: Any) -> str:
    principal = _nhi(st, s.key).principal_id
    resource = st.resources.get(s.body["resource"])
    if principal is None or resource is None or resource.service_principal_id is None:
        raise PlanError(f"can't grant {s.body['role']} to {s.key}: principal or resource missing")
    send(
        g,
        "POST",
        f"servicePrincipals/{principal}/appRoleAssignments",
        {
            "principalId": principal,
            "resourceId": resource.service_principal_id,
            "appRoleId": s.body["appRoleId"],
        },
        sl,
    )
    return f"granted {s.body['role']} to {s.key}"


def _revoke(g: GraphClient, s: Step, st: TenantState, sl: Any) -> str:
    principal = _nhi(st, s.key).principal_id
    g.delete(f"servicePrincipals/{principal}/appRoleAssignments/{s.body['assignmentId']}")
    return f"revoked {s.body['role']} from {s.key}"


HANDLERS: dict[str, Handler] = {
    "blueprint.create": _blueprint_create,
    "blueprint.principal": _blueprint_principal,
    "blueprint.credential": _blueprint_credential,
    "blueprint.adopt": _adopt,
    "blueprint.revoke": _blueprint_grant_revoke,
    "agent.create": _agent_create,
    "agent.enable": _agent_set_enabled,
    "agent.disable": _agent_set_enabled,
    "agent.adopt": _adopt,
    "spnhi.create": _spnhi_create,
    "spnhi.principal": _spnhi_principal,
    "spnhi.update": _spnhi_patch_app,
    "spnhi.credential": _spnhi_patch_app,
    "spnhi.enable": _spnhi_set_enabled,
    "spnhi.disable": _spnhi_set_enabled,
    "spnhi.adopt": _adopt,
    "grant.add": _grant,
    "grant.revoke": _revoke,
}


def apply_steps(
    graph: GraphClient,
    steps: list[Step],
    state: TenantState,
    save: Callable[[TenantState], None],
    sleep: Callable[[float], None] = time.sleep,
) -> list[str]:
    log = []
    for step in steps:
        log.append(HANDLERS[step.kind](graph, step, state, sleep))
        save(state)
    return log
