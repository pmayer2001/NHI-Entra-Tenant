"""Lifecycle engine, executor, policy merge, rotation and the proof token.

Time is a parameter (`today`), so 14-day grace periods are tested in milliseconds.
"""

from __future__ import annotations

import base64
import json
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import respx

from nhigov.agent_auth import TOKEN_URL, proof_of_possession
from nhigov.certs import generate_self_signed, load_local_cert
from nhigov.discovery.inventory import Inventory, Nhi, Person
from nhigov.graph.client import GraphClient
from nhigov.lifecycle.engine import LifecyclePlan, evaluate
from nhigov.lifecycle.policy import desired_policy
from nhigov.lifecycle.rotate import AddKeyWriter, PatchWriter, resolve, rotate
from nhigov.lifecycle.run import execute
from nhigov.lifecycle.state import LifecycleRecord, LifecycleState
from nhigov.reconcile.desired import build_desired
from nhigov.reconcile.engine import PlanError
from nhigov.reconcile.state import BlueprintRecord, NhiRecord, TenantState
from nhigov.registry.loader import Registry, load_registry
from nhigov.registry.models import Backend, WorkflowStatus

_REAL, _ = load_registry(Path(__file__).parents[2] / "registry")
KEY = "wf-lifecycle-test/agent-router"
# The fixture workflow is pinned active here, whatever its status in the real registry.
REGISTRY = replace(
    _REAL,
    workflows={
        **_REAL.workflows,
        "wf-lifecycle-test": _REAL.workflows["wf-lifecycle-test"].model_copy(
            update={"status": WorkflowStatus.ACTIVE}
        ),
    },
)
NAME = "nhi-wf-lifecycle-test-agent-router"
DEPARTING = "test-departing-sponsor@tenant.example"
DAY0 = date(2026, 11, 2)
G = "https://graph.microsoft.com/v1.0/"


def tenant() -> TenantState:
    nhis = {
        k: NhiRecord(backend="agent_id", principal_id=f"p-{k}", app_id=f"p-{k}",
                     blueprint=k.split("/")[1])
        for k in ("wf-claims-triage/agent-summarizer", "wf-claims-triage/agent-router", KEY)
    }  # fmt: skip
    nhis["wf-sp-backend-demo/agent-router"] = NhiRecord(
        backend="service_principal", principal_id="p-demo", app_id="demo-app",
        application_object_id="demo-obj",
    )  # fmt: skip
    return TenantState(nhis=nhis)


def inventory(t: TenantState, *, departing_enabled: bool = True,
              enabled: dict[str, bool] | None = None) -> Inventory:  # fmt: skip
    people = {}
    for upn, ok in (("owner@tenant.example", True), (DEPARTING, departing_enabled)):
        person = Person(id=upn, upn=upn, enabled=ok, member=True)
        people[upn] = person
    nhis = [
        Nhi(id=rec.principal_id or "?", kind="agent_identity", display_name=k,
            classification="managed", enabled=(enabled or {}).get(k, True))
        for k, rec in t.nhis.items()
    ]  # fmt: skip
    return Inventory(collected_at=datetime(2026, 11, 2, tzinfo=UTC), nhis=nhis, people=people)


def run(t: TenantState, lc: LifecycleState, today: date, registry: Registry = REGISTRY,
        **inv: object) -> LifecyclePlan:  # fmt: skip
    return evaluate(registry, inventory(t, **inv), t, lc, today)  # type: ignore[arg-type]


def kinds(plan: LifecyclePlan, key: str = KEY) -> list[str]:
    return [a.kind for a in plan.actions if a.key == key]


def row(plan: LifecyclePlan, key: str = KEY) -> str:
    return next(r.state for r in plan.rows if r.key == key)


# ------------------------------------------------------------------ departing sponsor (acceptance)


def test_departing_sponsor_is_disabled_after_the_grace_period() -> None:
    t = tenant()
    first = run(t, LifecycleState(), DAY0, departing_enabled=False)
    assert kinds(first) == []  # grace period starts; nothing disabled yet
    assert first.state.nhis[KEY].conditions["sponsor"] == DAY0
    assert "disable on 2026-11-16" in next(r.next_step for r in first.rows if r.key == KEY)

    day13 = run(t, first.state, DAY0 + timedelta(days=13), departing_enabled=False)
    assert kinds(day13) == []
    day14 = run(t, day13.state, DAY0 + timedelta(days=14), departing_enabled=False)
    assert kinds(day14) == ["disable"]
    assert "test-departing-sponsor" in day14.actions[0].reason
    assert all(kinds(day14, k) == [] for k in t.nhis if k != KEY)  # the owner's NHIs untouched


@respx.mock
def test_disable_holds_the_nhi_so_apply_keeps_it_off(tmp_path: Path) -> None:
    t = tenant()
    plan = run(t, LifecycleState(), DAY0, departing_enabled=False)
    plan = run(t, plan.state, DAY0 + timedelta(days=14), departing_enabled=False)
    patched = respx.patch(f"{G}servicePrincipals/p-{KEY}/microsoft.graph.agentIdentity").respond(
        204
    )
    with GraphClient(lambda: "t", sleep=lambda _: None) as g:
        execute(g, plan, t, DAY0, lambda *_: None, tmp_path)
    assert json.loads(patched.calls[0].request.content) == {"accountEnabled": False}
    holds = plan.state.holds()
    assert KEY in holds
    desired = build_desired(REGISTRY, Backend.AGENT_ID, holds)
    assert desired.nhis[KEY].should_be_enabled is False  # reconciler won't re-enable it
    assert desired.nhis["wf-claims-triage/agent-router"].should_be_enabled is True


def test_new_sponsor_releases_the_hold() -> None:
    t = tenant()
    lc = LifecycleState(
        nhis={KEY: LifecycleRecord(hold="sponsor left", conditions={"sponsor": DAY0})}
    )
    plan = run(t, lc, DAY0 + timedelta(days=20), departing_enabled=True, enabled={KEY: False})
    assert kinds(plan) == ["release"]
    assert "sponsor" not in plan.state.nhis[KEY].conditions


def test_retirement_supersedes_a_hold() -> None:
    # A held NHI whose workflow is then retired is never offered a release (which would
    # suggest re-enabling it); it goes straight down the retirement path.
    t = tenant()
    lc = LifecycleState(
        nhis={KEY: LifecycleRecord(hold="sponsor left", conditions={"sponsor": DAY0},
                                   disabled_on=DAY0)}
    )  # fmt: skip
    wf = REGISTRY.workflows["wf-lifecycle-test"]
    retired = replace(
        REGISTRY,
        workflows={**REGISTRY.workflows,
                   wf.id: wf.model_copy(update={"status": WorkflowStatus.RETIRED})},
    )  # fmt: skip
    plan = run(t, lc, DAY0 + timedelta(days=3), retired, departing_enabled=True,
               enabled={KEY: False})  # fmt: skip
    assert kinds(plan) == []
    assert row(plan) == "disabled"
    assert kinds(run(t, lc, DAY0 + timedelta(days=14), retired, enabled={KEY: False})) == ["delete"]


# ------------------------------------------------------------------ expiry, notices, retirement


def test_expired_workflow_is_disabled_immediately() -> None:
    plan = run(tenant(), LifecycleState(), date(2027, 2, 1))  # lifecycle test expires 2027-01-31
    assert kinds(plan) == ["disable"]
    (action,) = [a for a in plan.actions if a.key == KEY]
    assert "expired on 2027-01-31" in action.reason


@respx.mock
def test_review_notice_is_sent_once(tmp_path: Path) -> None:
    t = tenant()
    today = date(2026, 12, 20)  # review_by 2026-12-31 for wf-lifecycle-test, within 14 days
    plan = run(t, LifecycleState(), today)
    assert "notice" in kinds(plan)
    with GraphClient(lambda: "t", sleep=lambda _: None) as g:
        execute(g, plan, t, today, lambda *_: None, tmp_path)
    assert "wf-lifecycle-test review due 2026-12-31" in (
        tmp_path / f"notices-{today}.md"
    ).read_text(encoding="utf-8")
    assert "notice" not in kinds(run(t, plan.state, today + timedelta(days=1)))


@respx.mock
def test_retired_workflow_is_soft_deleted_after_grace_then_purged(tmp_path: Path) -> None:
    wfs = dict(REGISTRY.workflows)
    wfs["wf-lifecycle-test"] = wfs["wf-lifecycle-test"].model_copy(
        update={"status": WorkflowStatus.RETIRED}
    )
    retired = replace(REGISTRY, workflows=wfs)
    t = tenant()
    first = run(t, LifecycleState(), DAY0, retired, enabled={KEY: False})  # apply disabled it
    assert kinds(first) == []
    assert row(first) == "disabled"

    due = run(t, first.state, DAY0 + timedelta(days=14), retired, enabled={KEY: False})
    assert kinds(due) == ["delete"]
    deleted = respx.delete(f"{G}servicePrincipals/p-{KEY}").respond(204)
    with GraphClient(lambda: "t", sleep=lambda _: None) as g:
        execute(g, due, t, DAY0 + timedelta(days=14), lambda *_: None, tmp_path)
    assert deleted.called and KEY not in t.nhis  # state forgets it; apply won't recreate it

    later = run(t, due.state, DAY0 + timedelta(days=20), retired)
    assert row(later) == "soft-deleted"
    assert row(run(t, due.state, DAY0 + timedelta(days=45), retired)) == "purged"


@respx.mock
def test_service_principal_backend_uses_its_own_endpoints(tmp_path: Path) -> None:
    from nhigov.lifecycle.engine import Action

    t = tenant()
    plan = LifecyclePlan(
        actions=[Action("disable", "wf-sp-backend-demo/agent-router", "demo", "expired"),
                 Action("delete", "wf-sp-backend-demo/agent-router", "demo", "retired")],
    )  # fmt: skip
    off = respx.patch(f"{G}servicePrincipals/p-demo").respond(204)
    gone = respx.delete(f"{G}applications/demo-obj").respond(204)
    with GraphClient(lambda: "t", sleep=lambda _: None) as g:
        execute(g, plan, t, DAY0, lambda *_: None, tmp_path)
    assert off.called and gone.called


# ------------------------------------------------------------------ app management policy


def test_policy_merge_keeps_existing_restrictions_and_is_idempotent() -> None:
    uri_rule = {"uriAdditionWithoutUniqueTenantIdentifier": {"state": "enabled"}}
    as_read = {
        "uriAdditionWithoutUniqueTenantIdentifier": {
            "state": "enabled",
            "isStateSetByMicrosoft": True,
        }
    }  # fmt: skip  (read-only: not sent back)
    current = {"isEnabled": True, "applicationRestrictions": {"identifierUris": as_read,
               "passwordCredentials": [{"restrictionType": "passwordLifetime", "state": "enabled",
                                        "maxLifetime": "P90D"}]}}  # fmt: skip
    body, changes = desired_policy(current, 180)
    apps = body["applicationRestrictions"]
    assert apps["identifierUris"] == uri_rule  # Microsoft's rule survives
    types = {p["restrictionType"] for p in apps["passwordCredentials"]}
    assert types == {"passwordLifetime", "passwordAddition", "symmetricKeyAddition"}
    assert apps["keyCredentials"][0]["maxLifetime"] == "P180D"
    assert "servicePrincipalRestrictions" in body and len(changes) == 6

    after = {**current, **body}
    assert desired_policy(after, 180) == ({}, [])


# ------------------------------------------------------------------ rotation


def _b64_json(part: str) -> dict[str, object]:
    data: dict[str, object] = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    return data


def test_proof_of_possession_has_the_documented_shape(tmp_path: Path) -> None:
    cert = generate_self_signed("pop", tmp_path, 1)
    token = proof_of_possession(cert.private_pem, "app-object-id")
    head, body, _ = token.split(".")
    assert "=" not in token
    claims = _b64_json(body)
    assert claims["aud"] == "00000002-0000-0000-c000-000000000000"
    assert claims["iss"] == "app-object-id"
    assert int(str(claims["exp"])) - int(str(claims["nbf"])) == 600
    assert "x5t" in _b64_json(head)


def test_new_certificates_fit_the_policy_cap_exactly(tmp_path: Path) -> None:
    generate_self_signed("cap", tmp_path, 180)
    cert = load_local_cert("cap", tmp_path)
    assert cert is not None and cert.not_after - cert.not_before == timedelta(days=180)


def _rotation_tenant() -> TenantState:
    return TenantState(
        blueprints={"agent-router": BlueprintRecord(application_object_id="bp-obj",
                                                    app_id="bp-app")},
        nhis={"wf-claims-triage/agent-router": NhiRecord(
            backend="agent_id", principal_id="ag", app_id="ag", blueprint="agent-router")},
    )  # fmt: skip


BP = f"{G}applications/bp-obj/microsoft.graph.agentIdentityBlueprint"


def _mock_rotation(
    tmp_path: Path, token_ok: bool, extra_keys: list[dict[str, str]] | None = None
) -> tuple[respx.Route, respx.Route]:
    old = load_local_cert("bp-agent-router", tmp_path)
    assert old is not None
    base = BP
    respx.get(base).respond(json={"id": "bp-obj", "keyCredentials": [
        {"keyId": "old-key", "customKeyIdentifier": old.thumbprint_b64},
        *(extra_keys or [])]})  # fmt: skip
    add = respx.post(f"{base}/addKey").respond(json={"keyId": "new-key"})
    remove = respx.post(f"{base}/removeKey").respond(204)
    url = TOKEN_URL.format(tenant="tid")
    if token_ok:
        respx.post(url).respond(json={"access_token": "a.b.c"})
    else:
        respx.post(url).respond(401, json={"error": "invalid_client", "error_codes": [700027]})
    return add, remove


def _as_target(used: list[str]) -> AddKeyWriter:
    """addkey-self, with a stand-in client that records which key each call used."""

    def make(pem: Path) -> GraphClient:
        used.append(pem.name)
        return GraphClient(lambda: f"as:{pem.name}", sleep=lambda _: None)

    return AddKeyWriter(make, "bp-obj", "bp-agent-router itself")


@respx.mock
def test_rotation_adds_verifies_then_removes(tmp_path: Path) -> None:
    generate_self_signed("bp-agent-router", tmp_path, 180)
    old_bytes = (tmp_path / "bp-agent-router.pem").read_bytes()
    add, remove = _mock_rotation(tmp_path, token_ok=True)
    target = resolve("bp-agent-router", _rotation_tenant())
    used: list[str] = []
    with GraphClient(lambda: "t", sleep=lambda _: None) as g, httpx.Client() as http:
        log = rotate(g, _as_target(used), http, "tid", target, "api://x/.default", 180, DAY0,
                     tmp_path, sleep=lambda _: None)  # fmt: skip
    assert add.called and remove.called
    assert (
        add.calls[0].request.content
        and json.loads(remove.calls[0].request.content)["keyId"] == "old-key"
    )
    # Self-service: addKey as the blueprint with its current key, removeKey with the new one.
    assert used == ["bp-agent-router.pem", "bp-agent-router.next.pem"]
    assert add.calls[0].request.headers["Authorization"] == "Bearer as:bp-agent-router.pem"
    assert (tmp_path / f"bp-agent-router.retired-{DAY0}.pem").read_bytes() == old_bytes
    assert (tmp_path / "bp-agent-router.pem").read_bytes() != old_bytes
    assert any("verified" in line for line in log)


@respx.mock
def test_rotation_never_removes_the_old_key_if_the_new_one_fails(tmp_path: Path) -> None:
    generate_self_signed("bp-agent-router", tmp_path, 180)
    old_bytes = (tmp_path / "bp-agent-router.pem").read_bytes()
    add, remove = _mock_rotation(tmp_path, token_ok=False)
    target = resolve("bp-agent-router", _rotation_tenant())
    with (
        GraphClient(lambda: "t", sleep=lambda _: None) as g,
        httpx.Client() as http,
        pytest.raises(PlanError, match="old key was NOT removed"),
    ):  # (the addKey writer; PATCH shares the same add-verify-remove order)
        rotate(g, _as_target([]), http, "tid", target, "api://x/.default", 180, DAY0,
               tmp_path, sleep=lambda _: None)  # fmt: skip
    assert add.called and not remove.called
    assert (tmp_path / "bp-agent-router.pem").read_bytes() == old_bytes  # untouched
    assert (tmp_path / "bp-agent-router.next.pem").exists()  # kept for the retry


def test_rotation_target_must_be_known() -> None:
    with pytest.raises(PlanError):
        resolve("bp-nobody", _rotation_tenant())


@respx.mock
def test_patch_rotation_sends_both_keys_then_only_the_new_one(tmp_path: Path) -> None:
    """--method patch: the provisioner writes [current, new], verifies, then [new]."""
    generate_self_signed("bp-agent-router", tmp_path, 180)
    old = load_local_cert("bp-agent-router", tmp_path)
    assert old is not None
    add, remove = _mock_rotation(tmp_path, token_ok=True)
    patch = respx.patch(BP).respond(204)
    target = resolve("bp-agent-router", _rotation_tenant())
    with (
        GraphClient(lambda: "scanner", sleep=lambda _: None) as g,
        GraphClient(lambda: "prov", sleep=lambda _: None) as prov,
        httpx.Client() as http,
    ):
        rotate(g, PatchWriter(prov), http, "tid", target, "api://x/.default", 180, DAY0,
               tmp_path, sleep=lambda _: None)  # fmt: skip
    new = load_local_cert("bp-agent-router", tmp_path)  # moved into place
    assert new is not None
    bodies = [json.loads(c.request.content)["keyCredentials"] for c in patch.calls]
    assert [[k["customKeyIdentifier"] for k in b] for b in bodies] == [
        [old.thumbprint_b64, new.thumbprint_b64],
        [new.thumbprint_b64],
    ]
    assert all(c.request.headers["Authorization"] == "Bearer prov" for c in patch.calls)
    assert not add.called and not remove.called


@respx.mock
def test_patch_rotation_refuses_to_drop_a_key_it_does_not_hold(tmp_path: Path) -> None:
    generate_self_signed("bp-agent-router", tmp_path, 180)
    old_bytes = (tmp_path / "bp-agent-router.pem").read_bytes()
    _mock_rotation(tmp_path, token_ok=True,
                   extra_keys=[{"keyId": "ci", "customKeyIdentifier": "someone-else",
                                "displayName": "github-actions"}])  # fmt: skip
    patch = respx.patch(BP).respond(204)
    target = resolve("bp-agent-router", _rotation_tenant())
    with (
        GraphClient(lambda: "t", sleep=lambda _: None) as g,
        httpx.Client() as http,
        pytest.raises(PlanError, match="github-actions"),
    ):
        rotate(g, PatchWriter(g), http, "tid", target, "api://x/.default", 180, DAY0,
               tmp_path, sleep=lambda _: None)  # fmt: skip
    assert not patch.called
    assert (tmp_path / "bp-agent-router.pem").read_bytes() == old_bytes
