from __future__ import annotations

import json
from datetime import date

import httpx
import pytest
import respx

from nhigov.graph.client import GraphClient
from nhigov.probe.checks import READ_CHECKS, Outcome, classify
from nhigov.probe.report import render_matrix
from nhigov.probe.runner import (
    leftover_objects,
    recommend_backend,
    run_read_checks,
    run_write_checks,
)

BASE = "https://graph.microsoft.com/v1.0"
GUID = "11111111-2222-3333-4444-555555555555"


def _err(status: int, code: str, message: str = "") -> httpx.Response:
    return httpx.Response(
        status,
        json={"error": {"code": code, "message": message}},
        request=httpx.Request("GET", f"{BASE}/x"),
    )


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (httpx.Response(200, json={}), Outcome.OK),
        (_err(403, "Authorization_RequestDenied", "Insufficient privileges"), Outcome.FORBIDDEN),
        (
            _err(
                403,
                "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
                "Neither tenant is B2C or tenant doesn't have premium license",
            ),
            Outcome.LICENSE,
        ),
        (
            _err(400, "BadRequest", "Resource not found for the segment 'agentIdentity'"),
            Outcome.UNAVAILABLE,
        ),
        (_err(404, "Request_ResourceNotFound"), Outcome.NOT_FOUND),
        (_err(500, "InternalServerError"), Outcome.ERROR),
    ],
)
def test_classify(response: httpx.Response, expected: Outcome) -> None:
    assert classify(response)[0] is expected


def test_read_check_ids_unique() -> None:
    ids = [c.id for c in READ_CHECKS]
    assert len(ids) == len(set(ids))


@respx.mock
def test_run_read_checks_records_each_outcome() -> None:
    respx.route().respond(200, json={"value": []})
    client = GraphClient(lambda: "t", sleep=lambda _: None)
    results = run_read_checks({"scanner": client}, READ_CHECKS)
    assert len(results) == len(READ_CHECKS)
    assert all(r.outcome is Outcome.OK for r in results)


def test_dry_run_plans_writes_without_client() -> None:
    results = run_write_checks(None, "sponsor", "run", execute=False)
    assert results and all(r.outcome is Outcome.PLANNED for r in results)
    assert recommend_backend(results) == "service_principal"


@respx.mock
def test_write_sequence_happy_path_cleans_up() -> None:
    respx.post(f"{BASE}/applications").respond(201, json={"id": "bp-obj", "appId": "bp-app"})
    respx.get(f"{BASE}/applications/bp-obj").respond(json={"id": "bp-obj"})
    respx.post(f"{BASE}/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal").respond(
        201, json={"id": "bpp"}
    )
    create_agent = respx.post(f"{BASE}/servicePrincipals/microsoft.graph.agentIdentity").respond(
        201, json={"id": "ai-obj"}
    )
    respx.patch(f"{BASE}/servicePrincipals/ai-obj/microsoft.graph.agentIdentity").respond(204)
    respx.get(f"{BASE}/servicePrincipals/ai-obj/microsoft.graph.agentIdentity").respond(
        json={"id": "ai-obj", "tags": ["nhigov:probe"]}
    )
    respx.get(f"{BASE}/policies/defaultAppManagementPolicy").respond(json={"isEnabled": False})
    respx.patch(f"{BASE}/policies/defaultAppManagementPolicy").respond(204)
    del_ai = respx.delete(f"{BASE}/servicePrincipals/ai-obj").respond(204)
    del_bp = respx.delete(f"{BASE}/applications/bp-obj").respond(204)

    client = GraphClient(lambda: "t", sleep=lambda _: None)
    results = run_write_checks(client, "sponsor-id", "run", execute=True, sleep=lambda _: None)

    by_id = {r.check.id: r.outcome for r in results}
    assert all(o is Outcome.OK for o in by_id.values()), by_id
    assert recommend_backend(results) == "agent_id"
    sent = json.loads(create_agent.calls.last.request.content)
    assert sent["agentIdentityBlueprintId"] == "bp-app"
    assert del_ai.called and del_bp.called
    assert leftover_objects(results, "run") == []


@respx.mock
def test_write_sequence_flags_unpersisted_tags() -> None:
    respx.post(f"{BASE}/applications").respond(201, json={"id": "bp-obj", "appId": "bp-app"})
    respx.get(f"{BASE}/applications/bp-obj").respond(json={})
    respx.post(url__regex=r".*agentIdentityBlueprintPrincipal$").respond(201, json={})
    respx.post(url__regex=r".*microsoft\.graph\.agentIdentity$").respond(201, json={"id": "ai"})
    respx.patch(f"{BASE}/servicePrincipals/ai/microsoft.graph.agentIdentity").respond(204)
    respx.get(f"{BASE}/servicePrincipals/ai/microsoft.graph.agentIdentity").respond(
        json={"id": "ai", "tags": []}
    )
    respx.get(f"{BASE}/policies/defaultAppManagementPolicy").respond(403)
    respx.delete(url__regex=r".*").respond(204)

    client = GraphClient(lambda: "t", sleep=lambda _: None)
    by_id = {
        r.check.id: r
        for r in run_write_checks(client, "s", "run", execute=True, sleep=lambda _: None)
    }
    assert by_id["W05"].outcome is Outcome.ERROR
    assert by_id["W05"].detail == "tags not persisted"
    assert by_id["W06"].outcome is Outcome.FORBIDDEN


@respx.mock
def test_write_sequence_blueprint_unavailable_skips_and_cleans_nothing() -> None:
    respx.post(f"{BASE}/applications").respond(
        400, json={"error": {"code": "BadRequest", "message": "Invalid @odata.type"}}
    )
    respx.get(f"{BASE}/policies/defaultAppManagementPolicy").respond(json={"isEnabled": True})
    respx.patch(f"{BASE}/policies/defaultAppManagementPolicy").respond(204)
    delete = respx.delete(url__regex=r".*").respond(204)

    client = GraphClient(lambda: "t", sleep=lambda _: None)
    results = run_write_checks(client, "s", "run", execute=True, sleep=lambda _: None)
    by_id = {r.check.id: r.outcome for r in results}
    assert by_id["W01"] is Outcome.UNAVAILABLE
    assert by_id["W03"] is Outcome.SKIPPED
    assert by_id["C02"] is Outcome.SKIPPED
    assert not delete.called
    assert recommend_backend(results) == "service_principal"


@respx.mock
def test_cleanup_denied_reports_leftovers() -> None:
    """Reproduces the 2026-10-31 run: creates succeed, every update/delete is 403."""
    denied = {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient"}}
    respx.post(f"{BASE}/applications").respond(201, json={"id": "bp-obj", "appId": "bp-app"})
    respx.get(f"{BASE}/applications/bp-obj").respond(json={})
    respx.post(url__regex=r".*agentIdentityBlueprintPrincipal$").respond(201, json={})
    respx.post(url__regex=r".*microsoft\.graph\.agentIdentity$").respond(201, json={"id": "ai"})
    respx.get(f"{BASE}/servicePrincipals/ai/microsoft.graph.agentIdentity").respond(json={})
    respx.patch(url__regex=r".*").respond(403, json=denied)
    respx.get(f"{BASE}/policies/defaultAppManagementPolicy").respond(403, json=denied)
    respx.delete(url__regex=r".*").respond(403, json=denied)

    client = GraphClient(lambda: "t", sleep=lambda _: None)
    results = run_write_checks(client, "s", "run1", execute=True, sleep=lambda _: None)
    by_id = {r.check.id: r.outcome for r in results}
    assert by_id["C01"] is Outcome.FORBIDDEN and by_id["C02"] is Outcome.FORBIDDEN
    left = leftover_objects(results, "run1")
    assert len(left) == 3
    assert any("nhigov-probe-ai-run1" in x for x in left)


def test_matrix_redacts_guids() -> None:
    results = run_write_checks(None, GUID, "run", execute=False)
    md = render_matrix(results, "service_principal", date(2026, 10, 31))
    assert GUID not in md
    assert "| W01 |" in md
    assert "`service_principal`" in md


@respx.mock
def test_w02_retries_through_replication_lag() -> None:
    """The owner link can lag behind the blueprint: 403 first, then success."""
    denied = {"error": {"code": "Authorization_RequestDenied", "message": "not owner yet"}}
    respx.post(f"{BASE}/applications").respond(201, json={"id": "bp-obj", "appId": "bp-app"})
    respx.get(f"{BASE}/applications/bp-obj").respond(json={})
    w02 = respx.post(url__regex=r".*agentIdentityBlueprintPrincipal$").mock(
        side_effect=[httpx.Response(403, json=denied), httpx.Response(201, json={})]
    )
    respx.post(url__regex=r".*microsoft\.graph\.agentIdentity$").respond(403, json=denied)
    respx.get(f"{BASE}/policies/defaultAppManagementPolicy").respond(403, json=denied)
    respx.delete(url__regex=r".*").respond(204)
    sleeps: list[float] = []

    client = GraphClient(lambda: "t", sleep=lambda _: None)
    by_id = {
        r.check.id: r
        for r in run_write_checks(client, "s", "run", execute=True, sleep=sleeps.append)
    }
    assert w02.call_count == 2
    assert by_id["W02"].outcome is Outcome.OK
    assert "attempt 2" in by_id["W02"].detail
    assert by_id["W03"].outcome is Outcome.FORBIDDEN  # gave up after the backoff budget
    assert by_id["C02"].outcome is Outcome.OK


@respx.mock
def test_principal_never_created_is_not_reported_as_leftover() -> None:
    """Reproduces the second 2026-10-31 run: W02 403 and C02 404 throughout."""
    denied = {"error": {"code": "Authorization_RequestDenied", "message": "x"}}
    missing = {"error": {"code": "Request_ResourceNotFound", "message": "x"}}
    respx.post(f"{BASE}/applications").respond(201, json={"id": "bp-obj", "appId": "bp-app"})
    respx.get(f"{BASE}/applications/bp-obj").respond(json={})
    respx.post(url__regex=r".*").respond(403, json=denied)
    respx.get(f"{BASE}/policies/defaultAppManagementPolicy").respond(403, json=denied)
    respx.delete(url__regex=r".*").respond(404, json=missing)

    client = GraphClient(lambda: "t", sleep=lambda _: None)
    results = run_write_checks(client, "s", "run2", execute=True, sleep=lambda _: None)
    assert leftover_objects(results, "run2") == ["agent identity blueprint  nhigov-probe-bp-run2"]


def test_redact_catches_base64url_guids_in_agent_sub_claim() -> None:
    from nhigov.probe.report import redact

    sub = "'/eid1/c/pub/t/AAAAAAAAAAAAAAAAAAAAAA/a/BBBBBBBBBBBBBBBBBBBBBB/<agent A id>'"
    out = redact(sub)
    assert "AAAAAAAAAAAAAAAAAAAAAA" not in out
    assert "BBBBBBBBBBBBBBBBBBBBBB" not in out
    assert out == "'/eid1/c/pub/t/<b64-id>/a/<b64-id>/<agent A id>'"
    # Ordinary paths and URLs are untouched.
    assert redact("/v1.0/servicePrincipals/microsoft.graph.agentIdentity") == (
        "/v1.0/servicePrincipals/microsoft.graph.agentIdentity"
    )
