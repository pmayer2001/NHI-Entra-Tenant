"""Execute probe checks.

Read checks run as `nhigov-scanner`. Write checks run as `nhigov-provisioner` and
mutate the tenant, so they only execute with --execute after Paul confirms
(the operator confirms every write); otherwise they come back as PLANNED. Every object the write
sequence creates is named `nhigov-probe-*` and deleted in a finally block.

Steps that act on an object created seconds earlier retry with backoff: the
directory is replicated, so the object (or its owner link, which W02 depends on)
can be missing on the replica that serves the next call, showing up as a 404 or
a 403. Retries are capped at about 30s, so a real permission gap still fails.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import replace
from typing import Any

from nhigov.graph.client import GraphClient
from nhigov.probe.checks import Check, Identity, Outcome, Result, classify


def run_check(client: GraphClient, check: Check) -> tuple[Result, dict[str, Any]]:
    response = client.request(
        check.method,
        check.path,
        json=check.body,
        params=check.params or None,
        version=check.version,
        check=False,
    )
    outcome, code, message = classify(response)
    body: dict[str, Any] = {}
    if response.content:
        try:
            body = response.json()
        except ValueError:
            body = {}
    result = Result(
        check=check,
        outcome=outcome,
        status=response.status_code,
        code=code,
        detail=message,
        request_id=response.headers.get("request-id"),
    )
    return result, body


def run_read_checks(clients: dict[Identity, GraphClient], checks: Iterable[Check]) -> list[Result]:
    return [run_check(clients[c.identity], c)[0] for c in checks]


def _w(
    id_: str,
    capability: str,
    method: str,
    path: str,
    decides: str,
    body: dict[str, Any] | None = None,
) -> Check:
    return Check(id_, capability, "provisioner", method, path, decides, body=body)


def planned_write_checks(sponsor_id: str, run_id: str) -> list[Check]:
    """The write sequence with placeholders (<W01.appId>) for IDs known only at run time."""
    sponsor = f"https://graph.microsoft.com/v1.0/users/{sponsor_id}"
    return [
        _w(
            "W01", "Create agent identity blueprint", "POST", "applications",
            "Agent ID backend viable (ADR-003)",
            {
                "@odata.type": "Microsoft.Graph.AgentIdentityBlueprint",
                "displayName": f"nhigov-probe-bp-{run_id}",
                "sponsors@odata.bind": [sponsor],
            },
        ),
        _w(
            "W02", "Create blueprint principal", "POST",
            "servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal",
            "Agent ID backend viable (ADR-003)",
            {"appId": "<W01.appId>"},
        ),
        _w(
            "W03", "Create agent identity from blueprint", "POST",
            "servicePrincipals/microsoft.graph.agentIdentity",
            "One NHI per (workflow, agent) under Agent ID (P3)",
            {
                "displayName": f"nhigov-probe-ai-{run_id}",
                "agentIdentityBlueprintId": "<W01.appId>",
                "sponsors@odata.bind": [sponsor],
            },
        ),
        _w(
            "W04", "Set tags on agent identity", "PATCH",
            "servicePrincipals/<W03.id>/microsoft.graph.agentIdentity",
            "Tag-based correlation for agent identities (ADR-006)",
            {"tags": ["nhigov:probe"]},
        ),
        _w(
            "W05", "Tags persisted on agent identity", "GET",
            "servicePrincipals/<W03.id>/microsoft.graph.agentIdentity",
            "Tag-based correlation for agent identities (ADR-006)",
        ),
        _w(
            "W06", "App management policy write (no-op)", "PATCH",
            "policies/defaultAppManagementPolicy",
            "Tenant-wide 'no secrets' enforcement on Free (ADR-012, P7)",
            {"isEnabled": "<current value>"},
        ),
        _w(
            "C01", "Cleanup: delete agent identity", "DELETE",
            "servicePrincipals/<W03.id>",
            "Probe leaves no objects behind",
        ),
        _w(
            "C02", "Cleanup: delete blueprint (cascades)", "DELETE",
            "applications/<W01.id>",
            "Probe leaves no objects behind",
        ),
    ]  # fmt: skip


# Backoff between attempts for steps that follow a create (total ~30s).
LAG_BACKOFF = (2.0, 4.0, 8.0, 16.0)
_LAG = (Outcome.FORBIDDEN, Outcome.NOT_FOUND)


def run_write_checks(
    client: GraphClient | None,
    sponsor_id: str,
    run_id: str,
    execute: bool,
    sleep: Callable[[float], None] = time.sleep,
) -> list[Result]:
    plan = {c.id: c for c in planned_write_checks(sponsor_id, run_id)}
    if not execute or client is None:
        return [Result(c, Outcome.PLANNED) for c in plan.values()]

    results: list[Result] = []

    def run(
        id_: str, retry_on: tuple[Outcome, ...] = (), **changes: Any
    ) -> tuple[Result, dict[str, Any]]:
        check = replace(plan[id_], **changes)
        result, body = run_check(client, check)
        for attempt, delay in enumerate(LAG_BACKOFF, start=2):
            if result.outcome not in retry_on:
                break
            sleep(delay)
            result, body = run_check(client, check)
            if result.outcome is Outcome.OK:
                # Evidence for the replication-lag hypothesis, kept in the matrix.
                result = replace(result, detail=f"OK on attempt {attempt} (replication lag)")
        results.append(result)
        return result, body

    def skip(*ids: str, why: str) -> None:
        results.extend(Result(plan[i], Outcome.SKIPPED, detail=why) for i in ids)

    bp_obj_id: str | None = None
    agent_obj_id: str | None = None
    try:
        r, bp = run("W01")
        if r.outcome is not Outcome.OK:
            skip("W02", "W03", "W04", "W05", why="W01 failed")
        else:
            bp_obj_id, app_id = bp["id"], bp["appId"]
            # A just-created object can 404 on another replica for a few seconds.
            client.get_after_create(f"applications/{bp_obj_id}")
            run("W02", retry_on=_LAG, body={"appId": app_id})

            r, agent = run(
                "W03",
                retry_on=_LAG,
                body={**(plan["W03"].body or {}), "agentIdentityBlueprintId": app_id},
            )
            if r.outcome is not Outcome.OK:
                skip("W04", "W05", why="W03 failed")
            else:
                agent_obj_id = agent["id"]
                # Agent ID update/read/delete use the typed-cast URL (Graph v1.0 docs).
                agent_path = f"servicePrincipals/{agent_obj_id}/microsoft.graph.agentIdentity"
                client.get_after_create(agent_path)
                run("W04", retry_on=_LAG, path=agent_path)
                r, got = run("W05", retry_on=_LAG, path=agent_path, params={"$select": "id,tags"})
                if r.outcome is Outcome.OK and "nhigov:probe" not in got.get("tags", []):
                    results[-1] = replace(r, outcome=Outcome.ERROR, detail="tags not persisted")

        # W06 writes the policy's current isEnabled value back, so nothing changes.
        current = client.request("GET", "policies/defaultAppManagementPolicy", check=False)
        if current.is_success:
            run("W06", body={"isEnabled": bool(current.json().get("isEnabled", False))})
        else:
            outcome, code, msg = classify(current)
            results.append(
                Result(
                    plan["W06"],
                    outcome,
                    current.status_code,
                    code,
                    f"could not read current policy: {msg}",
                )
            )
    finally:
        # Deletes use the plain path: on 2026-10-31 the documented typed-cast DELETE
        # returned 403 for an app-only caller holding DeleteRestore.All, while
        # DELETE /applications/{id} returned 204 (ADR-005).
        if agent_obj_id:
            run("C01", retry_on=_LAG, path=f"servicePrincipals/{agent_obj_id}")
        else:
            skip("C01", why="nothing to delete")
        if bp_obj_id:
            run("C02", retry_on=_LAG, path=f"applications/{bp_obj_id}")
        else:
            skip("C02", why="nothing to delete")
    return results


def leftover_objects(results: Iterable[Result], run_id: str) -> list[str]:
    """Names of probe objects the cleanup could not delete, so a human can remove them.

    Deleting the blueprint cascades to its principal and agent identities, so
    only a failed C02 leaves anything behind.
    """
    outcome = {r.check.id: r.outcome for r in results}
    if outcome.get("C02") in (None, Outcome.OK, Outcome.SKIPPED, Outcome.PLANNED):
        return []
    left = [f"agent identity blueprint  nhigov-probe-bp-{run_id}"]
    if outcome.get("W02") is Outcome.OK:
        left.append(f"blueprint principal       nhigov-probe-bp-{run_id}")
    if outcome.get("C01") is not Outcome.OK and outcome.get("W03") is Outcome.OK:
        left.append(f"agent identity            nhigov-probe-ai-{run_id}")
    return left


def recommend_backend(results: Iterable[Result]) -> str:
    """Agent ID only if a blueprint, its principal and an agent identity could all be created."""
    ok = {r.check.id for r in results if r.outcome is Outcome.OK}
    return "agent_id" if {"W01", "W02", "W03"} <= ok else "service_principal"
