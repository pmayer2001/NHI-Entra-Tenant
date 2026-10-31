"""Phase 0 spike: one blueprint, two agent identities, real tokens (ADR-003).

Tests three claims about the Agent ID token flow on this tenant:
  1. A blueprint's certificate can get a token AS an agent identity (T1 -> T2).
  2. Blast radius: the SAME certificate gets tokens for a SECOND agent identity.
  3. Binding: T1 minted for agent A (fmi_path=A) can NOT be used to become agent B.

Default is a dry run that prints the plan. --execute creates real objects as
nhigov-provisioner (after a confirmation prompt) and deletes them in a finally
block. Raw tokens are never printed or saved; only decoded claims, with known
IDs replaced by labels and every other GUID redacted.

    uv run python scripts/spike_agent_token.py --sponsor YOUR-UPN            # plan
    uv run python scripts/spike_agent_token.py --sponsor YOUR-UPN --execute  # run
"""

from __future__ import annotations

import base64
import shutil
import time
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import httpx
import typer
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from nhigov.agent_auth import (
    TokenError,
    agent_identity_token,
    blueprint_exchange_token,
    unverified_claims,
)
from nhigov.certs import generate_self_signed
from nhigov.config import load_config
from nhigov.graph.auth import provisioner_token, scanner_token
from nhigov.graph.client import GraphClient, GraphError
from nhigov.probe.report import redact

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
BACKOFF = (2.0, 4.0, 8.0, 16.0, 30.0)  # ~60s budget for replication lag
# AADSTS codes seen while a new app or key replicates: app not found, key not found.
LAG_AADSTS = {700016, 700027}
CLAIMS_OF_INTEREST = ("aud", "iss", "appid", "azp", "oid", "sub", "idtyp", "roles", "tid")
RESULTS = Path("docs/spikes/agent-id-token-spike-results.md")

PLAN = """\
Plan (as nhigov-provisioner unless noted):
  1. Generate a 7-day self-signed cert in ~/.nhigov/certs/spike-<run>/ (local only)
  2. POST   blueprint  nhigov-spike-bp-<run>  (sponsor = --sponsor)
  3. PATCH  blueprint keyCredentials = that cert's PUBLIC key
  4. POST   blueprint principal
  5. POST   agent identities  nhigov-spike-ai-a-<run>  and  nhigov-spike-ai-b-<run>
  6. Token endpoint: T1(fmi_path=A) -> T2 as A;  T1(fmi_path=B) -> T2 as B
  7. Token endpoint: try T2 as B using T1 minted for A (expected: refused)
  8. DELETE agent identities and blueprint; delete the local cert folder
Results (claims only, IDs redacted) -> docs/spikes/agent-id-token-spike-results.md
"""

app = typer.Typer(add_completion=False)


def retry[T](
    fn: Callable[[], T], is_lag: Callable[[Exception], bool], log: list[str], step: str
) -> T:
    for attempt, delay in enumerate((*BACKOFF, None), start=1):
        try:
            result = fn()
        except Exception as exc:
            if delay is None or not is_lag(exc):
                raise
            time.sleep(delay)
            continue
        if attempt > 1:
            log.append(f"- {step}: OK on attempt {attempt} (replication lag)")
        return result
    raise AssertionError("unreachable")


def graph_lag(exc: Exception) -> bool:
    return isinstance(exc, GraphError) and exc.status in (403, 404)


def token_lag(exc: Exception) -> bool:
    return isinstance(exc, TokenError) and bool(LAG_AADSTS & set(exc.codes))


def summarize(token: str, labels: dict[str, str]) -> dict[str, Any]:
    claims = unverified_claims(token)
    out: dict[str, Any] = {k: claims[k] for k in CLAIMS_OF_INTEREST if k in claims}
    out["xms_* claims"] = sorted(k for k in claims if k.startswith("xms_"))
    text = repr(out)
    for raw, label in labels.items():
        text = text.replace(raw, label)
    return {"_": redact(text)}


@app.command()
def main(
    sponsor: str = typer.Option(..., help="Sponsor UPN (a member user in the tenant)"),
    execute: bool = typer.Option(False, "--execute", help="Create real objects and tokens"),
    yes: bool = typer.Option(False, "--yes", help="Skip the confirmation prompt"),
) -> None:
    typer.echo(PLAN)
    if not execute:
        typer.echo("Dry run. Re-run with --execute to perform these steps.")
        return
    if not yes:
        typer.confirm("Proceed with tenant writes?", abort=True)

    cfg = load_config()
    run_id = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    with GraphClient(scanner_token(cfg)) as scanner:
        sponsor_id = scanner.get(f"users/{sponsor}", params={"$select": "id"})["id"]
    sponsor_bind = [f"https://graph.microsoft.com/v1.0/users/{sponsor_id}"]

    cert_dir = Path(f"~/.nhigov/certs/spike-{run_id}").expanduser()
    cert = generate_self_signed(f"nhigov-spike-bp-{run_id}", cert_dir, lifetime_days=7)
    der = x509.load_pem_x509_certificate(cert.public_cer.read_bytes()).public_bytes(
        serialization.Encoding.DER
    )

    log: list[str] = []
    findings: dict[str, str] = {}
    labels: dict[str, str] = {cfg.tenant_id: "<tenant>", sponsor_id: "<sponsor>"}
    bp_id: str | None = None
    agent_ids: list[str] = []

    with GraphClient(provisioner_token(cfg)) as prov, httpx.Client(timeout=30) as http:
        try:
            bp = prov.post(
                "applications",
                {
                    "@odata.type": "Microsoft.Graph.AgentIdentityBlueprint",
                    "displayName": f"nhigov-spike-bp-{run_id}",
                    "sponsors@odata.bind": sponsor_bind,
                },
            )
            bp_id, bp_app_id = bp["id"], bp["appId"]
            labels |= {bp_id: "<blueprint object id>", bp_app_id: "<blueprint appId>"}
            prov.get_after_create(f"applications/{bp_id}")
            typer.echo("created blueprint")

            key_body = {
                "keyCredentials": [
                    {
                        "type": "AsymmetricX509Cert",
                        "usage": "Verify",
                        "key": base64.b64encode(der).decode(),
                        "displayName": f"spike-{run_id}",
                    }
                ]
            }
            try:
                retry(
                    lambda: prov.patch(
                        f"applications/{bp_id}/microsoft.graph.agentIdentityBlueprint", key_body
                    ),
                    graph_lag, log, "PATCH keyCredentials (typed-cast URL)",
                )  # fmt: skip
                findings["Cert upload path that worked"] = "typed-cast URL (documented)"
            except GraphError as exc:
                log.append(f"- PATCH keyCredentials via typed-cast URL: {exc.status} {exc.code}")
                retry(
                    lambda: prov.patch(f"applications/{bp_id}", key_body),
                    graph_lag, log, "PATCH keyCredentials (plain URL)",
                )  # fmt: skip
                findings["Cert upload path that worked"] = "plain `/applications/{id}` only"
            typer.echo("uploaded blueprint certificate")

            principal = retry(
                lambda: prov.post(
                    "servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal",
                    {"appId": bp_app_id},
                ),
                graph_lag, log, "create blueprint principal",
            )  # fmt: skip
            labels[principal["id"]] = "<blueprint principal id>"
            typer.echo("created blueprint principal")

            agents: dict[str, dict[str, Any]] = {}
            for name in ("a", "b"):
                agent = retry(
                    lambda name=name: prov.post(
                        "servicePrincipals/microsoft.graph.agentIdentity",
                        {
                            "displayName": f"nhigov-spike-ai-{name}-{run_id}",
                            "agentIdentityBlueprintId": bp_app_id,
                            "sponsors@odata.bind": sponsor_bind,
                        },
                    ),
                    graph_lag, log, f"create agent identity {name.upper()}",
                )  # fmt: skip
                agents[name] = agent
                agent_ids.append(agent["id"])
                labels[agent["id"]] = f"<agent {name.upper()} id>"
                if agent.get("appId") and agent["appId"] != agent["id"]:
                    labels[agent["appId"]] = f"<agent {name.upper()} appId>"
            a, b = agents["a"], agents["b"]
            findings["Agent identity `appId` == `id`?"] = (
                "yes" if a.get("appId") == a["id"] else f"no (appId present: {'appId' in a})"
            )
            typer.echo("created agent identities A and B")

            def client_id(agent: dict[str, Any]) -> str:
                return str(agent.get("appId") or agent["id"])

            tokens: dict[str, str] = {}
            for name, agent in (("A", a), ("B", b)):
                t1 = retry(
                    lambda agent=agent: blueprint_exchange_token(
                        http, cfg.tenant_id, bp_app_id, cert.private_pem, client_id(agent)
                    ),
                    token_lag, log, f"T1 (blueprint, fmi_path={name})",
                )  # fmt: skip
                t2 = retry(
                    lambda agent=agent, t1=t1: agent_identity_token(
                        http, cfg.tenant_id, client_id(agent), t1, GRAPH_SCOPE
                    ),
                    token_lag, log, f"T2 (as agent {name})",
                )  # fmt: skip
                tokens[f"T1 for {name}"], tokens[f"T2 as {name}"] = t1, t2
                typer.echo(f"got T1 and T2 for agent {name}")

            findings["1. Blueprint cert -> token as agent A"] = "succeeded"
            findings["2. Same cert -> token as agent B (blast radius)"] = "succeeded"

            try:
                agent_identity_token(
                    http, cfg.tenant_id, client_id(b), tokens["T1 for A"], GRAPH_SCOPE
                )
                findings["3. T1 minted for A reused to become B"] = (
                    "**ACCEPTED**: fmi_path does not bind T1 to one agent"
                )
            except TokenError as exc:
                findings["3. T1 minted for A reused to become B"] = (
                    f"refused (AADSTS{exc.codes[0] if exc.codes else '?'}: {exc.error})"
                )
            typer.echo("ran cross-agent check")

            for key, tok in tokens.items():
                findings[f"claims {key}"] = summarize(tok, labels)["_"]
        except (GraphError, TokenError) as exc:
            # Keep going to cleanup and still write what we learned up to this point.
            text = str(exc)
            for raw, label in labels.items():
                text = text.replace(raw, label)
            findings["STOPPED EARLY"] = text.splitlines()[0]
            typer.secho(f"stopped early: {findings['STOPPED EARLY']}", fg=typer.colors.RED)
        finally:
            # Delete agents explicitly and retry 404s: on 2026-10-31 deleting the
            # blueprint did NOT cascade to its agent identities, and a delete sent
            # right after creation 404'd on a replica that hadn't seen the agent yet.
            for agent_id in agent_ids:
                r = prov.request(
                    "DELETE", f"servicePrincipals/{agent_id}", retry_not_found=True, check=False
                )
                log.append(f"- cleanup agent identity: {r.status_code}")
            if bp_id:
                r = prov.request("DELETE", f"applications/{bp_id}", check=False)
                log.append(f"- cleanup blueprint: {r.status_code}")
            shutil.rmtree(cert_dir, ignore_errors=True)
            log.append("- cleanup local spike cert folder: done")

    write_results(run_id, findings, log)
    typer.echo(f"\nWrote {RESULTS}")
    for k, v in findings.items():
        if not k.startswith("claims"):
            typer.echo(f"  {k}: {v}")
    if "STOPPED EARLY" in findings:
        raise typer.Exit(1)
    if any(not line.endswith((": 204", "done")) for line in log if "cleanup" in line):
        typer.secho(
            f"CLEANUP INCOMPLETE: look for objects containing '{run_id}' with the scanner "
            "before deleting anything in the portal.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(2)


def write_results(run_id: str, findings: dict[str, str], log: list[str]) -> None:
    lines = [
        "# Agent ID token spike: results",
        "",
        f"_Generated by `scripts/spike_agent_token.py` on {date.today().isoformat()} "
        f"(run {run_id}). Raw tokens are never stored; IDs are labelled or redacted._",
        "",
        "| Question | Answer |",
        "|---|---|",
    ]
    for k, v in findings.items():
        if not k.startswith("claims"):
            lines.append(f"| {k} | {redact(v)} |")
    lines += ["", "## Token claims", ""]
    for k, v in findings.items():
        if k.startswith("claims"):
            lines += [f"**{k.removeprefix('claims ')}**", "", f"```\n{v}\n```", ""]
    lines += ["## Step log", "", *(redact(line) for line in log or ["- no retries needed"]), ""]
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    app()
