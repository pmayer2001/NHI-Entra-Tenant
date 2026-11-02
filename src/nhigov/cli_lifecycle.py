"""`nhigov lifecycle ...`: status, run, rotate and the tenant app management policy.

Reads run as the scanner. Writes (disable, delete, policy PATCH, key PATCH) run as
the provisioner; with --method addkey-self, addKey/removeKey run as the rotated
object itself.
All writes need --execute and a confirmation (CLAUDE.md §14).
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated

import httpx
import typer

from nhigov.agent_auth import TokenError
from nhigov.config import Config, load_config
from nhigov.discovery.scan import collect_inventory
from nhigov.graph.auth import provisioner_token, scanner_token
from nhigov.graph.client import GraphClient, GraphError
from nhigov.lifecycle.engine import LifecyclePlan, evaluate
from nhigov.lifecycle.policy import desired_policy
from nhigov.lifecycle.rotate import (
    AddKeyWriter,
    KeyWriter,
    Method,
    PatchWriter,
    Target,
    default_method,
    plan_text,
    resolve,
    rotate,
    self_service_client,
)
from nhigov.lifecycle.run import execute
from nhigov.lifecycle.state import LIFECYCLE_PATH, load_lifecycle, save_lifecycle
from nhigov.probe.report import redact
from nhigov.reconcile.engine import PlanError
from nhigov.reconcile.state import STATE_PATH, load_state, save_state
from nhigov.registry.findings import Severity
from nhigov.registry.loader import PLACEHOLDER_DOMAIN, Registry, load_registry
from nhigov.registry.models import Backend
from nhigov.registry.validate import validate_registry

lifecycle_app = typer.Typer(
    no_args_is_help=True, help="Lifecycle engine: expiry, sponsors, retirement, rotation."
)

ConfigOpt = Annotated[Path, typer.Option("--config")]
AsOf = Annotated[
    datetime | None,
    typer.Option("--as-of", formats=["%Y-%m-%d"], help="Pretend today is this date (demos)"),
]
Execute = Annotated[bool, typer.Option("--execute", help="Write to the tenant (asks first)")]
Yes = Annotated[bool, typer.Option("--yes", help="Skip the confirmation prompt")]
STATE_COLORS = {"disabled": "red", "expiring": "yellow", "soft-deleted": "red", "purged": "white"}


def _registry(cfg: Config) -> Registry:
    registry, findings = load_registry(Path("registry"), cfg.tenant_domain or PLACEHOLDER_DOMAIN)
    if any(f.severity is Severity.ERROR for f in findings + validate_registry(registry)):
        raise typer.BadParameter("the registry has errors; run `nhigov validate` first")
    return registry


def _evaluate(cfg: Config, today: date) -> tuple[Registry, LifecyclePlan]:
    registry = _registry(cfg)
    tenant = load_state(STATE_PATH)
    inventory = collect_inventory(cfg, registry, tenant, datetime.now(UTC))
    plan = evaluate(registry, inventory, tenant, load_lifecycle(),
                    today, Backend(cfg.identity_backend.value))  # fmt: skip
    return registry, plan


def _print(plan: LifecyclePlan, today: date) -> None:
    typer.echo(f"Lifecycle as of {today}\n")
    for row in plan.rows:
        typer.secho(f"  {row.state:<16} {row.name}", fg=STATE_COLORS.get(row.state))
        if row.detail:
            typer.echo(f"  {'':<16}   {redact(row.detail)}")
        if row.next_step:
            typer.echo(f"  {'':<16}   next: {row.next_step}")
    marks = {"disable": "-", "delete": "x", "notice": "!", "release": "~"}
    typer.echo(f"\n{len(plan.actions)} action(s) due" + (":" if plan.actions else "."))
    for a in plan.actions:
        typer.echo(f"  {marks[a.kind]} {a.kind:<8} {a.name}: {redact(a.reason)}")


@lifecycle_app.command("status")
def status(config_path: ConfigOpt = Path("config.yaml"), as_of: AsOf = None) -> None:
    """Each NHI's lifecycle state and what's due. Read-only."""
    today = as_of.date() if as_of else date.today()
    _, plan = _evaluate(load_config(config_path), today)
    save_lifecycle(plan.state)  # bookkeeping only: when each condition was first seen
    _print(plan, today)


@lifecycle_app.command("run")
def run(
    config_path: ConfigOpt = Path("config.yaml"),
    as_of: AsOf = None,
    execute_: Execute = False,
    yes: Yes = False,
) -> None:
    """Carry out what's due: notices, disables (holds), soft-deletes. Dry run by default."""
    cfg = load_config(config_path)
    today = as_of.date() if as_of else date.today()
    _, plan = _evaluate(cfg, today)
    save_lifecycle(plan.state)
    _print(plan, today)
    writes = [a for a in plan.actions if a.kind in ("disable", "delete")]
    if not plan.actions:
        return
    if not execute_:
        typer.echo("\nDry run: nothing changed. Re-run with --execute to act.")
        return
    if writes:
        typer.echo(f"\n{len(writes)} change(s) are written to the tenant as nhigov-provisioner.")
        if not yes:
            typer.confirm("Carry them out?", abort=True)
    tenant = load_state(STATE_PATH)

    def save(t: object, lc: object) -> None:
        save_state(tenant, STATE_PATH)
        save_lifecycle(plan.state, LIFECYCLE_PATH)

    with GraphClient(provisioner_token(cfg), base_url=cfg.graph.base_url) as prov:
        try:
            for line in execute(prov, plan, tenant, today, save, Path("reports")):
                typer.secho(f"  {line}", fg=typer.colors.GREEN)
        except GraphError as exc:
            typer.secho(f"\nStopped: Entra refused a step.\n  {exc}", fg="red", err=True)
            raise typer.Exit(1) from None
    typer.echo(
        "\nRun `nhigov plan`: held NHIs stay disabled; released ones are re-enabled by apply."
    )


def _writer(
    method: Method, target: Target, cfg: Config, http: httpx.Client, prov: GraphClient | None
) -> KeyWriter:
    """How rotate writes keys. Without clients (dry run), only describe() is usable."""
    if method is Method.PATCH:
        return PatchWriter(prov or GraphClient(lambda: ""))
    return AddKeyWriter(
        self_service_client(http, cfg.tenant_id, target, cfg.graph.base_url),
        target.application_object_id, f"{target.name} itself",
    )  # fmt: skip


@lifecycle_app.command("rotate")
def rotate_cmd(
    name: Annotated[str, typer.Argument(help="bp-<agent> or nhi-<workflow>-<agent>")],
    method: Annotated[
        Method | None,
        typer.Option("--method", help="How keys are written (default: patch for blueprints, "
                     "addkey-self for service-principal NHIs)"),
    ] = None,
    config_path: ConfigOpt = Path("config.yaml"),
    execute_: Execute = False,
    yes: Yes = False,
) -> None:  # fmt: skip
    """Rotate a certificate: add new, verify a token, then remove old. Dry run by default."""
    cfg = load_config(config_path)
    registry = _registry(cfg)
    days = registry.policy.max_credential_lifetime_days if registry.policy else 180
    tenant = load_state(STATE_PATH)
    try:
        target = resolve(name, tenant)
    except PlanError as exc:
        raise typer.BadParameter(str(exc)) from None
    method = method or default_method(target)
    with httpx.Client(timeout=30.0) as http:
        typer.echo(f"Rotate {name} (method: {method}):")
        for line in plan_text(target, _writer(method, target, cfg, http, None),
                              Path("~/.nhigov/certs"), days):  # fmt: skip
            typer.echo(f"  {line}")
        if not execute_:
            typer.echo("\nDry run: nothing changed. Re-run with --execute.")
            return
        if not yes:
            typer.confirm("Rotate now?", abort=True)
        scope = f"{registry.resources['res-sensitive-records'].identifier_uri}/.default"
        with (
            GraphClient(scanner_token(cfg), base_url=cfg.graph.base_url) as scanner,
            GraphClient(provisioner_token(cfg), base_url=cfg.graph.base_url) as prov,
        ):
            try:
                writer = _writer(method, target, cfg, http, prov)
                log = rotate(scanner, writer, http, cfg.tenant_id, target, scope, days,
                             date.today())  # fmt: skip
            except (PlanError, GraphError, TokenError) as exc:
                typer.secho(f"Rotation stopped: {exc}", fg="red", err=True)
                raise typer.Exit(1) from None
    for line in log:
        typer.secho(f"  {line}", fg=typer.colors.GREEN)


@lifecycle_app.command("policy")
def policy_cmd(
    config_path: ConfigOpt = Path("config.yaml"),
    execute_: Execute = False,
    yes: Yes = False,
) -> None:
    """Block new client secrets and cap certificate lifetime, tenant-wide. Dry run by default."""
    cfg = load_config(config_path)
    registry = _registry(cfg)
    days = registry.policy.max_credential_lifetime_days if registry.policy else 180
    with GraphClient(scanner_token(cfg), base_url=cfg.graph.base_url) as scanner:
        current = scanner.get("policies/defaultAppManagementPolicy")
    body, changes = desired_policy(current, days)
    if not changes:
        typer.secho("The tenant app management policy already matches. No changes.", fg="green")
        return
    typer.echo("PATCH /v1.0/policies/defaultAppManagementPolicy would:")
    for c in changes:
        typer.echo(f"  + {c}")
    typer.echo("Existing restrictions in the policy are kept.")
    if not execute_:
        typer.echo("\nDry run: nothing changed. Re-run with --execute.")
        return
    if not yes:
        typer.confirm("Apply the tenant-wide policy?", abort=True)
    with GraphClient(provisioner_token(cfg), base_url=cfg.graph.base_url) as prov:
        try:
            prov.patch("policies/defaultAppManagementPolicy", body)
        except GraphError as exc:
            typer.secho(f"Entra refused: {exc}", fg="red", err=True)
            raise typer.Exit(1) from None
    typer.secho("Policy updated: new client secrets are blocked tenant-wide.", fg="green")
