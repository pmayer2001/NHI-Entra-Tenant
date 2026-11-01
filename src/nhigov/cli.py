"""`nhigov` command-line entry point."""

from __future__ import annotations

import json
import logging
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated

import httpx
import structlog
import typer

from nhigov import __version__
from nhigov.certs import DEFAULT_CERT_DIR, DEFAULT_LIFETIME_DAYS, generate_self_signed
from nhigov.config import Config, load_config, load_tenant_domain
from nhigov.graph.auth import TokenAcquisitionError, provisioner_token, scanner_token
from nhigov.graph.client import GraphClient
from nhigov.probe.checks import READ_CHECKS, Outcome
from nhigov.probe.gate import NOT_ASSIGNED, check_gate
from nhigov.probe.report import redact, render_matrix
from nhigov.probe.resource import Verdict, render_resource_probe, run_resource_probe
from nhigov.probe.runner import (
    leftover_objects,
    recommend_backend,
    run_read_checks,
    run_write_checks,
)
from nhigov.reconcile.plan import PlanError, ResourcePlan, apply_plan, plan_resource
from nhigov.reconcile.resources import desired_application, desired_service_principal
from nhigov.reconcile.state import STATE_PATH, TenantState, load_state, save_state
from nhigov.registry.findings import Severity
from nhigov.registry.loader import PLACEHOLDER_DOMAIN, Registry, load_registry
from nhigov.registry.online import validate_online
from nhigov.registry.validate import validate_registry

app = typer.Typer(no_args_is_help=True, help="NHI governance for agentic workflows (Entra ID).")
cert_app = typer.Typer(no_args_is_help=True, help="Local certificate credentials (P7: no secrets).")
app.add_typer(cert_app, name="cert")
api_app = typer.Typer(no_args_is_help=True, help="The mock Sensitive Records API (Phase 2).")
app.add_typer(api_app, name="api")

ConfigOpt = Annotated[Path, typer.Option("--config", help="Path to config.yaml")]


@app.callback()
def main(verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False) -> None:
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.INFO if verbose else logging.WARNING
        ),
        logger_factory=structlog.PrintLoggerFactory(file=typer.get_text_stream("stderr")),
    )


@app.command()
def version() -> None:
    """Print the nhigov version."""
    typer.echo(__version__)


@cert_app.command("new")
def cert_new(
    name: Annotated[str, typer.Argument(help="e.g. nhigov-provisioner")],
    days: Annotated[int, typer.Option(help="Lifetime in days")] = DEFAULT_LIFETIME_DAYS,
    cert_dir: Annotated[Path, typer.Option("--dir")] = DEFAULT_CERT_DIR,
    overwrite: bool = False,
) -> None:
    """Generate a self-signed certificate. Upload the .cer to the app registration."""
    cert = generate_self_signed(name, cert_dir, days, overwrite)
    typer.echo(f"private key + cert : {cert.private_pem}   (never commit or share)")
    typer.echo(f"upload to Entra    : {cert.public_cer}")
    typer.echo(f"thumbprint (SHA-1) : {cert.thumbprint_sha1}")
    typer.echo(f"expires            : {cert.not_after:%Y-%m-%d}")


@app.command()
def probe(
    config_path: ConfigOpt = Path("config.yaml"),
    sponsor: Annotated[
        str | None,
        typer.Option(help="Sponsor UPN for write checks (resolved to an object ID by the scanner)"),
    ] = None,
    execute: Annotated[
        bool,
        typer.Option("--execute", help="Run the write checks (creates and deletes probe objects)"),
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", help="Skip the confirmation prompt")] = False,
    output: Annotated[Path, typer.Option()] = Path("docs/capability-matrix.md"),
) -> None:
    """Record which Graph capabilities this tenant supports (CLAUDE.md section 10).

    Read checks always run. Write checks are printed as a plan unless --execute is given.
    """
    if sponsor and ("<" in sponsor or ">" in sponsor):
        raise typer.BadParameter(f"replace the placeholder in --sponsor {sponsor!r}")
    cfg = load_config(config_path)
    run_id = datetime.now(UTC).strftime("%Y%m%d%H%M%S")

    with GraphClient(scanner_token(cfg), base_url=cfg.graph.base_url) as scanner:
        results = run_read_checks({"scanner": scanner}, READ_CHECKS)

        sponsor_id = "<sponsor-object-id>"
        if sponsor:
            sponsor_id = scanner.get(f"users/{sponsor}", params={"$select": "id"})["id"]

    if execute:
        if not sponsor:
            raise typer.BadParameter("--execute needs --sponsor (blueprints require a sponsor)")
        typer.echo(
            "About to CREATE then DELETE an agent identity blueprint, blueprint principal and "
            "agent identity (nhigov-probe-*), and write the app management policy's current "
            "value back to it."
        )
        if not yes:
            typer.confirm("Proceed with tenant writes?", abort=True)
        with GraphClient(provisioner_token(cfg), base_url=cfg.graph.base_url) as prov:
            results += run_write_checks(prov, sponsor_id, run_id, execute=True)
    else:
        results += run_write_checks(None, sponsor_id, run_id, execute=False)

    backend = recommend_backend(results)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_matrix(results, backend, date.today()), encoding="utf-8")

    for r in results:
        mark = "+" if r.outcome is Outcome.OK else "-"
        typer.echo(
            f" {mark} {r.check.id} {r.check.capability:<45} {r.outcome.value}  {redact(r.code)}"
        )
    typer.echo(f"\nRecommended backend: {backend}\nWrote {output}")

    if left := leftover_objects(results, run_id):
        typer.secho(
            "\nCLEANUP FAILED: these probe objects are still in the tenant:",
            fg=typer.colors.RED,
            err=True,
        )
        for name in left:
            typer.secho(f"  {name}", fg=typer.colors.RED, err=True)
        typer.secho(
            "Delete the blueprint in Entra admin center > Entra ID > Agents > Agent blueprints "
            "(this cascades to the rest).",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(2)


@app.command()
def validate(
    registry_dir: Annotated[Path, typer.Option("--registry", help="Registry folder")] = Path(
        "registry"
    ),
    config_path: ConfigOpt = Path("config.yaml"),
    online: Annotated[
        bool, typer.Option("--online", help="Also check sponsors/owners exist (read-only)")
    ] = False,
) -> None:
    """Validate the registry (CLAUDE.md section 6). Exits 1 if there are errors."""
    domain = load_tenant_domain(config_path)
    if online and not domain:
        raise typer.BadParameter("--online needs tenant_domain in config.yaml")
    registry, findings = load_registry(registry_dir, domain or PLACEHOLDER_DOMAIN)
    findings += validate_registry(registry)
    if online:
        cfg = load_config(config_path)
        with GraphClient(scanner_token(cfg), base_url=cfg.graph.base_url) as scanner:
            findings += validate_online(registry, scanner)

    typer.echo(f"registry: {registry.summary()}")
    for f in sorted(findings, key=lambda f: (f.severity != Severity.ERROR, f.rule, f.subject)):
        source = registry.sources.get(f.subject)
        where = f"  ({source.as_posix()})" if source else ""
        color = typer.colors.RED if f.severity is Severity.ERROR else typer.colors.YELLOW
        typer.secho(f"{f.severity.upper():<8}{f.rule}  {f.subject}: {f.message}{where}", fg=color)

    errors = sum(f.severity is Severity.ERROR for f in findings)
    warnings = len(findings) - errors
    if errors:
        typer.secho(f"invalid: {errors} error(s), {warnings} warning(s)", fg=typer.colors.RED)
        raise typer.Exit(1)
    typer.secho(f"valid: 0 errors, {warnings} warning(s)", fg=typer.colors.GREEN)


@api_app.command("probe")
def api_probe(
    config_path: ConfigOpt = Path("config.yaml"),
    registry_dir: Annotated[Path, typer.Option("--registry")] = Path("registry"),
    resource_id: Annotated[str, typer.Option("--resource")] = "res-sensitive-records",
    output: Annotated[Path, typer.Option()] = Path("docs/spikes/resource-registration-probe.md"),
) -> None:
    """Read-only checks before registering the API in Entra (runs as the scanner)."""
    cfg = load_config(config_path)
    registry, findings = load_registry(registry_dir, cfg.tenant_domain or PLACEHOLDER_DOMAIN)
    resource = registry.resources.get(resource_id)
    if resource is None or findings:
        raise typer.BadParameter(f"{resource_id} not loadable; run `nhigov validate` first")

    with GraphClient(scanner_token(cfg), base_url=cfg.graph.base_url) as scanner:
        answers = run_resource_probe(
            scanner, resource, cfg.tenant_id, cfg.control_plane.provisioner.client_id
        )
    app_body = desired_application(resource)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        render_resource_probe(answers, app_body, desired_service_principal("<appId>", resource.id)),
        encoding="utf-8",
    )
    colors = {Verdict.GO: typer.colors.GREEN, Verdict.WARN: typer.colors.YELLOW}
    for a in answers:
        typer.secho(
            f" {a.id} {a.verdict.value:<8} {a.question}\n          {redact(a.detail)}",
            fg=colors.get(a.verdict, typer.colors.RED),
        )
    typer.echo(f"\nWrote {output} (includes the exact bodies apply would send)")
    if any(a.verdict in (Verdict.BLOCKED, Verdict.UNKNOWN) for a in answers):
        raise typer.Exit(1)


@api_app.command("gate-check")
def api_gate_check(
    config_path: ConfigOpt = Path("config.yaml"),
    registry_dir: Annotated[Path, typer.Option("--registry")] = Path("registry"),
) -> None:
    """Ask Entra for API tokens as clients holding no role on it; expect refusal (AADSTS501051).

    Doesn't change anything: it only requests tokens.
    """
    cfg = load_config(config_path)
    registry, _ = load_registry(registry_dir, cfg.tenant_domain or PLACEHOLDER_DOMAIN)
    scope = f"{registry.resources['res-sensitive-records'].identifier_uri}/.default"
    clients = {
        "nhigov-scanner": cfg.control_plane.scanner,
        "nhigov-provisioner": cfg.control_plane.provisioner,
    }
    typer.echo(f"Requesting tokens for {scope} (neither identity holds a role on it)\n")
    with httpx.Client(timeout=30.0) as http:
        results = [
            check_gate(http, cfg.tenant_id, name, c.client_id, c.resolved_cert_path(), scope)
            for name, c in clients.items()
        ]
    for r in results:
        if r.refused:
            typer.secho(f"  PASS {r.identity}: refused by Entra (AADSTS{NOT_ASSIGNED})", fg="green")
        elif r.granted_roles or r.detail == "token issued":
            typer.secho(
                f"  FAIL {r.identity}: token issued, roles={list(r.granted_roles)}", fg="red"
            )
        else:
            codes = ", ".join(f"AADSTS{c}" for c in r.codes) or "?"
            typer.secho(f"  FAIL {r.identity}: refused for another reason ({codes})", fg="red")
        typer.echo(f"       {redact(r.detail)}")
    if not all(r.refused for r in results):
        raise typer.Exit(1)
    typer.echo("\nThe first gate holds: no role assignment, no token.")


@api_app.command("serve")
def api_serve(
    config_path: ConfigOpt = Path("config.yaml"),
    host: str = "127.0.0.1",
    port: int = 8000,
) -> None:
    """Run the Sensitive Records API locally. Tokens are validated against your tenant."""
    import uvicorn  # imported here so other commands don't pay for the web stack

    from sensitive_api.app import RecordStore, create_app
    from sensitive_api.auth import JwksCache, TokenValidator, http_jwks_fetcher
    from sensitive_api.settings import ApiSettings
    from sensitive_api.usage import UsageLog

    cfg = load_config(config_path)
    if cfg.sensitive_api is None:
        raise typer.BadParameter(
            "add a sensitive_api section to config.yaml (see config.example.yaml); "
            "the audience comes from registering res-sensitive-records"
        )
    settings = ApiSettings(
        tenant_id=cfg.tenant_id,
        audience=cfg.sensitive_api.audience,
        token_version=cfg.sensitive_api.token_version,
    )
    validator = TokenValidator(settings, JwksCache(http_jwks_fetcher(settings.jwks_url)))
    api = create_app(validator, RecordStore.from_file(), UsageLog(settings.usage_log))
    typer.echo(f"usage log: {settings.usage_log}")
    uvicorn.run(api, host=host, port=port)


def _managed_resource_plans(
    cfg: Config, registry_dir: Path, state: TenantState
) -> tuple[Registry, list[ResourcePlan]]:
    registry, findings = load_registry(registry_dir, cfg.tenant_domain or PLACEHOLDER_DOMAIN)
    findings += validate_registry(registry)
    if any(f.severity is Severity.ERROR for f in findings):
        raise typer.BadParameter("the registry has errors; run `nhigov validate` first")
    with GraphClient(scanner_token(cfg), base_url=cfg.graph.base_url) as scanner:
        plans = [
            plan_resource(scanner, res, state) for res in registry.resources.values() if res.managed
        ]
    return registry, plans


def _print_plans(plans: list[ResourcePlan]) -> None:
    typer.echo("Scope: resource APIs only (Phase 2). Agents and workflows arrive in Phase 3.\n")
    for p in plans:
        if p.is_noop:
            typer.secho(f"  = {p.resource_id}: no changes", fg=typer.colors.GREEN)
            continue
        if p.record is not None:
            typer.secho(f"  ~ {p.resource_id}: record existing objects in state", fg="yellow")
        for a in p.actions:
            mark, color = ("+", typer.colors.GREEN) if a.op == "create" else ("~", "yellow")
            typer.secho(f"  {mark} {a.op} {a.target} {p.resource_id}", fg=color)
            typer.echo(f"      {a.method} /v1.0/{a.path}")
            for change in a.changes:
                typer.echo(f"      - {change}")
            if a.op == "create":
                body = json.dumps(a.body, indent=2).replace("\n", "\n      ")
                typer.echo(f"      {body}")


@app.command()
def plan(
    config_path: ConfigOpt = Path("config.yaml"),
    registry_dir: Annotated[Path, typer.Option("--registry")] = Path("registry"),
    state_path: Annotated[Path, typer.Option("--state")] = STATE_PATH,
) -> None:
    """Show what `apply` would change in the tenant. Read-only (runs as the scanner)."""
    cfg = load_config(config_path)
    try:
        _, plans = _managed_resource_plans(cfg, registry_dir, load_state(state_path))
    except PlanError as exc:
        typer.secho(f"Plan refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from None
    _print_plans(plans)
    pending = sum(not p.is_noop for p in plans)
    typer.echo(f"\n{pending} resource(s) to change." if pending else "\nNo changes.")


@app.command()
def apply(
    config_path: ConfigOpt = Path("config.yaml"),
    registry_dir: Annotated[Path, typer.Option("--registry")] = Path("registry"),
    state_path: Annotated[Path, typer.Option("--state")] = STATE_PATH,
    yes: Annotated[bool, typer.Option("--yes", help="Skip the confirmation prompt")] = False,
) -> None:
    """Make the tenant match the registry. Re-plans first and asks before writing."""
    cfg = load_config(config_path)
    state = load_state(state_path)
    try:
        _, plans = _managed_resource_plans(cfg, registry_dir, state)
    except PlanError as exc:
        typer.secho(f"Plan refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from None
    _print_plans(plans)
    todo = [p for p in plans if not p.is_noop]
    if not todo:
        typer.echo("\nNo changes.")
        return
    typer.echo("\nThese changes are written as nhigov-provisioner.")
    if not yes:
        typer.confirm("Apply them to the tenant?", abort=True)

    with GraphClient(provisioner_token(cfg), base_url=cfg.graph.base_url) as prov:
        for p in todo:
            for line in apply_plan(prov, p, state, lambda s: save_state(s, state_path)):
                typer.secho(f"  {line}", fg=typer.colors.GREEN)
    typer.echo(
        f"\nState saved to {state_path}. Run `nhigov plan` again: it should show no changes."
    )

    api = state.resources.get("res-sensitive-records")
    if api and _set_api_audience(config_path, api.app_id):
        typer.echo(f"Added sensitive_api.audience to {config_path} for `nhigov api serve`.")


def _set_api_audience(config_path: Path, app_id: str) -> bool:
    """Append the API's audience to config.yaml if it has no sensitive_api section.
    Appending (not re-dumping) keeps the file's comments intact."""
    text = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    if "sensitive_api:" in text:
        return False
    block = (
        "\n# Added by `nhigov apply`: the Sensitive Records API's appId is the `aud` of its\n"
        "# v2 tokens (ADR-009).\n"
        f'sensitive_api:\n  audience: "{app_id}"\n  token_version: 2\n'
    )
    config_path.write_bytes((text.rstrip("\n") + "\n" + block).encode("utf-8"))
    return True


def run() -> None:
    """Console entry point: show auth failures as a short message, not a traceback."""
    try:
        app()
    except TokenAcquisitionError as exc:
        typer.secho(f"Authentication failed: {exc}", fg=typer.colors.RED, err=True)
        raise SystemExit(1) from None


if __name__ == "__main__":
    run()
