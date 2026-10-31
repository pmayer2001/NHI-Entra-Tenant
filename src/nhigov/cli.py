"""`nhigov` command-line entry point."""

from __future__ import annotations

import logging
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated

import structlog
import typer

from nhigov import __version__
from nhigov.certs import DEFAULT_CERT_DIR, DEFAULT_LIFETIME_DAYS, generate_self_signed
from nhigov.config import load_config
from nhigov.graph.auth import TokenAcquisitionError, provisioner_token, scanner_token
from nhigov.graph.client import GraphClient
from nhigov.probe.checks import READ_CHECKS, Outcome
from nhigov.probe.report import redact, render_matrix
from nhigov.probe.runner import (
    leftover_objects,
    recommend_backend,
    run_read_checks,
    run_write_checks,
)

app = typer.Typer(no_args_is_help=True, help="NHI governance for agentic workflows (Entra ID).")
cert_app = typer.Typer(no_args_is_help=True, help="Local certificate credentials (P7: no secrets).")
app.add_typer(cert_app, name="cert")

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


def run() -> None:
    """Console entry point: show auth failures as a short message, not a traceback."""
    try:
        app()
    except TokenAcquisitionError as exc:
        typer.secho(f"Authentication failed: {exc}", fg=typer.colors.RED, err=True)
        raise SystemExit(1) from None


if __name__ == "__main__":
    run()
