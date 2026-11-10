"""`nhigov usage analyze`: which granted roles were never used (L3, NHI-012).

Offline: it reads the API's usage log, the registry and the state file. No Graph call.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from nhigov.config import load_owner, load_tenant_domain
from nhigov.lifecycle.state import load_lifecycle
from nhigov.reconcile.state import STATE_PATH, load_state
from nhigov.registry.findings import Severity
from nhigov.registry.loader import PLACEHOLDER_DOMAIN, PLACEHOLDER_OWNER, load_registry
from nhigov.registry.validate import validate_registry
from nhigov.usage.analyze import Verdict, analyze, load_events, parse_window, write_report

usage_app = typer.Typer(no_args_is_help=True, help="Unused-permission analytics (L3).")

USAGE_LOG = Path("services/sensitive_api/usage.log")
COLORS = {Verdict.UNUSED: "yellow", Verdict.DORMANT: "yellow", Verdict.OK: "green"}


@usage_app.command("analyze")
def analyze_cmd(
    window: Annotated[str, typer.Option(help="How far back to look: 30d, 12h")] = "30d",
    log: Annotated[Path, typer.Option(help="The API's JSONL usage log")] = USAGE_LOG,
    as_of: Annotated[
        datetime | None,
        typer.Option(
            "--as-of",
            formats=["%Y-%m-%d", "%Y-%m-%dT%H:%M"],
            help="Pretend now is this time (demos; assumes the log is complete)",
        ),
    ] = None,
    config_path: Annotated[Path, typer.Option("--config")] = Path("config.yaml"),
    registry_dir: Annotated[Path, typer.Option("--registry")] = Path("registry"),
    state_path: Annotated[Path, typer.Option("--state")] = STATE_PATH,
    out_dir: Annotated[Path, typer.Option("--out")] = Path("reports"),
) -> None:
    """Compare each NHI's granted roles with the roles its calls used (granted - used)."""
    try:
        span = parse_window(window)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
    registry, loaded = load_registry(
        registry_dir,
        load_tenant_domain(config_path) or PLACEHOLDER_DOMAIN,
        load_owner(config_path) or PLACEHOLDER_OWNER,
    )
    if any(f.severity is Severity.ERROR for f in loaded + validate_registry(registry)):
        raise typer.BadParameter("the registry has errors; run `nhigov validate` first")
    now = as_of.replace(tzinfo=UTC) if as_of else datetime.now(UTC)
    events = load_events(log)
    report = analyze(events, registry, load_state(state_path), span, now, load_lifecycle().holds())

    if report.coverage_start is None:
        typer.secho(f"No usage events in {log} before {now:%Y-%m-%d %H:%M}.", fg="yellow")
    else:
        typer.echo(
            f"Window {window} as of {now:%Y-%m-%d %H:%M} UTC; the log covers "
            f"{report.span.total_seconds() / 3600:.1f}h of it ({len(events)} events in {log})."
        )
    for r in report.results:
        used = ", ".join(f"{role} x{n}" for role, n in sorted(r.used.items())) or "nothing"
        typer.secho(f"\n  {r.verdict.value:<9} {r.key} ({r.cadence})", fg=COLORS.get(r.verdict))
        typer.echo(f"            granted: {', '.join(x for rs in r.granted.values() for x in rs)}")
        typer.echo(f"            used:    {used}")
        if r.note:
            typer.echo(f"            note:    {r.note}")
    if report.unattributed_calls:
        typer.secho(
            f"\n{report.unattributed_calls} call(s) came from unregistered callers.",
            fg="yellow",
        )

    findings = report.findings
    typer.echo(f"\n{len(findings)} NHI-012 finding(s)")
    for f in findings:
        typer.secho(f"  medium   {f.rule}  {f.display_name}: {f.message}", fg="yellow")
        typer.echo(f"           fix: {f.remediation}")
    typer.echo(f"\nWrote {write_report(report, out_dir).as_posix()}")
