"""`nhigov ci vars`: what each GitHub environment needs to run nhigov in Actions.

None of it is secret: tenant, client and object IDs identify things, they don't
authenticate anything (the job's OIDC token does that). They still stay out of the
repo, so they live in GitHub *environment variables*, which only the jobs bound to
that environment receive.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from nhigov.config import load_config
from nhigov.reconcile.federated import GITHUB_ISSUER, WantedFic
from nhigov.reconcile.state import STATE_ENV, STATE_PATH, load_state
from nhigov.registry.loader import PLACEHOLDER_DOMAIN, load_registry
from nhigov.registry.models import IdentityType, Runtime

ci_app = typer.Typer(no_args_is_help=True, help="GitHub Actions setup (federated sign-in).")


def var_prefix(agent_id: str) -> str:
    """agent-summarizer -> AGENT_SUMMARIZER (GitHub variable names: letters, digits, _)."""
    return agent_id.upper().replace("-", "_")


@ci_app.command("vars")
def vars_cmd(
    config_path: Annotated[Path, typer.Option("--config")] = Path("config.yaml"),
    registry_dir: Annotated[Path, typer.Option("--registry")] = Path("registry"),
    state_path: Annotated[Path, typer.Option("--state")] = STATE_PATH,
) -> None:
    """Print the variables to set in each GitHub environment (Settings > Environments)."""
    cfg = load_config(config_path)
    registry, _ = load_registry(registry_dir, cfg.tenant_domain or PLACEHOLDER_DOMAIN)
    state = load_state(state_path)
    if not cfg.github.repository:
        raise typer.BadParameter("set github.repository in config.yaml first")
    envs: dict[str, dict[str, str]] = {}
    manual: list[str] = []
    for wf in sorted(registry.workflows.values(), key=lambda w: w.id):
        for wa in wf.agents:
            if Runtime.GITHUB_ACTIONS not in wa.runtimes:
                continue
            env = envs.setdefault(wf.id, {"NHIGOV_TENANT_ID": cfg.tenant_id})
            if registry.agents[wa.ref].identity_type is IdentityType.APPLICATION:
                # Control plane: report-only, so its federated credential is added by hand.
                cp = cfg.cp
                env |= {
                    "NHIGOV_TENANT_DOMAIN": cfg.tenant_domain or "",
                    "NHIGOV_IDENTITY_BACKEND": cfg.identity_backend.value,
                    "NHIGOV_SCANNER_CLIENT_ID": cp.scanner.client_id,
                    "NHIGOV_PROVISIONER_CLIENT_ID": cp.provisioner.client_id,
                    STATE_ENV: state.model_dump_json(),
                }
                fic = WantedFic(wf.id, cfg.github.repository)
                manual.append(
                    f"{wa.ref}: add a federated credential by hand (Certificates & secrets > "
                    f"Federated credentials > Other issuer): issuer {GITHUB_ISSUER}, "
                    f"subject {fic.subject}, name {fic.name}"
                )
                continue
            rec = state.nhis.get(f"{wf.id}/{wa.ref}")
            if rec is None or rec.app_id is None:
                manual.append(f"{wf.id}/{wa.ref}: not provisioned yet; run `nhigov apply` first")
                continue
            prefix = var_prefix(wa.ref)
            if cfg.sensitive_api:
                env["NHIGOV_API_AUDIENCE"] = cfg.sensitive_api.audience
            env[f"{prefix}_BACKEND"] = rec.backend
            env[f"{prefix}_CLIENT_ID"] = rec.app_id
            if rec.blueprint:
                bp = state.blueprints.get(rec.blueprint)
                if bp:
                    env[f"{prefix}_BLUEPRINT_APP_ID"] = bp.app_id

    typer.echo(f"Repository: {cfg.github.repository}")
    typer.echo("Create each environment under Settings > Environments, then add these variables")
    typer.echo("(Variables, not Secrets: none of them is a credential).\n")
    for name, values in envs.items():
        typer.secho(f"Environment: {name}", bold=True)
        for var, value in sorted(values.items()):
            shown = value if var != STATE_ENV else f"<{len(value)} chars of JSON; see below>"
            typer.echo(f"  {var} = {shown}")
        typer.echo()
    if any(STATE_ENV in v for v in envs.values()):
        typer.echo(f"{STATE_ENV} (one line, paste as-is):")
        typer.echo(state.model_dump_json())
        typer.echo()
    for line in manual:
        typer.secho(f"! {line}", fg="yellow")
