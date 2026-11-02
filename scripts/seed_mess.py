"""Plant a reproducible set of misconfigured NHIs, so discovery can be shown to find them.

    uv run python scripts/seed_mess.py plant                # dry run: prints the plan
    uv run python scripts/seed_mess.py plant --execute      # writes (asks first)
    uv run nhigov scan
    uv run python scripts/seed_mess.py verify               # every seed found, nothing else
    uv run python scripts/seed_mess.py cleanup --execute    # removes everything it planted

Phase 5 acceptance (CLAUDE.md §12): every seeded problem is found, and nothing else.
`plant` records a baseline scan first, so "nothing else" means nothing beyond what
was already there.

Safety (CLAUDE.md §14): writes need --execute plus confirmation, run as the
provisioner. Every app is tagged `nhigov:seed` (agent identities can't be tagged,
so they're named `seed-...`). The one client secret expires in 6 days and its value
is discarded unread. Certificates are public keys only: no private key is kept, so
nobody can sign in as a seed. The Graph-admin seed has no credential at all.
"""

from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import typer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from nhigov.config import Config, load_config
from nhigov.discovery.rules.base import Finding
from nhigov.discovery.scan import collect_inventory, evaluate
from nhigov.graph.auth import provisioner_token, scanner_token
from nhigov.graph.client import GraphClient, GraphError
from nhigov.reconcile.engine import send
from nhigov.reconcile.resources import role_id
from nhigov.reconcile.state import load_state
from nhigov.registry.loader import PLACEHOLDER_DOMAIN, load_registry

app = typer.Typer(no_args_is_help=True, add_completion=False)

SEED_TAG = "nhigov:seed"
SEED_STATE = Path("reports/seed-state.json")  # reports/ is git-ignored: real object IDs
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
RES = "res-sensitive-records"
SUMMARIZER = "wf-claims-triage/agent-summarizer"

PLAN = """
  S1 seed-secret-app     app + SP with a client secret (expires in 6 days)   NHI-001 002 003
  S2 seed-longcert-app   app + SP with a 2-year certificate (public only)    NHI-001 002 004
  S3 seed-graph-admin    app + SP, no credential, Directory.ReadWrite.All    NHI-001 002 005
  S4 seed-dir-role       app + SP; YOU assign "Directory Readers" (manual)   NHI-001 002 006
  S5 seed-shared-sp      app + SP tagged with two workflows                  NHI-001 002 008
  S6 seed-bp-many-creds  blueprint with 3 certificates (public only)         NHI-001 011
  S7 seed-orphan-agent   blueprint + principal + agent identity, then the
                         blueprint is deleted (deletion doesn't cascade)     NHI-001 013
  S8 drift               Records.Annotate added to the real summarizer       NHI-007
  S9 human-only role     give an app Records.Read.All (User-only): Graph accepts it  NHI-009
"""


@dataclass
class Expected:
    rule: str
    object_id: str
    name: str
    manual: bool = False  # depends on a step Paul does by hand (S4)


@dataclass
class SeedState:
    planted_at: str = ""
    baseline: list[str] = field(default_factory=list)  # finding keys before planting
    apps: dict[str, str] = field(default_factory=dict)  # name -> application object ID
    service_principals: dict[str, str] = field(default_factory=dict)  # name -> SP ID
    agent_identities: dict[str, str] = field(default_factory=dict)
    blueprint_principals: dict[str, str] = field(default_factory=dict)
    assignments: list[dict[str, str]] = field(default_factory=list)  # {principal, id}
    expected: list[Expected] = field(default_factory=list)
    evidence: dict[str, str] = field(default_factory=dict)

    def save(self) -> None:
        SEED_STATE.parent.mkdir(parents=True, exist_ok=True)
        SEED_STATE.write_bytes(json.dumps(asdict(self), indent=2).encode("utf-8"))

    @classmethod
    def load(cls) -> SeedState:
        data = json.loads(SEED_STATE.read_text(encoding="utf-8"))
        data["expected"] = [Expected(**e) for e in data["expected"]]
        return cls(**data)


def public_cert(name: str, days: int) -> dict[str, str]:
    """A keyCredential for a fresh self-signed certificate. The private key is
    generated, used to sign the certificate, and dropped: nothing can sign in with it."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=days))
        .sign(key, hashes.SHA256())
    )  # fmt: skip
    der = cert.public_bytes(serialization.Encoding.DER)
    return {"type": "AsymmetricX509Cert", "usage": "Verify", "displayName": f"seed {days}d",
            "key": base64.b64encode(der).decode()}  # fmt: skip


class Planter:
    def __init__(self, cfg: Config, prov: GraphClient, scanner: GraphClient, s: SeedState):
        self.cfg, self.prov, self.scanner, self.s = cfg, prov, scanner, s

    def expect(self, rules: str, object_id: str, name: str, manual: bool = False) -> None:
        for r in rules.split():
            self.s.expected.append(Expected(f"NHI-{r}", object_id, name, manual))
        self.s.save()

    def app_and_sp(self, name: str, **body: Any) -> tuple[str, str]:
        tags = [SEED_TAG, *body.pop("tags", [])]
        a = self.prov.post("applications", {"displayName": name, "signInAudience": "AzureADMyOrg",
                                            "tags": tags, **body})  # fmt: skip
        self.s.apps[name] = a["id"]
        self.s.save()
        sp = send(self.prov, "POST", "servicePrincipals", {"appId": a["appId"]})
        self.s.service_principals[name] = sp["id"]
        self.s.save()
        typer.echo(f"  created {name}")
        return a["id"], sp["id"]

    def blueprint(self, name: str, sponsor_id: str) -> dict[str, Any]:
        bp = self.prov.post("applications", {
            "@odata.type": "Microsoft.Graph.AgentIdentityBlueprint", "displayName": name,
            "tags": [SEED_TAG],
            "sponsors@odata.bind": [f"https://graph.microsoft.com/v1.0/users/{sponsor_id}"],
        })  # fmt: skip
        self.s.apps[name] = bp["id"]
        self.s.save()
        return bp

    def assign(self, principal: str, resource: str, role: str) -> None:
        a = send(self.prov, "POST", f"servicePrincipals/{principal}/appRoleAssignments",
                 {"principalId": principal, "resourceId": resource, "appRoleId": role})  # fmt: skip
        self.s.assignments.append({"principal": principal, "id": a["id"]})
        self.s.save()

    def plant(self, sponsor_id: str) -> None:
        state = load_state()
        res_sp = state.resources[RES].service_principal_id
        graph_sp = self.scanner.get(
            "servicePrincipals",
            params={"$filter": f"appId eq '{GRAPH_APP_ID}'", "$select": "id,appRoles"},
        )["value"][0]
        dir_rw = next(
            r["id"] for r in graph_sp["appRoles"] if r["value"] == "Directory.ReadWrite.All"
        )

        # S1: a client secret. Its value comes back once in the response and is dropped here.
        app_id, sp = self.app_and_sp("seed-secret-app")
        end = (datetime.now(UTC) + timedelta(days=6)).isoformat()
        try:
            response = send(
                self.prov,
                "POST",
                f"applications/{app_id}/addPassword",
                {"passwordCredential": {"displayName": "seed (6 days)", "endDateTime": end}},
            )
        except GraphError as exc:
            # Phase 6: the tenant app management policy blocks new secrets. That's P7
            # prevented rather than detected, so there's no NHI-003 to find.
            self.s.evidence["S1"] = f"secret refused by policy: {exc.status} {exc.code}"
            self.expect("001 002", sp, "seed-secret-app")
            typer.echo(f"  S1 secret: {self.s.evidence['S1']}")
            response = {}
        else:
            self.expect("003", sp, "seed-secret-app")
        response.pop("secretText", None)
        del response
        if "S1" not in self.s.evidence:
            self.expect("001 002", sp, "seed-secret-app")

        # S2: a certificate valid for two years (policy: 180 days).
        _, sp = self.app_and_sp("seed-longcert-app", keyCredentials=[public_cert("seed", 730)])
        self.expect("001 002 004", sp, "seed-longcert-app")

        # S3: tenant-wide write permission on a principal nobody can sign in as.
        _, sp = self.app_and_sp("seed-graph-admin")
        self.assign(sp, graph_sp["id"], dir_rw)
        self.expect("001 002 005", sp, "seed-graph-admin")

        # S4: directory role, assigned by Paul (the provisioner can't, by design).
        _, sp = self.app_and_sp("seed-dir-role")
        self.expect("001 002", sp, "seed-dir-role")
        self.expect("006", sp, "seed-dir-role", manual=True)

        # S5: one SP claimed by two workflows.
        _, sp = self.app_and_sp(
            "seed-shared-sp", tags=["nhigov:workflow=wf-claims-triage",
                                    "nhigov:workflow=wf-sp-backend-demo"])  # fmt: skip
        self.expect("001 002 008", sp, "seed-shared-sp")

        # S6: a blueprint with three credentials (policy: one per runtime, 2).
        bp = self.blueprint("seed-bp-many-creds", sponsor_id)
        creds = [public_cert(f"seed-{i}", 90) for i in range(3)]
        send(self.prov, "PATCH",
             f"applications/{bp['id']}/microsoft.graph.agentIdentityBlueprint",
             {"keyCredentials": creds})  # fmt: skip
        typer.echo("  created seed-bp-many-creds")
        self.expect("001 011", bp["id"], "seed-bp-many-creds")

        # S7: delete a blueprint and leave its agent identity behind.
        bp = self.blueprint("seed-orphan-bp", sponsor_id)
        principal = send(self.prov, "POST",
                         "servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal",
                         {"appId": bp["appId"]})  # fmt: skip
        self.s.blueprint_principals["seed-orphan-bp"] = principal["id"]
        agent = send(self.prov, "POST", "servicePrincipals/microsoft.graph.agentIdentity", {
            "displayName": "seed-orphan-agent", "agentIdentityBlueprintId": bp["appId"],
            "sponsors@odata.bind": [f"https://graph.microsoft.com/v1.0/users/{sponsor_id}"],
        })  # fmt: skip
        self.s.agent_identities["seed-orphan-agent"] = agent["id"]
        self.s.save()
        self.prov.delete(f"applications/{bp['id']}")
        self.s.apps.pop("seed-orphan-bp")
        self.s.save()
        typer.echo("  created seed-orphan-agent and deleted its blueprint")
        self.expect("001 013", agent["id"], "seed-orphan-agent")
        # Observed 2026-11-01: the blueprint *principal* survives its blueprint too, as a
        # shadow SP owned only by the provisioner. Expected, so `verify` counts it.
        self.expect("001 002", principal["id"], "seed-orphan-bp (blueprint principal)")

        # S8: drift on a real managed NHI. `nhigov apply` would revoke it.
        summarizer = state.nhis[SUMMARIZER].principal_id
        assert summarizer and res_sp
        self.assign(summarizer, res_sp, role_id(RES, "Records.Annotate"))
        typer.echo("  added Records.Annotate to the summarizer (drift)")
        self.expect("007", summarizer, "nhi-wf-claims-triage-agent-summarizer")

        # S9: give an app a User-only role. Observed 2026-11-01: Graph *accepts* it, despite
        # allowedMemberTypes ["User"]. So NHI-009 is a live control, and the API's own check
        # (app tokens never reach /full) is what actually protects the data.
        secret_sp = self.s.service_principals["seed-secret-app"]
        try:
            self.assign(secret_sp, res_sp, role_id(RES, "Records.Read.All"))
            self.s.evidence["S9"] = "accepted: Graph let an app hold a User-only role"
            self.expect("009", secret_sp, "seed-secret-app")
        except GraphError as exc:
            self.s.evidence["S9"] = f"refused: {exc.status} {exc.code}"
        self.s.save()
        typer.echo(f"  S9 human-only role: {self.s.evidence['S9']}")


def _clients(cfg: Config) -> tuple[GraphClient, GraphClient]:
    return (GraphClient(provisioner_token(cfg), base_url=cfg.graph.base_url),
            GraphClient(scanner_token(cfg), base_url=cfg.graph.base_url))  # fmt: skip


def _scan(cfg: Config) -> list[Finding]:
    registry, _ = load_registry(Path("registry"), cfg.tenant_domain or PLACEHOLDER_DOMAIN)
    state = load_state()
    now = datetime.now(UTC)
    return evaluate(collect_inventory(cfg, registry, state, now), registry, state, now)


@app.command()
def plant(
    execute: Annotated[bool, typer.Option("--execute", help="Write to the tenant")] = False,
    yes: Annotated[bool, typer.Option("--yes")] = False,
) -> None:
    """Plant the seeds (dry run unless --execute)."""
    typer.echo("Seeds (each tagged nhigov:seed; run `cleanup --execute` to remove):" + PLAN)
    if not execute:
        typer.echo("Dry run: nothing written. Re-run with --execute to plant.")
        return
    if SEED_STATE.exists():
        raise typer.BadParameter(f"{SEED_STATE} exists: run `cleanup --execute` first")
    if not yes:
        typer.confirm("Plant these misconfigured NHIs in the tenant?", abort=True)
    cfg = load_config()
    s = SeedState(planted_at=datetime.now(UTC).isoformat())
    s.baseline = sorted(f.key for f in _scan(cfg))
    s.save()
    typer.echo(f"baseline scan: {len(s.baseline)} existing finding(s) recorded")
    prov, scanner = _clients(cfg)
    with prov, scanner:
        sponsor = scanner.get(f"users/paul@{cfg.tenant_domain}", params={"$select": "id"})["id"]
        Planter(cfg, prov, scanner, s).plant(sponsor)
    typer.secho(
        "\nManual step for S4 (the provisioner may not assign directory roles, §14.3):\n"
        "  Entra admin center > Identity > Roles & admins > Directory Readers >\n"
        "  Add assignments > select the enterprise app 'seed-dir-role' > Add.\n"
        "Then: uv run nhigov scan, and uv run python scripts/seed_mess.py verify",
        fg=typer.colors.YELLOW,
    )


@app.command()
def verify(
    findings_file: Annotated[Path | None, typer.Option(help="Defaults to today's scan")] = None,
) -> None:
    """Compare the latest scan with what was planted."""
    s = SeedState.load()
    path = findings_file or Path(f"reports/findings-{datetime.now(UTC):%Y-%m-%d}.json")
    found = {f["key"]: f for f in json.loads(path.read_text(encoding="utf-8"))}
    expected = {f"{e.rule}:{e.object_id}": e for e in s.expected}
    missing = [e for k, e in expected.items() if k not in found]
    unexpected = [f for k, f in found.items() if k not in expected and k not in s.baseline]
    for e in sorted(expected.values(), key=lambda e: (e.name, e.rule)):
        ok = f"{e.rule}:{e.object_id}" in found
        typer.secho(f"  {'FOUND  ' if ok else 'MISSING'} {e.rule}  {e.name}"
                    f"{'  (needs your manual step)' if e.manual and not ok else ''}",
                    fg="green" if ok else "red")  # fmt: skip
    for f in unexpected:
        typer.secho(f"  EXTRA   {f['rule']}  {f['display_name']}: {f['message']}", fg="red")
    typer.echo(f"\nS9 evidence: {s.evidence.get('S9', 'not run')}")
    if missing or unexpected:
        typer.secho(f"\n{len(missing)} missing, {len(unexpected)} unexpected", fg="red")
        raise typer.Exit(1)
    typer.secho(f"\nAll {len(expected)} seeded findings found, nothing else. "
                "Phase 5 acceptance met.", fg="green")  # fmt: skip


@app.command()
def cleanup(
    execute: Annotated[bool, typer.Option("--execute")] = False,
    yes: Annotated[bool, typer.Option("--yes")] = False,
) -> None:
    """Remove everything `plant` created (dry run unless --execute)."""
    if not SEED_STATE.exists():
        typer.echo("Nothing planted.")
        return
    s = SeedState.load()
    typer.echo(f"Would delete apps {sorted(s.apps)}, "
               f"agent identities {sorted(s.agent_identities)}, "
               f"blueprint principals {sorted(s.blueprint_principals)}, "
               f"and {len(s.assignments)} role assignment(s).")  # fmt: skip
    if not execute:
        typer.echo("Dry run: nothing deleted. Re-run with --execute.")
        return
    if not yes:
        typer.confirm("Delete the seeds?", abort=True)
    cfg = load_config()
    prov, _ = _clients(cfg)
    failures = []
    with prov:
        for a in s.assignments:  # drift on the real summarizer, first
            try:
                prov.delete(f"servicePrincipals/{a['principal']}/appRoleAssignments/{a['id']}")
            except GraphError as exc:
                if exc.status != 404:
                    failures.append(str(exc))
        targets = [
            *(f"servicePrincipals/{i}" for i in s.agent_identities.values()),
            # Typed-cast URL per the docs (needs AgentIdentityBlueprintPrincipal.DeleteRestore.All
            # or ownership); the plain URL got 403 on 2026-11-01.
            *(
                f"servicePrincipals/{i}/microsoft.graph.agentIdentityBlueprintPrincipal"
                for i in s.blueprint_principals.values()
            ),
            *(f"applications/{i}" for i in s.apps.values()),  # deleting an app removes its SP
        ]
        for path in targets:
            try:
                prov.delete(path)
                typer.echo(f"  deleted {path.split('/')[0]} {path.split('/')[1][:8]}...")
            except GraphError as exc:
                if exc.status != 404:
                    failures.append(str(exc))
    if failures:
        typer.secho("Some deletes failed (seed-state kept for a retry):", fg="red")
        for f in failures:
            typer.secho(f"  {f}", fg="red")
        raise typer.Exit(1)
    SEED_STATE.unlink()
    typer.secho("Seeds removed. A directory role assigned by hand went with its SP.", fg="green")


if __name__ == "__main__":
    app()
