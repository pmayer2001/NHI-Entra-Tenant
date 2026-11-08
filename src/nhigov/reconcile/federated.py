"""Federated identity credentials for GitHub Actions (ADR-005, ADR-014).

A federated credential says "trust a token from this issuer, with exactly this
subject, as a sign-in for this app". GitHub issues each job an OIDC token whose
`sub` names the repo and, for jobs bound to an environment, the environment:
`repo:<owner>@<owner_id>/<repo>@<repo_id>:environment:<name>` (repos created since
mid-2026; the numeric IDs survive renames and can't be reclaimed by someone who
re-registers a deleted name) or `repo:<owner>/<repo>:environment:<name>` (older).
nhigov names environments after workflows, so a credential bound to
`environment:wf-claims-triage` admits only jobs running in that environment, and
no secret exists anywhere.

Where the credential goes follows ADR-003: on the *blueprint* for Agent ID (the
agent identity has no credentials of its own), on the NHI's own app registration
for the service-principal backend. Credentials nhigov manages are named
`gh-<workflow id>`; others are reported, never touched.
"""

from __future__ import annotations

from dataclasses import dataclass

from nhigov.reconcile.engine import IdentityPlan, JsonDict, PlanContext, Step

GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
EXCHANGE_AUDIENCE = "api://AzureADTokenExchange"
PREFIX = "gh-"


@dataclass(frozen=True)
class WantedFic:
    workflow_id: str
    subject_repo: str  # GitHubSettings.subject_repo

    @property
    def name(self) -> str:
        return f"{PREFIX}{self.workflow_id}"

    @property
    def subject(self) -> str:
        return f"repo:{self.subject_repo}:environment:{self.workflow_id}"

    def body(self) -> JsonDict:
        return {
            "name": self.name,
            "issuer": GITHUB_ISSUER,
            "subject": self.subject,
            "audiences": [EXCHANGE_AUDIENCE],
            "description": f"nhigov: GitHub Actions environment {self.workflow_id}",
        }


def _matches(found: JsonDict, want: WantedFic) -> bool:
    return (
        found.get("issuer") == GITHUB_ISSUER
        and found.get("subject") == want.subject
        and list(found.get("audiences") or []) == [EXCHANGE_AUDIENCE]
    )


def plan_fics(
    ctx: PlanContext,
    plan: IdentityPlan,
    *,
    kind: str,  # "blueprint" or "spnhi": selects the apply handler and the path
    key: str,
    label: str,
    path: str | None,  # .../federatedIdentityCredentials, or None if the app is new
    workflows: list[str],
) -> None:
    """Add missing `gh-*` credentials, replace changed ones, remove ones no longer wanted."""
    if workflows and not ctx.github_subject_repo:
        plan.notes.append(
            f"{label}: {', '.join(workflows)} run in GitHub Actions, but config has no "
            "github.repository; no federated credential planned"
        )
        return
    wanted = {w.name: w for w in (WantedFic(wf, ctx.github_subject_repo or "") for wf in workflows)}
    existing = ctx.graph.list_all(path) if path else []
    for fic in existing:
        name = fic.get("name") or ""
        want = wanted.get(name)
        if want is not None and _matches(fic, want):
            del wanted[name]
            continue
        if not name.startswith(PREFIX):
            plan.notes.append(
                f"{label}: federated credential {name!r} ({fic.get('subject')}) isn't "
                "managed by nhigov; review it (it can mint tokens like any other credential)"
            )
            continue
        reason = "subject changed" if want is not None else "workflow no longer runs in GitHub"
        plan.steps.append(
            Step(
                f"{kind}.fic-remove",
                key,
                f"federated credential {name} on {label} ({reason})",
                f"DELETE /v1.0/<{label}>/federatedIdentityCredentials/{fic['id']}",
                {"id": fic["id"], "name": name},
            )
        )
    for want in wanted.values():
        plan.steps.append(
            Step(
                f"{kind}.fic-add",
                key,
                f"federated credential {want.name} on {label}",
                f"POST /v1.0/<{label}>/federatedIdentityCredentials",
                want.body(),
                (f"subject: {want.subject}",),
            )
        )
