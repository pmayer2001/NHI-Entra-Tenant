# ADR-014: GitHub Actions runtime with federated credentials

**Status:** Accepted (2026-11-07). Live verification pending: an agent job must run in CI with no secrets in the repo.

## Context
ADR-005 chose certificates for local runs and GitHub OIDC for CI. Agents run where the registry says (`runtimes:`), and CI is where a credential is most often leaked: a secret in a repository or workflow variable is readable by anyone who can change a workflow. A federated credential removes the thing to leak: the job proves who it is with a token GitHub mints for that job only.

## Decision
- **Trust one environment per workflow.** Every job bound to a GitHub *environment* gets an OIDC token whose subject is `repo:<owner>/<repo>:environment:<name>`. nhigov names environments after workflows and creates a federated credential that trusts exactly that subject (issuer `https://token.actions.githubusercontent.com`, audience `api://AzureADTokenExchange`). Environment-bound subjects, not branch ones, because an environment can carry protection rules (required reviewers, allowed branches) and its own variables.
- **Where the credential goes follows ADR-003.** Agent ID: on the agent's *blueprint*, since agent identities hold no credentials (`POST /applications/{id}/microsoft.graph.agentIdentityBlueprint/federatedIdentityCredentials`, `AgentIdentityBlueprint.AddRemoveCreds.All`). Service-principal backend: on the NHI's own app registration.
- **The reconciler manages them from the registry.** A (workflow, agent) pair whose `runtimes` include `github-actions` gets `gh-<workflow>` on its blueprint or app while the NHI is enabled; a suspended, retired or lifecycle-held workflow loses it on the next `apply`. A changed repository replaces it. Credentials not named `gh-*` are reported, never touched. The control plane stays report-only (ADR-010), so the scanner's credential is added by hand; `nhigov ci vars` prints its exact subject.
- **Token flow in CI.** The job requests its GitHub token (needs `permissions: id-token: write`) and presents it as the client assertion where a local run presents a certificate-signed one: T1 as the blueprint with `fmi_path`, then T2 as the agent identity, unchanged.
- **IDs come from environment variables, not the repo.** Tenant, client and object IDs aren't credentials, but they stay out of git. `nhigov ci vars` prints what each GitHub environment needs; the nightly scan also receives the state file as `NHIGOV_STATE_JSON`, so it can tell managed NHIs from shadow ones.
- **The registry decides where an agent may run.** `nhigov agent run` refuses to run in GitHub Actions unless the pair lists `github-actions`, and locally unless it lists `local`.
- **Public logs show counts only.** `nhigov scan --summary-only` prints counts by rule and fails on critical/high findings. Object names and details describe the tenant's security posture and stay in local reports.

## Why
No secret exists to rotate or leak, and the credential is useless outside a job in that environment of that repository. Managing it through plan/apply keeps CI sign-in paths reviewable in the same diff as everything else, and removes them when a workflow stops being active.

## Alternatives rejected
- **A certificate or client secret stored as a GitHub secret:** a stealable, long-lived credential (P7), readable by any workflow change that echoes it.
- **Branch-based subjects (`ref:refs/heads/main`):** any workflow on that branch could sign in as any NHI trusted that way; environments scope it to one workflow's jobs.
- **Adding the credentials by hand:** they'd drift from the registry, and nothing would remove them when a workflow is retired.

## Consequences
- **Blast radius (ADR-003) reaches CI.** The credential sits on the shared blueprint, so a job in `wf-claims-triage`'s environment can request T1 for *any* agent identity of `bp-agent-summarizer`, including other workflows' agents. Authorization stays per agent (each holds only its own roles), but sign-in reach is the blueprint's. Mitigations: environment protection rules, one blueprint per trust zone, NHI-011's limit on credentials per blueprint.
- A blueprint used locally and in CI holds two credentials, matching `max_blueprint_credentials: 2`.
- Usage logged by the API inside a CI job stays in that job; local usage analytics (ADR-013) doesn't see CI calls.
