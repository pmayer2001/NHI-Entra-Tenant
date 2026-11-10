# Setting up nhigov on your own tenant

This guide takes you from nothing to a working setup:
- a free Entra ID tenant, with its own provisioner and scanner;
- agents with their own identities, calling a protected API;
- discovery, lifecycle and usage analytics running against that tenant;
- optionally, agents and a nightly scan in GitHub Actions with no secrets.

Everything after the one-time portal steps goes through `nhigov`. Read [docs/principles.md](principles.md) first if you want the rules the tool enforces.

**Cost.** Everything here runs on **Microsoft Entra ID Free** and GitHub's free tier. You create no Azure resources; Graph API calls are free. Set the budget alert in step 1 anyway.

**What stays out of git.** These files are git-ignored, so your tenant's identifiers never reach the repo:
- `config.yaml` (tenant ID, client IDs, domain);
- `state/` (object IDs of everything nhigov created);
- `reports/`;
- the API's `usage.log`;
- your private keys in `~/.nhigov/certs/`.

Keep it that way if you publish a fork.

---

## What you'll end up with

| In Entra | Type | Created by | Purpose |
|---|---|---|---|
| `nhigov-scanner` | App registration + service principal | You (portal) | Read-only: `plan`, `scan`, lifecycle status |
| `nhigov-provisioner` | App registration + service principal | You (portal) | Writes: `apply`, lifecycle actions, certificate rotation |
| Your owner user, e.g. `alice@<tenant>.onmicrosoft.com` | Member user | You (portal) | Human sponsor of every example workflow |
| `test-departing-sponsor@<tenant>` | Member user (optional) | You (portal) | Plays an employee who leaves, for the lifecycle demo |
| `res-sensitive-records` | App registration + service principal | `nhigov apply` | The mock API's identity; defines the app roles agents get |
| `bp-agent-summarizer`, `bp-agent-router` | Agent identity blueprints (+ blueprint principals) | `nhigov apply` | Reusable agent definitions; they hold the sign-in credentials |
| `nhi-<workflow>-<agent>` | Agent identities (or app + service principal for the fallback backend) | `nhigov apply` | One NHI per (workflow, agent), each with only its declared roles |

| In GitHub (optional) | Created by | Purpose |
|---|---|---|
| Environment `wf-claims-triage` + variables | You | Lets the agent job sign in as its NHI |
| Environment `wf-control-plane` + variables | You | Lets the nightly scan sign in as `nhigov-scanner` |
| Federated credential on `bp-agent-summarizer` | `nhigov apply` | Trusts jobs in `wf-claims-triage` |
| Federated credential on `nhigov-scanner` | You (portal) | Trusts jobs in `wf-control-plane` |

---

## Prerequisites

- Python 3.12, [uv](https://docs.astral.sh/uv/), git.
- A **personal** Microsoft account for a new Azure free account. Never use an employer tenant: the provisioner gets tenant-wide write permissions.
- For the CI part: a GitHub account. The repository must be **public** for GitHub *environments* to work on the free plan; private repos need GitHub Pro or higher.

```bash
git clone <your fork> && cd <repo>
uv sync
```

---

## 1. Create the tenant and a cost guardrail

1. Create an [Azure free account](https://azure.microsoft.com/free/) with a personal email. This creates a free Entra ID tenant named `<something>.onmicrosoft.com`.
2. **Budget alert at $1.** Azure portal → *Cost Management + Billing* → *Budgets* → *Add*. Scope: the free subscription; amount `1`; alert at 100% of actual cost, to your email.
3. Check the licence. Entra admin center (<https://entra.microsoft.com>) → *Overview* → *License* should say **Microsoft Entra ID Free**. You don't need a trial.

## 2. Create a member user to own and sponsor things

The account you signed up with is usually a *guest* in the new tenant (its UPN contains `#EXT#`). Sponsors must be member users, so create one:

1. Entra admin center → *Users* → *New user* → *Create new user*, e.g. `alice@<tenant>.onmicrosoft.com`.
2. Assign it **Global Administrator**. It needs this to grant admin consent in steps 4 and 5.
3. Sign in as that user once and register MFA; security defaults require it.
4. *(Optional, for the lifecycle demo)* Create `test-departing-sponsor@<tenant>.onmicrosoft.com` with no roles.

The registry writes sponsors as `"{owner}@{tenant_domain}"`. You'll set `owner: alice` and the domain in `config.yaml` (step 6), and nhigov fills them in when it loads the registry.

## 3. Create certificates for the two control-plane apps

nhigov never uses client secrets. Each app proves who it is with a certificate whose private key stays on your machine.

```bash
uv run nhigov cert new nhigov-scanner
uv run nhigov cert new nhigov-provisioner
```

Each command writes a key and a `.cer` (public certificate) to `~/.nhigov/certs/` and prints the path to upload. They're valid for 180 days.

## 4. Register `nhigov-scanner` (read-only)

1. Entra admin center → *App registrations* → *New registration*. Name `nhigov-scanner`, *Accounts in this organizational directory only*, no redirect URI.
2. *Certificates & secrets* → **Certificates** → *Upload certificate* → `~/.nhigov/certs/nhigov-scanner.cer`. **Don't create a client secret.**
3. *API permissions* → *Add a permission* → *Microsoft Graph* → **Application permissions**, and add:

   | Permission | Why the scanner needs it |
   |---|---|
   | `Application.Read.All` | Read app registrations, service principals and their credentials |
   | `Directory.Read.All` | Read owners, users and directory objects |
   | `RoleManagement.Read.Directory` | See directory roles held by NHIs (NHI-006) |
   | `User.Read.All` | Check that sponsors exist and are enabled (NHI-002) |
   | `AuditLog.Read.All` | Read audit and sign-in reports where the licence allows |
   | `AgentIdentityBlueprint.Read.All` | Read Agent ID blueprints |
   | `AgentIdentity.Read.All` | Read agent identities |
   | `Policy.Read.All` | Read the tenant's app management policy |

4. Remove the default delegated `User.Read`; nothing uses it.
5. Click **Grant admin consent for <tenant>**. Each permission's status should turn green.
6. Note the *Application (client) ID* and the *Directory (tenant) ID* from *Overview*.

> If the `AgentIdentity*` permissions aren't in the picker, Agent ID isn't available in your tenant. Skip them, and use `identity_backend: service_principal` in step 8.

## 5. Register `nhigov-provisioner` (writes)

1. New registration `nhigov-provisioner`, single tenant. Upload `~/.nhigov/certs/nhigov-provisioner.cer`; again, no secret.
2. **Application permissions** (Microsoft Graph). This list is the ceiling; ADR-005 explains each one:

   | Permission | Why |
   |---|---|
   | `Application.ReadWrite.OwnedBy` | Create and manage the apps it creates (resource app, fallback NHIs), and nothing else |
   | `AppRoleAssignment.ReadWrite.All` | Grant NHIs their roles on the API, and revoke undeclared ones. **High-risk:** it can grant any app any role |
   | `Policy.ReadWrite.ApplicationConfiguration` | Write the tenant app management policy (block client secrets). **High-risk** |
   | `AgentIdentityBlueprint.Create` | Create blueprints |
   | `AgentIdentityBlueprint.AddRemoveCreds.All` | Add certificates and federated credentials to blueprints |
   | `AgentIdentityBlueprint.UpdateAuthProperties.All` | Set blueprint identifier URIs |
   | `AgentIdentityBlueprint.DeleteRestore.All` | Delete blueprints (lifecycle) |
   | `AgentIdentityBlueprintPrincipal.Create` | Create the blueprint's service principal |
   | `AgentIdentityBlueprintPrincipal.DeleteRestore.All` | Delete it (lifecycle) |
   | `AgentIdentity.Create.All` | Create agent identities from blueprints |
   | `AgentIdentity.EnableDisable.All` | Disable an agent identity when its sponsor leaves or its workflow expires |
   | `AgentIdentity.DeleteRestore.All` | Soft-delete retired agent identities |

3. Remove delegated `User.Read`, then **Grant admin consent**.
4. Note its client ID.

The two high-risk permissions are declared with a time-limited `exception:` in [registry/workflows/wf-control-plane.yaml](../registry/workflows/wf-control-plane.yaml). Discovery flags them if that exception lapses. Keep the provisioner's key on one machine, and never give it to CI.

## 6. Configure

```bash
cp config.example.yaml config.yaml
```

Fill in:
- `tenant_id`;
- `tenant_domain` (e.g. `contoso.onmicrosoft.com`);
- `owner` (the part before `@` of your step 2 user);
- the scanner's and provisioner's `client_id`.

Leave `sensitive_api` as it is; `apply` fills it in. Every setting can also come from an environment variable (shown next to it in the file).

```bash
uv run nhigov validate            # offline registry check: expect 0 errors
uv run nhigov validate --online   # also checks the sponsors exist in your tenant
```

## 7. Probe what your tenant can do

```bash
uv run nhigov -v probe
```

This runs read checks as the scanner and *plans* the write checks. To run the write checks, which create and then delete `nhigov-probe-*` objects:

```bash
uv run nhigov probe --sponsor alice@<tenant>.onmicrosoft.com --execute
```

The result is written to `docs/capability-matrix.md`, with IDs redacted. Expect these on Free:
- Agent ID create and read: OK;
- tags on agent identities: refused;
- service-principal sign-in logs: licence required;
- app management policy write: 403.

## 8. Choose the identity backend

Set `identity_backend: agent_id` in `config.yaml` if the probe's Agent ID writes (W01–W03) were OK. Otherwise set `service_principal`. A single workflow can override it with `backend:` (see `registry/workflows/wf-sp-backend-demo.yaml`).

## 9. Review the example registry

`registry/` is the source of truth: what may exist, who sponsors it, and exactly what it may do.

| Workflow | Agents | What it shows |
|---|---|---|
| `wf-claims-triage` | summarizer (`Records.Read.Redacted`), router (`Records.Read.Metadata`, `Records.Annotate`) | The main example; the summarizer also runs in GitHub Actions |
| `wf-usage-demo` | summarizer | Unused-permission analytics (`nhigov usage analyze`) |
| `wf-sp-backend-demo` | router, on the service-principal backend | The fallback backend: an app with its own certificate |
| `wf-lifecycle-test` | router, sponsored by `test-departing-sponsor` | Sponsor departure. It's `status: retired`, so nothing is created; set it to `active` to run the demo |
| `wf-control-plane` | scanner, provisioner | The governance tooling registered like any other workflow. Report-only: `apply` never changes these two apps |

Delete any workflow you don't want, and add your own: copy one, give it an `id`, a sponsor, `expires` (12 months at most) and `review_by`, and grant only roles listed in the agent's `max_permissions`. Then run `nhigov validate`.

## 10. Create the agents' certificates

`plan` won't create a blueprint, or a fallback-backend NHI, until its certificate exists locally:

```bash
uv run nhigov cert new bp-agent-summarizer
uv run nhigov cert new bp-agent-router
uv run nhigov cert new nhi-wf-sp-backend-demo-agent-router   # only if you kept that workflow
```

You don't upload these by hand: `apply` uploads the public certificate to the blueprint or app.

## 11. Plan and apply

```bash
uv run nhigov plan      # read-only, as the scanner: lists every change
uv run nhigov apply     # re-plans, asks for confirmation, then writes as the provisioner
uv run nhigov plan      # should now say "No changes"
```

The first `apply` does the following:
1. Registers `res-sensitive-records` with its four app roles, and turns on *assignment required*, so only clients granted a role can get a token for it.
2. Creates each blueprint and its blueprint principal, and uploads the blueprint's certificate.
3. Creates one agent identity per (workflow, agent), sponsored by your owner user.
4. Assigns each NHI exactly its declared roles.
5. Writes `sensitive_api.audience` into your `config.yaml`.

Everything it created is recorded in `state/tenant-state.json`, which is how nhigov knows which Entra object is which. Back it up, and don't commit it.

If `apply` stops partway (Entra can take a few seconds to make new objects visible), fix the cause and run it again. It picks up where it left off.

## 12. Run an agent

```bash
uv run nhigov api serve                                      # terminal 1: API on 127.0.0.1:8000
uv run nhigov agent run wf-claims-triage agent-summarizer    # terminal 2
uv run nhigov agent run wf-claims-triage agent-router
```

The summarizer prints its token's roles (`['Records.Read.Redacted']`) and summaries in which the claimant and SSN appear as `[REDACTED]`. The router routes records and leaves a note on each.

Then prove least privilege against real tokens. With the API still running:

```bash
uv run pytest tests/authz
```

## 13. Discover, govern, analyse

```bash
uv run nhigov scan                        # every NHI in the tenant, findings in reports/
uv run nhigov lifecycle status            # each NHI's lifecycle state and what's due
uv run nhigov lifecycle run               # dry run of due actions; --execute to act
uv run nhigov usage analyze --window 30d  # roles granted but never used (needs some API traffic)
```

A clean tenant scans with **0 findings**. To see the scanner work, `scripts/seed_mess.py` plants deliberately broken NHIs; its own help explains it.
- The planted problems include a short-lived client secret, tagged and removed by its cleanup command.
- One of them, the directory role, needs a manual portal step that the script prints.

```bash
uv run python scripts/seed_mess.py plant            # dry run
uv run python scripts/seed_mess.py plant --execute  # creates the seeds
uv run nhigov scan
uv run python scripts/seed_mess.py verify           # every seed found, nothing else
uv run python scripts/seed_mess.py cleanup --execute
```

**Lifecycle demo (optional):**
1. Set `wf-lifecycle-test` to `status: active` and run `apply`.
2. Disable `test-departing-sponsor` in the portal.
3. Run `uv run nhigov lifecycle run --as-of <today + 14 days>`. It plans to disable the NHI once the sponsor grace period has passed.
4. Run it again with `--execute`.

**Tenant-wide "no client secrets" policy:** `uv run nhigov lifecycle policy` (dry run first). On Entra ID Free the write is refused (403, even for a Global Administrator), so on Free nhigov *detects* secrets (NHI-003) rather than preventing them.

## 14. GitHub Actions (optional): agents and the nightly scan with no secrets

CI jobs sign in with a short-lived OIDC token that GitHub issues to the job. A **federated credential** in Entra trusts exactly one repository + environment, so there's no secret to store. See ADR-014 for the design.

1. **Push your fork to a public GitHub repository**, with Actions enabled.
2. **Find the repo's immutable IDs.** Open `https://api.github.com/repos/<owner>/<repo>` and note `owner.id` and `id`. Put them in `config.yaml`:
   ```yaml
   github:
     repository: "<owner>/<repo>"
     owner_id: <owner.id>
     repository_id: <id>
   ```
   Repositories created since mid-2026 put these IDs in the token's subject (`repo:<owner>@<owner_id>/<repo>@<id>:environment:<name>`). Without them Entra refuses the token with `AADSTS700213`.
3. **`uv run nhigov plan`, then `apply`.** This adds the federated credential `gh-wf-claims-triage` to `bp-agent-summarizer`, because that agent lists `github-actions` in its `runtimes`.
4. **`uv run nhigov ci vars`.** This prints, for each GitHub environment, the variables it needs, plus the scanner's federated credential to add by hand.
5. **Create the environments.** In the repo: *Settings* → *Environments* → *New environment*, named exactly:
   - **`wf-claims-triage`**: `NHIGOV_TENANT_ID`, `NHIGOV_API_AUDIENCE`, `AGENT_SUMMARIZER_BACKEND`, `AGENT_SUMMARIZER_CLIENT_ID`, `AGENT_SUMMARIZER_BLUEPRINT_APP_ID`.
   - **`wf-control-plane`**: `NHIGOV_TENANT_ID`, `NHIGOV_TENANT_DOMAIN`, `NHIGOV_OWNER`, `NHIGOV_IDENTITY_BACKEND`, `NHIGOV_SCANNER_CLIENT_ID`, `NHIGOV_PROVISIONER_CLIENT_ID`, `NHIGOV_STATE_JSON` (one long JSON line, printed at the end of `ci vars`).

   Add them as **Variables**, not Secrets: they're IDs, and none of them authenticates anything. Copy names and values exactly. GitHub passes a variable that doesn't exist as an empty string, and the CI scan stops with an error naming the missing variable.
6. **Add the scanner's federated credential by hand.** nhigov never changes its own control plane. Go to *App registrations* → `nhigov-scanner` → *Certificates & secrets* → *Federated credentials* → *Add credential* → **Other issuer**:
   - Issuer: `https://token.actions.githubusercontent.com`
   - Subject identifier: `repo:<owner>@<owner_id>/<repo>@<repository_id>:environment:wf-control-plane`
   - Audience: `api://AzureADTokenExchange`
   - Name: `gh-wf-control-plane`

   Type or paste the subject on a single line. A trailing space or line break is stored silently and never matches. `nhigov plan` checks this credential and shows any mismatch with hidden characters visible.
7. **Run.** *Actions* → **agent: wf-claims-triage / agent-summarizer** → *Run workflow*. The log shows `GitHub OIDC (federated credential)`, the token roles and redacted records. **nightly discovery scan** runs daily at 05:23 UTC, or on demand. It prints counts only and fails on any critical or high finding.

Never add a federated credential to `nhigov-provisioner`. Nothing in CI should be able to write to your tenant, and `plan` reports any credential on it as undeclared.

## 15. Keeping it running

- **Certificates last 180 days.** Run `uv run nhigov lifecycle rotate <bp-name>` (dry run, then `--execute`) before they expire. It adds the new certificate, proves a token works with it, and only then removes the old one. Discovery flags expiring and expired credentials (NHI-004). The two control-plane certificates are rotated by hand: `nhigov cert new <name> --overwrite`, then upload the new `.cer` and remove the old one in the portal.
- **Review dates.** Each workflow has `review_by` and `expires`. `lifecycle status` and the scan (NHI-010) tell you when they're due; renew them in the registry.
- **Retiring a workflow.** Set `status: retired`. `apply` disables its NHIs at once, and `lifecycle run --execute` soft-deletes them after the grace period. Entra keeps them restorable for 30 days.

## Removing everything

There's no single teardown command, on purpose.
1. Retire all workflows and let the lifecycle soft-delete their NHIs, or delete them in the portal: *Agent ID* for agent identities and blueprints, *App registrations* for the others.
2. Delete `nhigov-scanner` and `nhigov-provisioner`.
3. Delete `~/.nhigov/certs/` and `state/`.
4. Delete the GitHub environments.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `AADSTS700213 No matching federated identity record` in CI | The credential's subject doesn't match the job's token. Usually the name-only subject on a new repo, a wrong environment name, or hidden whitespace | Set `github.owner_id` and `repository_id`, then `apply`. For the scanner, retype the subject. `nhigov plan` shows the stored subject |
| `AADSTS700027` (certificate not found) | The certificate in `~/.nhigov/certs/` isn't the one uploaded to that app | Upload the matching `.cer`, or re-run `apply` for agent certificates |
| `AADSTS501051` when an agent asks for a token | That NHI has no role on the API (assignment is required) | Grant the role in the registry, then `apply` |
| `apply` stops with a 404 or 409 right after creating or deleting something | Entra replication lag | Re-run `apply`; it retries and resumes |
| `plan` notes "no local certificate" | Step 10 not done for that blueprint or NHI | `nhigov cert new <name>`, then `plan` again |
| CI scan exits 2 naming a variable | A GitHub environment variable is missing or misspelled | Add it exactly as `nhigov ci vars` prints it |
| Every managed NHI shows NHI-002 | `owner` or `tenant_domain` is wrong, so sponsors resolve to nobody | Fix `config.yaml` (or the CI variables) |
| Removing a permission under *API permissions* didn't remove it | That list is what the app *requests*; the grant is separate | Revoke it under *Enterprise applications* → the app → *Permissions* |
