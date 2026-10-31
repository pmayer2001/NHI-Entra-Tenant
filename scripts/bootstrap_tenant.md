# Bootstrap the tenant (one-time, manual)

These are the only portal steps in the project. After this, everything goes through code. Tick each box as you go. Never paste tenant IDs, client IDs or object IDs into this file, because the repo may be public.

## 1. Tenant and cost guardrail
- [X] Create an Azure free account with a **personal** email (never an employer account, CLAUDE.md §14.6). This creates a free Entra ID tenant (`<something>.onmicrosoft.com`).
- [X] **Budget alert at $1:** Azure portal → *Cost Management + Billing* → *Budgets* → *Add*. Scope: the free subscription, amount `1`, alert at 100% actual to your email.
- [X] Confirm the tenant is **Microsoft Entra ID Free**: Entra admin center → *Overview* → *License*. Do **not** start the P2 trial yet (Phase 9).

## 2. A cloud-only admin and sponsor user
Your sign-up account is usually a *guest* (`#EXT#`) from your personal Microsoft account. Sponsors must be real member users, so:
- [X] Entra admin center → *Users* → *New user* → `paul@<tenant>.onmicrosoft.com`. Assign **Global Administrator** (needed once, to grant admin consent below).
- [X] Sign in as that user and register MFA (security defaults enforce it on Free).
- [X] Also create `test-departing-sponsor@<tenant>.onmicrosoft.com` (no roles). Phase 6 disables it on purpose.

## 3. Certificates for the control plane (local, no portal)
```bash
uv run nhigov cert new nhigov-provisioner
uv run nhigov cert new nhigov-scanner
```
Each command prints the `.cer` path to upload and the thumbprint. Private keys stay in `~/.nhigov/certs/`.

## 4. Register `nhigov-scanner` (read-only)
- [X] *App registrations* → *New registration*. Name `nhigov-scanner`, *Single tenant*, no redirect URI.
- [X] *Certificates & secrets* → **Certificates** tab → *Upload* `~/.nhigov/certs/nhigov-scanner.cer`. **Do not create a client secret** (P7).
- [X] *API permissions* → *Add* → *Microsoft Graph* → **Application permissions**:
  `Application.Read.All`, `Directory.Read.All`, `RoleManagement.Read.Directory`, `User.Read.All`, `AuditLog.Read.All`, `AgentIdentityBlueprint.Read.All`, `AgentIdentity.Read.All`, `Policy.Read.All`
- [X] Remove the default delegated `User.Read` (unused; least privilege).
- [X] *Grant admin consent for <tenant>*.
- [X] Copy *Application (client) ID* and *Directory (tenant) ID* into `config.yaml` (git-ignored).

> If an `AgentIdentity*` permission isn't in the picker, Agent ID isn't available on this tenant. Skip those permissions and note it. The probe will confirm, and we'll use the service principal backend.

## 5. Register `nhigov-provisioner` (write)
- [X] New registration `nhigov-provisioner`, single tenant, upload `nhigov-provisioner.cer`, no secret.
- [X] **Application permissions** (ceiling set by CLAUDE.md §14.3; rationale in ADR-005):
  `Application.ReadWrite.OwnedBy`, `AppRoleAssignment.ReadWrite.All`, `Policy.ReadWrite.ApplicationConfiguration`, `AgentIdentityBlueprint.Create`, `AgentIdentityBlueprint.AddRemoveCreds.All`, `AgentIdentityBlueprint.UpdateAuthProperties.All`, `AgentIdentityBlueprintPrincipal.Create`, `AgentIdentity.Create.All`,
  plus for lifecycle (ADR-005 amendment): `AgentIdentity.EnableDisable.All`, `AgentIdentity.DeleteRestore.All`, `AgentIdentityBlueprint.DeleteRestore.All`
- [X] Remove delegated `User.Read`. Grant admin consent.
- [X] Copy the client ID into `config.yaml`.

## 6. Configure and probe
```bash
cp config.example.yaml config.yaml      # then fill in the three IDs
uv run nhigov -v probe                  # read checks only; write checks shown as "planned"
```
Then, **after confirming in the Claude Code session**:
```bash
uv run nhigov probe --sponsor paul@YOURTENANT.onmicrosoft.com --execute
```
This creates and deletes `nhigov-probe-*` objects. Commit the regenerated `docs/capability-matrix.md` (IDs are redacted automatically).

## 7. Agent ID token spike ✅ (2026-10-31)
Follow `docs/spikes/agent-id-token-spike.md` if probe W01–W03 are OK.

## 8. Record the outcome
- [X] Set `identity_backend` in `config.yaml` to the probe's recommendation (`agent_id`).
- [X] Update ADR-003's status to *Accepted* with the chosen backend.
- [ ] Note anything that surprised you in `docs/learning-notes.md`.
