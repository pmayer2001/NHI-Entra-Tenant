# ADR-006: Plan/apply reconciler, disable before delete

**Status:** Accepted. Implemented in `src/nhigov/reconcile/` (ADR-010).

## Context
Tenant mutations must be reviewable and safe to repeat. Every write is shown as a plan first and needs the operator's confirmation.

## Decision
- `nhigov plan` diffs the registry against the tenant and prints create / update / disable / delete actions. It's read-only and runs as the scanner (ADR-005).
- `nhigov apply` executes a **saved** plan as the provisioner. Running it twice does nothing the second time.
- Deletes happen only through the lifecycle state machine (ADR-012): disable → grace period → soft-delete → purge.

## Correlating registry entries with Entra objects
Primary: `state/tenant-state.json`, which maps registry IDs to Entra object IDs (no secrets; committed).
Secondary: tags on applications and service principals: `nhigov:managed`, `nhigov:workflow=<id>`, `nhigov:agent=<id>`.
**Resolved 2026-10-31:** the provisioner can't set `tags` on agent identities. `PATCH …/microsoft.graph.agentIdentity` returned 403 with `AgentIdentity.EnableDisable.All`, and we chose not to widen to `AgentIdentity.ReadWrite.All` (ADR-005). On the Agent ID backend, agent identities are correlated by **state file + naming convention** (`nhi-<wf>-<agent>`). Tags remain in use on objects the provisioner can tag (SP-backend apps and service principals); tagging blueprints is untested.

## Why
- Same safety model as Terraform: you see the diff before anything changes.
- Disabling is reversible and surfaces hidden dependencies (something breaks) before anything is gone. Entra also keeps deleted applications for 30 days.

## Alternatives rejected
- **Imperative create/delete commands**: no diff and no idempotency.
- **Tags only, no state file**: not possible, because agent identities can't be tagged with the provisioner's permissions (see above).

## Consequences
- The state file can go stale if someone deletes objects in the portal. `plan` treats a missing object as drift, not as an error.
