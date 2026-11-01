# ADR-010: The reconciler (plan/apply for identities)

**Status:** Accepted and verified live (Phase 3, 2026-11-01): apply, then plan shows no changes. Builds on ADR-003 (backends) and ADR-006 (plan/apply).

## Context
Phase 2's `plan`/`apply` handled one resource API. Phase 3 has to create and maintain the NHIs themselves: blueprints, agent identities, service-principal NHIs, their certificates and their role grants. It must stay safe when the tenant drifts, and running it twice must change nothing.

## Decision
- **Steps name registry keys, not object IDs.** A plan is a list of `Step`s like `agent.create wf-claims-triage/agent-router`. The executor looks up IDs in the state file when each step runs, because objects created earlier in the same apply have no ID at plan time. State is saved after every step, so a failed apply resumes instead of duplicating.
- **Plan reads as the scanner; apply writes as the provisioner,** re-planning immediately before it writes.
- **Two backends behind one interface** (`backends/agent_id.py`, `backends/service_principal.py`). Each plans its own NHIs and reports their principal IDs. Role grants are planned once for both, because both end in a service principal.
- **Per-workflow `backend:`** overrides `config.yaml`'s `identity_backend` (ADR-008 schema addition). Both backends run side by side without giving any (workflow, agent) pair two NHIs (P3). `wf-sp-backend-demo` exercises the fallback.
- **Correlation without tags.** Agent identities can't be tagged (Phase 0), so one found by name is adopted only if it was created from *our* blueprint, which is tagged `nhigov:managed`. Blueprints and SP-backend apps must carry the tag to be adopted.
- **Refuse to guess.** If state names an object the tenant doesn't return, or a name match fails the ownership checks, plan stops.
- **Status mapping:**

  | Status | What exists |
  |---|---|
  | `requested` | Nothing is created |
  | `active` | Created and enabled |
  | `suspended`, `retired` | Disabled; never created if missing |

  Deleting is the lifecycle engine's job (Phase 6).
- **Grants:** on resources nhigov manages, the reconciler grants what the registry declares and **revokes anything else** (Paul, 2026-11-01). Revoking can only reduce access. Grants on unmanaged resources (Microsoft Graph) are reported, not changed.
- **Credentials:** `apply` uploads a local certificate's *public* key only when the object has no credential. Replacing a credential is rotation, which belongs to the lifecycle engine (§8: create new, verify, then remove old).
- **The control plane is report-only** (Paul, 2026-11-01). `plan` compares the scanner's and provisioner's Graph grants with `wf-control-plane.yaml` and reports drift. `apply` never edits them: a bug in a reconciler that can change the provisioner's own permissions could grant itself more.
- **Sponsors** are set at create. `plan` tries to read them back and reports a 403 instead of failing (Paul, 2026-11-01). The docs list only `AgentIdentity.ReadWrite.All` for reading sponsors, and the scanner stays read-only.

## Alternatives rejected
- **Terraform-style saved plan files:** re-planning immediately before writing gives the same safety without a stale-plan problem. The confirmation prompt shows exactly what will run.
- **Granting the scanner `AgentIdentity.ReadWrite.All`** to read sponsors: it breaks "the scanner can never write" (ADR-005).
- **Adopting agent identities by name alone:** names aren't unique or protected; anyone with Agent ID rights could pre-create `nhi-…` and have it adopted.

## Consequences
- The first `apply` needs local certificates (`nhigov cert new bp-<agent>` and `nhi-<workflow>-<agent>`). Without them, `plan` creates the objects but reports that the certificate is missing.
- Live run (2026-11-01): the scanner *can* read sponsors despite the docs, so `plan` does detect sponsor drift; the 403 path remains as a fallback.
- A tenant-side change to a blueprint credential is reported, never undone, until Phase 6 rotation exists.
