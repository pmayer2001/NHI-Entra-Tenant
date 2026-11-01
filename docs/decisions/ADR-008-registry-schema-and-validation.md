# ADR-008: Registry schema and validation

**Status:** Accepted (Phase 1, 2026-10-31). Implemented in `src/nhigov/registry/`.

## Context
ADR-001 makes `registry/*.yaml` the source of truth. It's only a control if invalid entries can't get through: a typo, a human role granted to an agent, a missing sponsor or an unjustified high-risk permission must fail *before* the reconciler acts on it (Phase 3).

## Decision
- **Pydantic v2 models, strict.** `extra="forbid"` everywhere: an unknown field is an error, because a misspelled governance field (`sponsr:`) is a missing control, not a cosmetic problem. Models are frozen.
- **Two layers.** Single-file rules live in the models (types, required fields, `review_by ≤ expires`). Cross-file rules are pure functions in `validate.py`, each returning `Finding`s (`REG-002`…`REG-014`). That's the same shape Phase 5's discovery rules use.
- **Errors vs. warnings.** Errors block (exit 1, CI fails). Warnings, like an unused agent definition or an expired workflow the lifecycle will handle, never block.
- **Offline by default.** `nhigov validate` needs no tenant, so it runs in CI on every PR. `--online` adds REG-020: sponsors, owners and exception approvers exist, are enabled and are members, checked read-only as the scanner.
- **Rule-to-test discipline.** Every rule has at least one test that breaks the real example registry in one way and expects that rule. A meta-test fails if a rule is added without a case.

## Additions to CLAUDE.md §6, and why
| Addition | Why |
|---|---|
| `identity_type: agent \| application` | The control plane (P9) isn't AI and needs Graph permissions, so it stays a classic app registration on every backend. |
| `trust_zone` (default `default`) | Agents in one zone share a blueprint, and the spike proved one blueprint credential reaches all of them (ADR-003). The field makes splitting blueprints a data change, not a schema change. |
| `managed: false` resources | Microsoft Graph is a resource we grant but don't own. Listing its roles lets grants be checked uniformly; the reconciler never edits it. |
| `exception.covers` | An exception names exactly which high-risk roles it justifies, so adding another high-risk role later fails until it's justified too. A blanket exception would hide that. |
| `{tenant_domain}` in UPNs | The tenant domain reveals the tenant ID with one public lookup. It's substituted from git-ignored config at load time and never committed. |
| `backend` on a workflow (Phase 3) | Overrides config's `identity_backend` for one workflow, so the service-principal fallback can be shown live next to Agent ID without giving a pair two NHIs (P3). See ADR-010. |
| `policy.control_plane` | Names the identities REG-012 requires to be registered in an active workflow (P9). |

## Alternatives rejected
- **JSON Schema files**: the cross-file rules (subset checks, P9) need code anyway, and pydantic gives typed objects to the reconciler for free.
- **One fixture folder per invalid case**: dozens of near-identical copies that drift from the real registry. Mutating a copy of the real registry keeps every test anchored to what we ship.
- **A separate `ControlPlane` kind**: cleaner to read, but the high-risk exception rule (REG-010) wouldn't run on the most privileged identities.

## Consequences
- The registry can't express agent roles that are also user-assignable (REG-006). That's intentional (P4), and a resource needing that would be a design smell.
- Online checks depend on the scanner holding `User.Read.All`.
