# ADR-011: Discovery scanner

**Status:** Accepted, verified live (2026-11-01): `seed_mess.py verify` found all 23 seeded findings and nothing else.

## Context
The reconciler only sees what the registry declares. Governance also needs the opposite view: everything that exists in the tenant, including what nobody registered (P1) and what drifted after `apply`.

## Decision
- **Three stages:**
  1. *Collectors* read Graph as the scanner, one module per source.
  2. The *inventory* normalizes what they read into one record per NHI.
  3. *Rules* are pure functions over the inventory.

  The inventory is saved (`reports/inventory-<date>.json`), so rules can be re-run offline (`nhigov scan --from-inventory`) and unit-tested without a tenant.
- **One record per identity:** an app registration and its service principal are one NHI, and so are a blueprint and its blueprint principal. Credentials live on the app and grants live on the SP; a rule needs both.
- **Classification:**

  | Class | How it's recognised |
  |---|---|
  | **managed** | In the state file, or a control-plane client ID from config |
  | **microsoft-first-party** | Owner organization is Microsoft |
  | **third-party-consented** | Owned by another organization |
  | **shadow** | Created locally but unknown to nhigov |

  First-party SPs are listed but not expanded (no per-object calls), which keeps a scan to seconds.
- **Accountability (NHI-002):** a managed NHI's accountable human is its *registry* sponsor. For anything else it's an enabled member user among its Entra owners or sponsors. A service-principal owner, like the provisioner that created it, doesn't count.
- **Exceptions are read from the registry:** NHI-005 ignores a high-risk permission covered by an unexpired `exception:` on the NHI's workflow.
- **Findings have a stable key** (`rule:object_id`), so a CI job can open one GitHub issue per finding and close it when it clears.
- **Acceptance is measured against a baseline.** `seed_mess.py plant` scans first, records what already exists, then plants. `verify` requires every planted finding and nothing beyond the baseline.

## Alternatives rejected
- **Rules calling Graph directly:** that would mean a slower scan, no offline tests, and every rule needing its own error handling.
- **Microsoft's built-in reports** (Workload ID Premium, Agent 365 inventory): paid, and they don't know our registry.

## Consequences
- **Finding seen on the first scan:** each blueprint principal is automatically granted Microsoft Graph `AgentIdentity.CreateAsManager` when it's created. Revoking it failed (`EntitlementGrants can be updated only through a source`): it's system-managed. It's now accepted in `policy.blueprint_graph_grants`; any *other* grant on a blueprint is flagged by NHI-007 and revoked by `apply`.
- Agent identities report `servicePrincipalType: ServiceIdentity` and no `appOwnerOrganizationId`. They're recognised through the typed-cast listing instead.
- Seeding showed two more Entra behaviours: a User-only app role *can* be assigned to an app through Graph, and a blueprint principal survives its blueprint's deletion.
