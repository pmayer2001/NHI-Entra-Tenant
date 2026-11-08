# Governing principles

The rules nhigov enforces. ADRs, code comments and findings refer to them as P1–P9.

| # | Principle | How it's enforced |
|---|---|---|
| P1 | **Every use of AI is a registered application** (a "workflow") in an application registry. | `registry/workflows/*.yaml` is the source of truth. The reconciler refuses to create identities for anything not registered. Discovery flags anything in the tenant that isn't registered (NHI-001). |
| P2 | **Agents and skills are reusable** across workflows. | `registry/agents/*.yaml` defines an agent once and workflows reference it. Under Agent ID, an agent definition maps to an **agent identity blueprint**. |
| P3 | **One NHI per (workflow, agent) pair.** | The reconciler creates one agent identity (or service principal) per pair. Discovery flags an NHI used by two workflows (NHI-008). |
| P4 | **NHI-specific roles that restrict data, not just systems.** | Resource APIs define separate app roles for NHIs (`allowedMemberTypes: ["Application"]`) and humans (`["User"]`). The resource redacts fields by role and refuses app tokens on human routes. `allowedMemberTypes` is a default, not a guarantee (Graph accepted a User-only role on an app), so P4 is enforced by the API, the registry (REG-006), the reconciler (revokes undeclared roles) and discovery (NHI-009). |
| P5 | **Skills never get their own identity.** A skill runs under the identity of the agent that calls it. | Registry schema: skills have no `permissions` field. |
| P6 | **Every NHI has a human sponsor, an expiry date and a review date.** | Required registry fields. The lifecycle engine acts on them (ADR-012). |
| P7 | **No client secrets.** Federated credentials or certificates only. | Discovery flags any secret (NHI-003). The tenant app management policy can block new secrets where the tenant's licence allows writing it (ADR-012). |
| P8 | **Least privilege is tested.** Every role grant has a positive test (can do X) and a negative test (can't do Y, can't see field Z). | `tests/authz/` runs against real tokens. |
| P9 | **The governance tooling is governed too.** The provisioner and scanner are registered like any other NHI. | `registry/workflows/wf-control-plane.yaml`. |

## Operating rules

- **Plan before apply.** Every tenant write is shown as a plan first and needs `--execute` (or `apply`'s prompt) plus a confirmation.
- **No secrets in the repo.** Private keys stay in `~/.nhigov/certs/`; tenant IDs, client IDs and the tenant domain stay in the git-ignored `config.yaml` and state files.
- **The provisioner stays narrow.** Every permission it holds is listed and justified in ADR-005.
- **$0 target.** No billable Azure resources; paid Entra features are emulated in code and listed in `free-vs-paid.md`.
