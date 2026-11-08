# ADR-003: Identity backend adapter (Agent ID primary, service principal fallback)

**Status:** Accepted on 2026-10-31. **Backend: `agent_id`**, with the service principal backend kept as a tested fallback.

**Evidence (probe, Entra ID Free tenant):** an app-only provisioner created a blueprint (W01), its principal (W02, after replication-lag retries) and an agent identity with a sponsor (W03), then deleted them (C01/C02). Not available: setting `tags` on agent identities with `AgentIdentity.EnableDisable.All` (W04 403), so correlation uses the state file (ADR-006). Still to verify in the spike: the `fmi_path` token flow behind the blast-radius argument below.

## Context
Microsoft Entra Agent ID adds object types built for AI agents. As of Oct 2026 they're in **Graph v1.0** (verified on Microsoft Learn on 2026-10-31):

| Object | Graph type | Create endpoint |
|---|---|---|
| Agent identity blueprint | `microsoft.graph.agentIdentityBlueprint` (an application subtype) | `POST /applications` with `@odata.type: Microsoft.Graph.AgentIdentityBlueprint` + `OData-Version: 4.0` |
| Blueprint principal | `microsoft.graph.agentIdentityBlueprintPrincipal` | `POST /servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal` `{appId}` |
| Agent identity | `microsoft.graph.agentIdentity` (a service principal subtype, `servicePrincipalType: ServiceIdentity`) | `POST /servicePrincipals/microsoft.graph.agentIdentity` `{displayName, agentIdentityBlueprintId, sponsors@odata.bind}` |

A **sponsor is mandatory** on blueprints and agent identities. Whoever creates a blueprint becomes its owner, and owners can create agent identities under it without an Agent ID directory role. Whether a free tenant allows any of this is unknown until the probe runs.

## Decision
An `IdentityBackend` protocol with two implementations, selected by `identity_backend` in config:

| Registry concept | Agent ID backend | Service principal backend |
|---|---|---|
| Agent definition (reusable, P2) | Blueprint + blueprint principal (`bp-<agentId>`) | Registry-only template |
| (workflow, agent) instance (P3) | Agent identity (`nhi-<wf>-<agent>`) with sponsor | App registration + SP (`nhi-<wf>-<agent>`) |
| Credential (P7) | Certificate / FIC **on the blueprint** | Certificate / FIC on each app |
| Permissions (P4) | App role assignments on the agent identity | App role assignments on the SP |

`nhigov probe` recommends `agent_id` only if W01–W03 (create blueprint, principal, agent identity) all succeed.

## Why
Agent ID's structure maps directly onto P2/P3: blueprint = reusable definition, agent identity = per-workflow instance. The adapter keeps the reconciler, discovery and lifecycle independent of which backend exists on this tenant, and the SP backend is always available as a fallback.

## The blast-radius trade-off (confirmed by spike, 2026-10-31)
Per Microsoft Learn, agent identities **have no credentials of their own**. An autonomous agent gets a token in two steps:

1. The **blueprint** authenticates with *its* credential and requests `scope=api://AzureADTokenExchange/.default` with `fmi_path=<agent identity client ID>`.
2. That token is used as the `client_assertion` in a client-credentials request **as the agent identity** for the real resource.

So **whoever holds a blueprint credential can mint tokens for every agent identity under that blueprint**. Authorization stays per agent identity, since each has its own role assignments, so P3 holds for *what* an agent can do. But the *reach* of a stolen credential is the whole blueprint. Under the SP backend, a stolen cert reaches exactly one NHI.

Mitigations to evaluate:
- One blueprint per (agent, trust zone) rather than one per agent definition.
- One federated credential per runtime environment, with tight subjects (`repo:…:environment:wf-x`).
- Discovery rule NHI-011: alert on blueprints with credentials for more than N runtimes.

**Spike results** (`docs/spikes/agent-id-token-spike-results.md`):
- **Confirmed:** one blueprint certificate obtained tokens as agent A *and* agent B. The blast radius is the whole blueprint.
- **Also (live authz tests and discovery):** the boundary between blueprints holds (another blueprint's agent: `AADSTS7002134` at T2), but every blueprint principal holds a system-managed Graph `AgentIdentity.CreateAsManager` grant that can't be revoked. So a stolen blueprint key can also *create* agent identities, not just act as existing ones. Discovery watches for any other grant on a blueprint (NHI-007).
- **Confirmed:** a T1 minted with `fmi_path=A` was **refused** when presented to become agent B (`AADSTS7002142`). Entra binds T1 to one agent: T1's `sub` claim encodes `/t/<tenant>/a/<blueprint appId>/<agent id>`. So the exposure is the blueprint *credential*, not a leaked T1 (a leaked T1 reaches one agent, for its short lifetime).
- **The resource sees the agent, not the blueprint:** T2's `appid`, `oid` and `sub` are all the agent identity, so per-agent authorization (P3/P4) works as designed. T2 also carries `xms_par_app_azp`, which looks like the parent blueprint. A resource could log it to tie every agent call back to its blueprint (to verify when we build the Sensitive API).

## Alternatives rejected
- **Agent ID only**: blocked if the free tenant can't create blueprints.
- **Service principals only**: loses the blueprint/instance model and the interview-relevant Agent ID experience.

## Consequences
- **Deleting a blueprint did not cascade to its agent identities** (spike, 2026-10-31), contrary to Microsoft Learn. Two agent identities stayed live for 3+ minutes after the blueprint delete returned 204, until deleted explicitly. Lifecycle must **delete agent identities first, then the blueprint**, and discovery should flag **agent identities whose blueprint no longer exists** (rule NHI-013, approved 2026-10-31).
- Two implementations to keep behaviourally equivalent. Shared reconciler tests run against both.
- On the Agent ID backend, the per-workflow GitHub environment subject must sit on the *blueprint's* federated credential, so one blueprint accumulates one FIC per workflow environment. That makes NHI-011 more important.
