# ADR-001: Registry in git as YAML, not in Entra

**Status:** Accepted

## Context
Every AI use case must be a registered application (P1) with business metadata: owner, sponsor, data classification, expiry, review date and expected cadence. Something has to be the source of truth for that, and for which identities and permissions *should* exist.

## Decision
Desired state lives in `registry/*.yaml`, validated by pydantic v2 models. Entra ID is the **enforcement point**, not the source of truth. The reconciler (ADR-006) makes the tenant match the registry, and discovery flags anything in the tenant the registry doesn't know about.

## Why
- Pull requests give review *before* a change happens. Git also gives history, blame and rollback for free. This is the GitOps / infrastructure-as-code model.
- Entra's native catalogs either cost money (Agent 365 registry, entitlement management) or can't hold the business fields we need.
- Plain files are testable offline. `nhigov validate` runs in CI with no tenant at all.

## Alternatives rejected
- **Metadata in Entra attributes** (custom security attributes, directory extensions). Custom security attributes may need P1, and an attribute change takes effect immediately with no review step.
- **The Agent 365 / Agent Registry** as the catalog. It needs paid licensing and is meant for Microsoft 365 agent discovery, not a general governance schema.

## Consequences
- The tenant can drift from git (someone clicks in the portal). Discovery rule NHI-007 detects that drift.
- Correlating registry entries with Entra objects needs a state file plus tags (ADR-006).
