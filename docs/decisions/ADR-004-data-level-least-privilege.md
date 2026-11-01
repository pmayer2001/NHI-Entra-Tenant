# ADR-004: Data-level least privilege lives in the resource, via app-only roles

**Status:** Accepted (Phase 0). Implemented in Phase 2.

## Context
P4 requires NHI roles that restrict *data*, not just *systems*. Entra directory roles govern the directory itself (users, apps, policies), not business records. Once a token reaches an API, only that API can decide which fields to return.

## Decision
The mock Sensitive Records API (`res-sensitive-records`) defines **separate role sets** for humans and agents:

| Role | `allowedMemberTypes` | Effect |
|---|---|---|
| `Records.Read.All` | `User` | Full records, including PII (claimant name, SSN, date of birth, account number) |
| `Records.Read.Redacted` | `Application` | Records with SSN / DOB / account number redacted |
| `Records.Read.Metadata` | `Application` | IDs, timestamps, status only |
| `Records.Annotate` | `Application` | Append a triage note; cannot modify fields |

The API validates the JWT (signature via the tenant's JWKS, `iss`, `aud`, `exp`), requires `idtyp == "app"` on agent routes, maps each route to a required role, redacts fields the role doesn't allow, and logs every call (feeds L3 usage analytics, ADR-007).

## Why
- `allowedMemberTypes` separates agent roles (`Application`) from human roles (`User`), so the portal and consent flows steer each to the right kind of principal. **It isn't a hard guarantee** (amendment below): the resource has to enforce the separation itself.
- App-only tokens carry the granted app roles in the `roles` claim, so the resource can enforce this without calling Graph.

## Alternatives rejected
- **One shared role set**: one mis-assignment exposes PII to an agent.
- **Scopes (delegated permissions)**: agents here run autonomously with no signed-in user. Scopes describe what an app may do *on behalf of a user*, so they're the wrong primitive.

## Amendment (Phase 5, 2026-11-01): `allowedMemberTypes` isn't enforced by Graph
Seed S9 assigned `Records.Read.All` (`allowedMemberTypes: ["User"]`) to a service principal with `POST /servicePrincipals/{id}/appRoleAssignments`, app-only with `AppRoleAssignment.ReadWrite.All`, and Graph **accepted** it. P4 therefore rests on layers we own, not on the IdP flag:
1. **The API**: human routes require a user token (`idtyp`/`scp`), so an app holding `Records.Read.All` still gets 403 (unit-tested since Phase 2).
2. **The registry**: REG-006 rejects any grant of a non-Application role to an NHI.
3. **The reconciler**: `apply` revokes roles the registry doesn't declare on managed resources.
4. **Discovery**: NHI-009 flags any NHI holding a User-assignable role (found the seed live).

## Consequences
- Redaction is only as good as the API's code, so it gets negative tests (P8): every agent response is asserted to contain no raw PII.
