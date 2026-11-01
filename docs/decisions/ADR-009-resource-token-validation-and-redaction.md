# ADR-009: How the Sensitive Records API validates tokens and redacts data

**Status:** Accepted for the offline build (Phase 2, 2026-10-31). The token version and audience are confirmed when the resource app is registered (Phase 2, Part A).

## Context
ADR-004 puts data-level least privilege in the resource. Entra issues a token listing the caller's app roles. Everything after that is the resource's job: deciding whether to trust the token, whether the role covers the route, and which fields to return. A mistake in any of those leaks data no matter how carefully the roles were granted.

## Decision
- **The validation order is fixed.** The service checks, in this order: the `alg` allow-list (RS256 only), `kid` in the tenant's JWKS, the signature, `iss`, `aud`, `exp`/`nbf` (60 s leeway), `tid`, then the caller type. Any failure returns **401**. A trusted caller whose roles don't cover the route, or who is the wrong kind of caller, gets **403**. The specific reason for a rejection goes to the usage log, never back to the caller.
- **One configured token version.** `iss` and `aud` follow the resource app's `requestedAccessTokenVersion`, not the caller's. The spike showed that T1 was v2 and T2 for Graph was v1. We accept exactly one version, set in config. Accepting both would double what an attacker can try for no benefit.
- **The caller type comes from `idtyp`.** `idtyp == "app"` means an app-only token, from an agent or service principal. A token with `scp` and no `idtyp: app` is a user token. Agent routes require app, and the human route requires user. If neither can be determined, the token gets 401. The resource app therefore **must request the `idtyp` optional claim** (Part A), because Entra omits it otherwise.
- **The JWKS cache refetches on an unknown `kid`, at most once every 5 minutes.** That handles key rotation without letting random `kid` values hammer Entra's key endpoint. If the key endpoint is down, the request errors out; it is never treated as valid.
- **Each route requires exactly one role, declared next to the route** with `Depends(requires_role(...))`. There's no route without a role, and no route accepts "any of" several roles.
- **Redaction uses explicit per-role views.** Each role lists every field it can see, marked clear or masked, and anything not listed is omitted. A field added to the data later stays invisible until someone deliberately grants it. PII is the claimant's name plus ADR-004's SSN, date of birth and account number (name added 2026-11-01: triage needs the claim, not who made it). Masked PII returns `"[REDACTED]"` rather than partial values like the last four digits, because any part of an SSN is still PII.
- **Annotate is write-only.** The note body rejects unknown fields (422), and the response is the note itself, not the record.
- **Every call to a protected route is logged** to `usage.log` as JSON lines, denials included. Each line records the route template rather than the concrete URL, plus `blueprint_appid` (from `xms_par_app_azp`) so an agent's call can be traced back to its blueprint. A rejected token logs no caller identity, because nothing in an untrusted token is fact.
- **The service is its own package** (`services/sensitive_api`) and doesn't import `nhigov`. A resource server shouldn't depend on the tooling that governs it.

## Alternatives rejected
- **PyJWT's `PyJWKClient`.** It fetches keys with urllib, which tests can't intercept with respx, and it has no refetch rate limit.
- **`fastapi-azure-auth` or MSAL middleware.** They work, but they hide exactly the checks this project exists to demonstrate.
- **Partial masking (`***-**-1234`).** Even partial values are useful to an attacker who combines several sources.

## Registration (Part A probe, read-only)
`nhigov api probe` (results in `docs/spikes/resource-registration-probe.md`) showed: Microsoft has enabled `uriAdditionWithoutUniqueTenantIdentifier` on this tenant, with v2-token apps exempt; `nonDefaultUriAddition` is off. **Decision: the app is registered with `requestedAccessTokenVersion: 2`**, which keeps `api://nhigov-sensitive-records` legal and makes `aud` the appId. Fallback if the exemption is ever removed: `api://<appId>`, set right after creation. The service principal sets `appRoleAssignmentRequired: true`. App role IDs are UUID5 values derived from `resource id/role value`, so re-running `apply` produces the same IDs.

## Consequences
- Confirmed with real agent tokens (Phase 4): `aud` is the appId, `iss` is v2, `idtyp: app` is present, and `roles` is exactly the registry's grants. v2 tokens do **not** carry `xms_par_app_azp`, so the usage log's `blueprint_appid` is empty for agents; Phase 7 attributes calls to blueprints through nhigov's state (agent appId -> blueprint).
- The fake data uses SSN area number `000`, which the SSA has never issued, so no value in the repo can be a real SSN.
- Notes are kept in memory only and are lost on restart. Persistence isn't the point of the mock.
