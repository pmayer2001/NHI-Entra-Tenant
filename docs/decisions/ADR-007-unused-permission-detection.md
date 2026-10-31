# ADR-007: Unused-permission detection at three levels

**Status:** Accepted (Phase 0). L3 implemented in Phase 7. L1/L2 depend on probe results R09–R11.

## Context
An **app-only token carries every granted app role every time**. The `.default` scope can't request a subset. So Entra's sign-in data can show *that* an NHI authenticated, but never *which* permission it used. Only the resource that checked the `roles` claim knows that.

## Decision
| Level | Question | Source | Cost |
|---|---|---|---|
| L1 Identity | Did this NHI authenticate in N days? | `reports/servicePrincipalSignInActivities`, `appCredentialSignInActivities` (probe R10/R11) | Likely P1. Use during the P2 trial |
| L2 Resource | Holds roles on A and B but only gets tokens for A? | SP sign-in logs, `resourceId` (probe R09) | Likely P1. Short retention |
| L3 Permission | Which app role was actually exercised? | Our API's JSONL usage log | **Free** |

`nhigov usage analyze --window 30d` computes `granted − used` per NHI, scaled by `expected_cadence` so a monthly agent isn't flagged after 10 days, and emits NHI-012 findings with a suggested registry change.

## Why
We own one resource (the mock API), so we can show permission-level analysis for free and be explicit about what's paid. Microsoft's equivalent for Graph itself is Graph activity logs (P1 + Log Analytics, paid). It's documented in `docs/free-vs-paid.md`, not implemented.

## Consequences
- L3 only covers resources that log role usage. Graph permissions held by NHIs can't be checked at L3 on a free tenant.
