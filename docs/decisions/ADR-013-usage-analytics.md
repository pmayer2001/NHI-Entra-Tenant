# ADR-013: Usage analytics (L3, NHI-012)

**Status:** Accepted (Phase 7, 2026-11-02). Live acceptance passed 2026-11-06: `wf-usage-demo`'s summarizer, granted `Records.Read.Metadata` on purpose, was flagged (NHI-012: never used in 4 days, expected hourly) while its `Records.Read.Redacted` (6 calls) and the claims-triage NHIs were `ok`. Loop closed 2026-11-08: the role was removed from the registry, `apply` revoked the assignment, and the next analysis showed the agent `ok` with 0 findings.

## Context
ADR-007 chose permission-level (L3) detection from our API's usage log, because an app-only token carries every granted role on every call and Entra can't say which one was used. This ADR records how "unused" is decided without crying wolf.

## Decision
- **Granted comes from the registry, used comes from the log.** Granted = the registry's roles on resources we own (`managed: true`); those are the only resources whose usage we log. Used = roles on *allowed* calls (`role_used`). A 403 is an attempt, not usage. The recommendation is a registry change, so the registry is the right baseline. Grants outside the registry are NHI-007's job.
- **Attribution through the state file.** A log event's `oid`/`appid` is matched to the NHI recorded at creation. Calls from anything else are counted as "unattributed": a registered API being called by an unregistered caller is worth a look.
- **Cadence sets how long to wait.** A role is judged only once the log covers `MIN_RUNS = 3` expected runs: 3 hours for an hourly agent, 3 days for daily, 21 for weekly, 90 for monthly (more than the default 30-day window, so the output says to raise it). An on-demand agent has no rhythm, so it needs the whole window. Before that, the verdict is **too early**, not **unused**.
- **Coverage is what the log can vouch for.** It starts at the later of the window start, the log's first event and the NHI's creation (`created_at`, now written to the state file by `apply`). An NHI isn't judged on days it didn't exist.
- **Verdicts:** `ok`, `unused` (some roles never used → NHI-012 for those roles), `dormant` (no role used → NHI-012, suggest suspending the workflow), `too-early`, `skipped` (lifecycle hold, workflow not active, not provisioned).
- **Offline and read-only.** `nhigov usage analyze` reads the log, registry and state; no Graph call. Findings use the discovery `Finding` model and key, so Phase 8 can file them like any other finding.

## Why
False positives teach people to ignore a report. "Unused" is an argument from absence of evidence, so the tool has to show it looked long enough before claiming it.

## Alternatives rejected
- **NHI-012 as a discovery rule over the inventory:** rules are pure functions of what Graph returns, and usage isn't in Graph. Kept separate, same finding format.
- **Using the token's `granted_roles` from the log as "granted":** an NHI that never calls would never appear, so dormant NHIs would be invisible.
- **A fixed age threshold (e.g. 30 days) for every NHI:** flags a monthly agent after one quiet month, or misses an hourly agent that's been idle for a week.

## Consequences
- NHIs created before Phase 7 have no `created_at`; they're judged from the log's start. A refresh of state (`adopt`) keeps `created_at`; losing the state file loses it.
- Graph permissions (the control plane's) aren't covered: no free source says which Graph permission was used (Graph activity logs are paid, `free-vs-paid.md`).
- `--as-of` assumes the log is complete up to that time, like `lifecycle --as-of`.
