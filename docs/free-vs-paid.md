# Free vs. paid: Entra-native feature → our emulation

The tenant runs on **Entra ID Free** (target spend: $0). Where Microsoft sells a feature, we build the governance outcome in code and say so honestly. The "Evidence" column is filled in from `docs/capability-matrix.md` and the Phase 9 P2 trial.

| Entra-native feature | License | Our emulation | Evidence |
|---|---|---|---|
| Lifecycle Workflows | ID Governance | `nhigov lifecycle run` state machine (§8) | |
| Access reviews (for service principals) | P2 / ID Governance | `review_by` in registry + NHI-010 finding + GitHub issue to sponsor | |
| Entitlement management / access packages for agents | ID Governance / Agent 365 | Registry PR = access request; reconciler = provisioning | |
| Agent ID governance (sponsor automation, Agent 365 registry) | Agent 365 + P1 or M365 E7 | Sponsor is a required registry field; NHI-002 + lifecycle disable on sponsor departure | |
| Conditional Access for workload identities | Workload ID Premium | Not emulated. Try it during the P2 trial (Phase 9) | |
| Graph activity logs (which Graph permission was used) | P1 + Log Analytics (paid) | **Not implemented.** L3 analysis on our own API instead (ADR-007) | |
| SP sign-in activity reports (dormancy) | Assumed P1, but probe R10/R11 returned **200 on Free** (2026-10-31) | L1 may be possible on Free. Confirm the data is actually populated once NHIs sign in | R10/R11 OK; data not yet checked |
| Sign-in logs for service principals | **P1 confirmed** (probe R09: `Authentication_RequestFromNonPremiumTenantOrB2CTenant`) | L3 usage log; L2 only during the trial | R09 license required |
| App management policy (block secrets, cap cert lifetime) | Reportedly Free now (probe R12/W06) | Native if probe says OK, else NHI-003/NHI-004 detection only | R12 read OK (scanner); W06 403: the provisioner couldn't read or write it with `Policy.ReadWrite.ApplicationConfiguration`, contrary to the docs. Unresolved, revisit in Phase 6 |
