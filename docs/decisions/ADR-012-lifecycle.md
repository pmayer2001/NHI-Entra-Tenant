# ADR-012: Lifecycle engine

**Status:** Accepted (2026-11-01). Verified live 2026-11-01: the departing-sponsor run disabled the NHI via `AgentIdentity.EnableDisable.All`, and the next `plan` kept it disabled (hold).

## Context
The registry says when each NHI expires, who sponsors it and whether its workflow is retired, but nothing acted on that. Entra's Lifecycle Workflows and Agent 365 sponsor automation are paid (`free-vs-paid.md`). Credentials also need rotating before they expire, and P7 was only *detected* (NHI-003), not prevented.

## Decision
- **Engine (`lifecycle/engine.py`):** a pure function over the registry, a discovery inventory (read as the scanner), the state file and the lifecycle state. It returns each NHI's state (requested / active / expiring / disabled / soft-deleted / purged) and the actions due. `run.py` executes them as the provisioner, only with `--execute` and a confirmation.
- **Lifecycle state (`state/lifecycle.json`, git-ignored):** records the first day each condition was seen. Grace periods need a start date, and Entra exposes an account's current `accountEnabled`, not when it changed.
- **Holds:** when the engine disables an NHI (sponsor gone for `sponsor_grace_days`, or past `expires`), it records a hold. `build_desired` treats a held NHI as not-to-be-enabled, so `apply` won't turn it back on and `plan` shows why. Once the cause is fixed (new sponsor, renewed dates), the engine releases the hold, and the next `apply` re-enables the NHI. This resolves the conflict between "the registry says active" and "the lifecycle disabled it".
- **Retirement:** `apply` disables NHIs of a retired workflow (ADR-010). After `retirement_grace_days`, the engine soft-deletes them and removes them from the state file, so `plan` doesn't treat them as missing. Entra purges them 30 days later.
- **Notices:** expiry and review dates within `expiry_notice_days` produce one notice each, written to `reports/notices-<date>.md`. A CI job can turn these into GitHub issues for the sponsor.
- **`--as-of DATE`:** time is an input, so a 14-day grace period can be demonstrated, and tested, without waiting.
- **Rotation (`lifecycle rotate`):** generate a new certificate, `addKey` with a proof of possession signed by the current key, verify a real token with the new key (T1 → T2 for blueprints), and only then `removeKey` the old one. If verification fails, the old key stays and the command stops. **How keys are written (amended 2026-11-01, `--method`):** `addKey` as the provisioner with the proof's `iss` = the blueprint → 401 `Authentication_MissingOrMalformed`. `addKey` as the blueprint itself → 403: the "apps roll their own keys without permission" exemption doesn't cover blueprints, and the permission they'd need (`AgentIdentityBlueprint.AddRemoveCreds.All`) covers every blueprint, so it isn't granted. Blueprints therefore default to **`patch`**: the provisioner PATCHes `keyCredentials` to [current, new], verifies, then [new]. That's safe only because every key on the object is held locally; rotate refuses if it finds any other key. `addkey-self` stays the default for service-principal NHIs (plain apps). A third try, `addKey` as the provisioner with the proof's `iss` = the provisioner, also got 401; that method was removed. **Live: `patch` rotated `bp-agent-router` on 2026-11-01 and `tests/authz` passed on the new key.**
- **App management policy (`lifecycle policy`):** merges `passwordAddition` + `symmetricKeyAddition` + `asymmetricKeyLifetime P180D` into the tenant default policy, for apps and service principals, and keeps existing restrictions. That turns P7 from detected into prevented.
- **Certificates fit the cap exactly:** `cert new` now counts the lifetime from the backdated start, so a "180-day" certificate is 180 days, not 180 days and 5 minutes.

## Alternatives rejected
- **Changing the registry's `status:` from the engine:** the registry is reviewed desired state (ADR-001); a tool shouldn't rewrite it. Holds keep the decision visible without editing git.
- **Reading account-disable times from the audit log:** retention on Free is short, and the engine would depend on `AuditLog.Read.All` data shape. First-seen tracking is simpler and conservative: the grace period never starts *earlier* than reality.
- **PATCHing `keyCredentials` blindly:** Graph never returns existing keys' public bytes, so a PATCH replaces them; for keys we don't hold, that's a silent remove. Kept only for objects whose every key is held locally (the `patch` method above), and it still adds before it removes.
- **Granting a blueprint `AgentIdentityBlueprint.AddRemoveCreds.All` so it can roll its own key:** it's tenant-wide, so one stolen blueprint key could add credentials to every blueprint.

## Consequences
- Grace periods start when nhigov first *notices* a condition, so run `lifecycle status` regularly (for example, nightly in CI).
- Blueprint retirement (agents → blueprint principal → blueprint) isn't automated yet. The engine deletes NHIs, not blueprints.
- **App management policy: built, but its write is refused on the free tenant (2026-11-01).** The provisioner and a Global Administrator both got 403 on the PATCH, most likely a licence gate. `lifecycle policy` stays as a dry-run check of what's missing; P7 is detected by NHI-003, not prevented. If a tenant can apply it, `seed_mess.py` records a refused secret as evidence of prevention.
