# ADR-005: Authentication without secrets

**Status:** Accepted (Phase 0). Certificate tooling in `src/nhigov/certs.py`, auth in `src/nhigov/graph/auth.py`.

## Context
P7 forbids client secrets. Secrets are the most common NHI compromise path: they leak through logs, CI variables and copy-paste, and they're bearer credentials.

## Decision
| Where | Credential | How |
|---|---|---|
| Local runs | Self-signed **certificate** | `nhigov cert new <name>` writes `~/.nhigov/certs/<name>.pem` (key + cert, never committed) and `<name>.cer` (public, uploaded to the app) |
| GitHub Actions | **Federated identity credential** (OIDC) | Subject bound to a GitHub environment per workflow: `repo:<owner>/<repo>:environment:wf-<id>` |
| Control plane | Two separate apps, both certificate-based | `nhigov-provisioner` (write), `nhigov-scanner` (read-only) |

Certificates default to **180 days**, matching the app management policy cap planned for Phase 6.

### Control-plane permissions (application permissions, admin-consented)
**`nhigov-scanner`** (read-only): `Application.Read.All`, `Directory.Read.All`, `RoleManagement.Read.Directory`, `User.Read.All`, `AuditLog.Read.All`, `AgentIdentityBlueprint.Read.All`, `AgentIdentity.Read.All`, `Policy.Read.All`.
`Policy.Read.All` is the one addition to CLAUDE.md §7's list. It lets the scanner read the app management policy (probe R12). It's read-only.

**`nhigov-provisioner`** (CLAUDE.md §14.3 ceiling):
`Application.ReadWrite.OwnedBy`, `AppRoleAssignment.ReadWrite.All`, `Policy.ReadWrite.ApplicationConfiguration`, `AgentIdentityBlueprint.Create`, `AgentIdentityBlueprint.AddRemoveCreds.All`, `AgentIdentityBlueprint.UpdateAuthProperties.All`, `AgentIdentityBlueprintPrincipal.Create`, `AgentIdentity.Create.All`.
`AgentIdentity.Create.All` is **provisional**. Microsoft Learn says blueprint owners can create agent identities without an Agent ID *role*, but it doesn't say whether an app-only caller still needs a Graph *permission*. The probe (W03) decides, and we remove the permission if ownership alone suffices.

### Amendment (2026-10-31): approved by Paul and applied
The write probe showed the provisioner can **create** Agent ID objects but not **update or delete** them. Ownership plus `Application.ReadWrite.OwnedBy` isn't enough (see learning notes). Without delete, the lifecycle engine (§8) and ADR-006's disable-before-delete model can't work on the Agent ID backend. Proposed additions, each narrower than the `ReadWrite.All` that §14.3 already allows:

| Permission | Needed for | Evidence |
|---|---|---|
| `AgentIdentity.EnableDisable.All` | Disable an agent identity (ADR-006 step 1); documented least-privileged *update* permission | W04 403 |
| `AgentIdentity.DeleteRestore.All` | Delete or restore agent identities (lifecycle soft-delete) | C01 403 |
| `AgentIdentityBlueprint.DeleteRestore.All` | Delete blueprints when an agent definition retires; cascades to its agent identities | C02 403 |

Confirmed after granting: `AgentIdentityBlueprint.DeleteRestore.All` works only on `DELETE /applications/{id}`, not on the documented typed-cast path (403). See learning notes.

### Amendment (2026-11-01): blueprint principal delete, approved by Paul and applied
| Permission | Needed for | Evidence |
|---|---|---|
| `AgentIdentityBlueprintPrincipal.DeleteRestore.All` | Delete a blueprint principal: the middle step of retiring a blueprint (agents -> blueprint principal -> blueprint, because deletes don't cascade). Soft-delete, restorable for 30 days. | Seed cleanup: 403 on both `DELETE /servicePrincipals/{id}` and the typed-cast path, although the provisioner owns the principal. Graph Explorer can't consent to Agent ID scopes, so a human couldn't delete it either. |

Not on `policy.high_risk_permissions`. Declared in `wf-control-plane.yaml`, so the report-only control-plane check and NHI-007 expect it.

**Not proposed:** `AgentIdentity.ReadWrite.All`. If `EnableDisable.All` doesn't allow setting `tags`, ADR-006 falls back to the state file plus naming convention rather than widening the provisioner.
**Still provisional:** `AgentIdentity.Create.All`. W03 succeeded *with* it, so we don't yet know whether ownership alone would suffice.

### Read through the scanner, write through the provisioner
`plan` uses the scanner, for example to resolve sponsor UPNs to object IDs. Only `apply` uses the provisioner. So the provisioner never needs `User.Read*`, and a bug in `plan` can't write.

## Known risk: `AppRoleAssignment.ReadWrite.All`
This permission lets its holder grant **any** app role, including Graph roles, to **any** service principal, *including itself*. It's a well-known privilege-escalation path: a compromised provisioner can make itself Global-Admin-equivalent through `RoleManagement.ReadWrite.Directory`. Mitigations:
- The private key lives only on Paul's machine. CI never gets the provisioner, only the scanner and per-workflow NHIs.
- Discovery rule NHI-005 watches the provisioner's own grants (P9: the governance tooling is governed too).
- Phase 9: evaluate Conditional Access for workload identities to pin the provisioner to known IPs (P2 trial only).

## Note: Agent ID rejects broad delegated tokens
Agent ID APIs reject tokens carrying `Directory.AccessAsUser.All`, such as Azure CLI tokens. Always use the provisioner with client credentials.

## Alternatives rejected
- **Client secrets in a local `.env`**: violates P7.
- **One control-plane app with read and write**: a bug in the scanner could write. Splitting them also makes the scanner safe to run nightly in CI.
- **Managed identity**: needs Azure compute, which costs money (CLAUDE.md §3).
