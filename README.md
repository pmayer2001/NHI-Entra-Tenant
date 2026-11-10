# nhigov: NHI governance for agentic workflows on Microsoft Entra ID

`nhigov` runs a Microsoft Entra ID tenant as the identity provider for AI agents. It provisions, scopes, discovers, monitors and retires the **non-human identities (NHIs)** that agents use, with least privilege enforced down to individual data fields. It's built to run on a **free** Entra ID tenant; paid Entra features are emulated in code (see [free-vs-paid](docs/free-vs-paid.md)).

## What it does

| Capability | Command | Design |
|---|---|---|
| Registry of AI workflows, agents and resources as YAML in git, validated offline | `nhigov validate` | [ADR-001](docs/decisions/ADR-001-registry-in-git.md), [ADR-008](docs/decisions/ADR-008-registry-schema-and-validation.md) |
| Plan/apply reconciler: Agent ID blueprints and agent identities (or service principals), certificates, role grants | `nhigov plan`, `nhigov apply` | [ADR-003](docs/decisions/ADR-003-identity-backend-adapter.md), [ADR-006](docs/decisions/ADR-006-plan-apply-reconciler.md), [ADR-010](docs/decisions/ADR-010-reconciler.md) |
| Mock Sensitive Records API: JWT validation, role-based field redaction, usage log | `nhigov api serve` | [ADR-004](docs/decisions/ADR-004-data-level-least-privilege.md), [ADR-009](docs/decisions/ADR-009-resource-token-validation-and-redaction.md) |
| Deterministic agent runtimes that call the API as their own NHI | `nhigov agent run <workflow> <agent>` | [ADR-005](docs/decisions/ADR-005-authentication-without-secrets.md) |
| Discovery scanner: inventory every NHI, flag shadow, over-privileged and orphaned identities (NHI-001…013) | `nhigov scan` | [ADR-011](docs/decisions/ADR-011-discovery.md) |
| Lifecycle engine: expiry, sponsor departure, retirement, certificate rotation | `nhigov lifecycle status\|run\|rotate\|policy` | [ADR-012](docs/decisions/ADR-012-lifecycle.md) |
| Unused-permission analytics from the API's usage log (NHI-012) | `nhigov usage analyze` | [ADR-007](docs/decisions/ADR-007-unused-permission-detection.md), [ADR-013](docs/decisions/ADR-013-usage-analytics.md) |
| Capability probe: which Entra features this tenant allows | `nhigov probe` | [capability matrix](docs/capability-matrix.md) |
| GitHub Actions runtime: agents and the nightly scan sign in with the job's OIDC token through federated credentials, no secrets | `nhigov ci vars` | [ADR-014](docs/decisions/ADR-014-github-actions-runtime.md) |

The rules it enforces are in [docs/principles.md](docs/principles.md).

## Getting started

**[docs/setup.md](docs/setup.md)** walks through everything that happens outside this repo:
- creating a free Entra tenant and a cost alert;
- registering the scanner and provisioner apps, with each Graph permission they need and why;
- certificates and configuration;
- creating the agents with `plan`/`apply`, and running them;
- the optional GitHub Actions setup (environments, variables and federated credentials).

It ends with troubleshooting for the errors you're most likely to hit.

Without a tenant, you can still run the offline checks:

```bash
uv sync
uv run pytest tests/unit
uv run nhigov validate
```

## Commands

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src/ services/
uv run pytest tests/unit                  # offline; Graph mocked with respx
uv run pytest tests/authz                 # live tenant: needs certs in ~/.nhigov/certs/
uv run nhigov cert new nhigov-scanner     # self-signed cert -> ~/.nhigov/certs/ (upload the .cer)
uv run nhigov -v probe                    # capability probe: reads run; writes are planned only
uv run nhigov validate                    # offline registry check
uv run nhigov api probe                   # read-only checks before registering the API
uv run nhigov api gate-check              # live: unassigned clients must be refused a token (AADSTS501051)
uv run nhigov api serve                   # Sensitive Records API on 127.0.0.1:8000
uv run nhigov agent run wf-claims-triage agent-summarizer   # an agent calls the API as its NHI
uv run nhigov plan                        # read-only diff as the scanner
uv run nhigov apply                       # writes as the provisioner, after a confirmation
uv run nhigov scan                        # read-only discovery -> reports/
uv run python scripts/seed_mess.py plant  # dry run; --execute plants misconfigured test NHIs
uv run nhigov lifecycle status            # read-only: each NHI's lifecycle state, what's due
uv run nhigov lifecycle run --as-of DATE  # dry run; --execute disables/deletes
uv run nhigov lifecycle rotate bp-agent-router   # dry run; --execute rotates the certificate
uv run nhigov lifecycle policy            # dry run; --execute blocks secrets tenant-wide
uv run nhigov usage analyze --window 30d  # offline: granted - used per NHI from the API log
uv run nhigov ci vars                     # GitHub environment variables for the CI runtime
uv run nhigov scan --summary-only         # counts only, for CI logs; exits 1 on critical/high
```

Every command that writes to the tenant prints a plan first and asks before writing.
