# ADR-002: Python + raw Microsoft Graph over httpx, not `msgraph-sdk`

**Status:** Accepted (Phase 0). Implemented in `src/nhigov/graph/client.py`.

## Context
Every component (reconciler, discovery, lifecycle, probe) talks to Microsoft Graph. Agent ID object types are new, and their URLs use OData *typed casts* such as `/applications/microsoft.graph.agentIdentityBlueprint`.

## Decision
A thin, typed `GraphClient` built on `httpx`, with tokens from `azure-identity`. Nothing else in the codebase calls Graph directly.

## Why
1. Generated SDKs trail new API surface. Agent ID calls need `OData-Version: 4.0` and typed-cast URLs, which are trivial to send raw and awkward through an SDK.
2. Seeing the raw request and response is the point of a learning project.
3. Fewer dependencies, and `respx` makes the client easy to test offline.

## What the client handles (and why each matters)
| Concern | Behaviour | Why |
|---|---|---|
| Paging | Follows `@odata.nextLink` until exhausted | Graph caps pages (100 for Agent ID lists); stopping at page 1 hides NHIs from discovery |
| Throttling | Retries 429/503/504; uses `Retry-After` seconds, else exponential backoff capped at 60s | Graph throttles per app and tenant; ignoring `Retry-After` prolongs throttling |
| Eventual consistency | `get_after_create()` retries 404 with backoff (2s, 4s, 8s…) | A directory write can take seconds to reach the replica that serves your next read |
| OData v4 | Header added automatically for typed-cast URLs or `@odata.type` bodies | Required by Agent ID endpoints. Not sent otherwise, so we aren't relying on it by accident |
| Logging | One `structlog` line per HTTP attempt: method, path, status, `request-id`, elapsed ms | `request-id` is what Microsoft support asks for. Retries show up as separate lines |
| Errors | `GraphError` with status, Graph error `code`, message, `request-id` | The `code` tells a missing permission from a license gate (see probe) |

`check=False` returns the raw response instead of raising, so the probe can *record* failures rather than stop on them.

## Alternatives rejected
- **Terraform `azuread`**: no Agent ID resources, and discovery and analytics need Python anyway.
- **PowerShell (Microsoft.Graph / Microsoft.Entra modules)**: weaker for unit testing and data processing.
- **`msgraph-sdk`**: see Why (1) and (2).

## Consequences
- We maintain our own retry and paging logic (about 150 lines, unit tested).
- No typed models for Graph responses come for free. Collectors will define pydantic models only for the fields they use.
