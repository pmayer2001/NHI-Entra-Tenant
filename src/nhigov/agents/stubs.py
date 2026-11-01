"""The agent programs. Each receives an HTTP client already carrying its token.

They're written to need exactly the roles the registry grants them, so running
them is also a check that the grants are sufficient (positive half of P8).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

import httpx

from nhigov.agents.skills import classify_priority, route_by_rules, summarize_text

DEFAULT_RECORDS = ("rec-0001", "rec-0002", "rec-0003")

Stub = Callable[[httpx.Client, Sequence[str], int], list[str]]


def summarizer(api: httpx.Client, record_ids: Sequence[str], limit: int) -> list[str]:
    """Needs Records.Read.Redacted. It can't list records (no Metadata role in
    claims triage), so it's handed record IDs, as a router would in a real flow."""
    out = []
    for record_id in list(record_ids or DEFAULT_RECORDS)[:limit]:
        response = api.get(f"/records/{record_id}")
        response.raise_for_status()
        record = response.json()
        out.append(
            f"{record_id}: [{classify_priority(record)}] {summarize_text(record['description'])}"
            # shown on purpose: both must read [REDACTED] for an agent
            f"  claimant={record.get('claimant_name')} ssn={record.get('ssn')}"
        )
    return out


def router(api: httpx.Client, record_ids: Sequence[str], limit: int) -> list[str]:
    """Needs Records.Read.Metadata (to list) and Records.Annotate (to leave a note)."""
    response = api.get("/records")
    response.raise_for_status()
    records = [r for r in response.json() if not record_ids or r["id"] in record_ids]
    out = []
    for record in records[:limit]:
        queue = route_by_rules(record)
        if queue is None:
            out.append(f"{record['id']}: {record['status']}, no routing needed")
            continue
        note = api.post(
            f"/records/{record['id']}/notes", json={"text": f"routed to {queue} by agent-router"}
        )
        if note.status_code == 403:
            result = "note refused: 403, this identity doesn't hold Records.Annotate"
        else:
            note.raise_for_status()
            result = f"note {note.status_code}"
        out.append(f"{record['id']}: {record['status']} -> {queue} ({result})")
    return out


STUBS: dict[str, Stub] = {"agent-summarizer": summarizer, "agent-router": router}
