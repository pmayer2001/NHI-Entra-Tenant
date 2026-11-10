"""Role -> field visibility (P4: restrict data, not just systems).

Each role gets an explicit view. A field missing from a view is omitted, so a
field added to the data later is invisible until someone grants it here.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

REDACTED = "[REDACTED]"


class Show(StrEnum):
    CLEAR = "clear"
    MASKED = "masked"  # present, so the caller knows the field exists, but value withheld


METADATA = ("id", "status", "created_at", "updated_at")
# ADR-004's sensitive fields, plus the claimant's name (2026-11-01): triage needs
# the claim, not who made it, so no agent role sees a person's identity.
PII = ("claimant_name", "ssn", "date_of_birth", "account_number")

VIEWS: dict[str, dict[str, Show]] = {
    "Records.Read.Metadata": dict.fromkeys(METADATA, Show.CLEAR),
    "Records.Read.Redacted": {
        **dict.fromkeys(METADATA, Show.CLEAR),
        **dict.fromkeys(("claim_type", "amount", "description"), Show.CLEAR),
        **dict.fromkeys(PII, Show.MASKED),
        "notes": Show.CLEAR,
    },
    # Human-only role (member_types: [User]); no agent can be assigned it.
    "Records.Read.All": {
        **dict.fromkeys(METADATA, Show.CLEAR),
        **dict.fromkeys(("claim_type", "amount", "description"), Show.CLEAR),
        **dict.fromkeys(PII, Show.CLEAR),
        "notes": Show.CLEAR,
    },
}


def render(record: dict[str, Any], role: str) -> dict[str, Any]:
    """The record as `role` may see it. Unknown roles see nothing (fail closed)."""
    view = VIEWS.get(role, {})
    out: dict[str, Any] = {}
    for name, show in view.items():
        if name in record:
            out[name] = record[name] if show is Show.CLEAR else REDACTED
    return out
