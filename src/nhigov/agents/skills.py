"""Skills: pure functions an agent calls. They take data, not credentials (P5).

A skill can only see what its calling agent's role let the API return, so the
same skill run by a less-privileged agent sees less. No skill holds a token.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def summarize_text(text: str, max_words: int = 12) -> str:
    words = text.split()
    head = " ".join(words[:max_words])
    return f"{head}{'…' if len(words) > max_words else ''} ({len(words)} words)"


def classify_priority(record: dict[str, Any]) -> str:
    amount = float(record.get("amount") or 0)
    if amount >= 5000:
        return "high"
    return "medium" if amount >= 1000 else "low"


ROUTES = {"new": "intake", "in_review": "adjuster", "approved": "closeout", "denied": "closeout"}
ESCALATE_AFTER_DAYS = 30


def route_by_rules(record: dict[str, Any], now: datetime | None = None) -> str | None:
    """Queue for a record from metadata alone, or None if it needs no routing (closed)."""
    queue = ROUTES.get(str(record.get("status")))
    if queue is None:
        return None
    created = datetime.fromisoformat(str(record["created_at"]))
    if ((now or datetime.now(UTC)) - created).days > ESCALATE_AFTER_DAYS and queue != "closeout":
        return "escalation"
    return queue
