"""A validation finding. Same shape the Phase 5 discovery rules will use."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Severity(StrEnum):
    ERROR = "error"  # blocks the registry (CI fails, reconciler refuses to plan)
    WARNING = "warning"  # worth a human look, never blocks


@dataclass(frozen=True)
class Finding:
    rule: str  # e.g. "REG-007"
    severity: Severity
    message: str
    subject: str = ""  # registry ID (or file path for parse errors) the finding is about
