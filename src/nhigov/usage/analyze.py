"""L3 unused-permission detection: granted - used, per NHI (ADR-007, NHI-012).

An app-only token carries every granted role on every call, so Entra can't say
which role was exercised. Our API can: it logs the role each allowed call needed
(`role_used`). Here the registry's grants on resources we own (`managed: true`,
the only ones whose usage we log) are compared with the roles the log shows in use.

Cadence keeps this from crying wolf. A role is only judged once the log covers
MIN_RUNS expected runs of the agent (3 days for a daily agent, 90 for a monthly
one). An on-demand agent has no rhythm to scale by, so it needs the whole window.
Until then the verdict is "too early", not "unused".

Coverage starts at the log's first event: before that we know nothing. As with
`lifecycle --as-of`, a later --as-of assumes the log is complete up to that date.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from nhigov.discovery.rules.base import Finding, Severity
from nhigov.reconcile.state import TenantState
from nhigov.registry.loader import Registry
from nhigov.registry.models import Cadence, WorkflowStatus

RULE_ID = "NHI-012"
MIN_RUNS = 3
PERIOD = {
    Cadence.HOURLY: timedelta(hours=1),
    Cadence.DAILY: timedelta(days=1),
    Cadence.WEEKLY: timedelta(days=7),
    Cadence.MONTHLY: timedelta(days=30),
}
RATIONALE = (
    "An app-only token carries every granted role on every call, so a role that's never "
    "exercised is pure exposure: a stolen credential gets it for free. Only the resource "
    "knows which role a call needed, which is why this comes from the API's usage log."
)


class Verdict(StrEnum):
    OK = "ok"  # every granted role was used
    UNUSED = "unused"  # some roles used, others not
    DORMANT = "dormant"  # granted roles, no allowed call at all
    TOO_EARLY = "too-early"  # the log doesn't cover enough expected runs yet
    SKIPPED = "skipped"  # held by the lifecycle, workflow not active, or not provisioned


@dataclass(frozen=True)
class Event:
    ts: datetime
    oid: str | None
    appid: str | None
    role_used: str | None
    outcome: str


@dataclass(frozen=True)
class NhiUsage:
    key: str  # "<workflow>/<agent>"
    workflow: str
    agent: str
    cadence: Cadence
    verdict: Verdict
    granted: dict[str, list[str]]  # resource -> roles the registry grants
    used: dict[str, int]  # role -> allowed calls in the window
    unused: dict[str, list[str]] = field(default_factory=dict)  # resource -> roles
    principal_id: str | None = None
    note: str = ""
    observed: timedelta = timedelta(0)  # log coverage since the NHI existed

    def finding(self) -> Finding | None:
        if self.verdict not in (Verdict.UNUSED, Verdict.DORMANT) or self.principal_id is None:
            return None
        roles = ", ".join(f"{res}:{r}" for res, rs in self.unused.items() for r in rs)
        days = _fmt(self.observed)
        if self.verdict is Verdict.DORMANT:
            message = f"no call used any granted role in {days} (expected {self.cadence})"
            remediation = (
                f"Confirm the workflow still runs. If not, set `status: suspended` (or "
                f"`retired`) in registry/workflows/{self.workflow}.yaml; the lifecycle "
                "engine then disables the NHI."
            )
        else:
            message = f"never used {roles} in {days} (expected {self.cadence})"
            remediation = (
                f"In registry/workflows/{self.workflow}.yaml, remove {roles} from "
                f"{self.agent}'s permissions. `nhigov apply` then revokes the grant."
            )
        return Finding(
            rule=RULE_ID,
            severity=Severity.MEDIUM,
            object_id=self.principal_id,
            display_name=f"nhi-{self.workflow}-{self.agent}",
            classification="managed",
            message=message,
            rationale=RATIONALE,
            remediation=remediation,
        )


@dataclass(frozen=True)
class UsageReport:
    as_of: datetime
    window: timedelta
    coverage_start: datetime | None  # the later of the window start and the log's first event
    results: list[NhiUsage]
    unattributed_calls: int  # calls from callers that aren't a registered NHI

    @property
    def span(self) -> timedelta:
        return self.as_of - self.coverage_start if self.coverage_start else timedelta(0)

    @property
    def findings(self) -> list[Finding]:
        return [f for r in self.results if (f := r.finding()) is not None]

    def to_json(self) -> dict[str, Any]:
        return {
            "as_of": self.as_of.isoformat(),
            "window_days": self.window.total_seconds() / 86400,
            "coverage_start": self.coverage_start.isoformat() if self.coverage_start else None,
            "unattributed_calls": self.unattributed_calls,
            "results": [
                {
                    "key": r.key, "verdict": r.verdict.value, "cadence": r.cadence.value,
                    "granted": r.granted, "used": r.used, "unused": r.unused, "note": r.note,
                }
                for r in self.results
            ],
            "findings": [f.model_dump(mode="json") | {"key": f.key} for f in self.findings],
        }  # fmt: skip


def parse_window(text: str) -> timedelta:
    """'30d' or '12h'."""
    unit = text[-1:].lower()
    if unit not in ("d", "h") or not text[:-1].isdigit() or int(text[:-1]) <= 0:
        raise ValueError(f"window must look like 30d or 12h, got {text!r}")
    n = int(text[:-1])
    return timedelta(days=n) if unit == "d" else timedelta(hours=n)


def load_events(path: Path) -> list[Event]:
    """The API's JSONL usage log. Malformed lines are skipped, not fatal."""
    if not path.exists():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            raw = json.loads(line)
            ts = datetime.fromisoformat(raw["ts"])
        except (ValueError, KeyError, TypeError):
            continue
        events.append(
            Event(
                ts, raw.get("oid"), raw.get("appid"), raw.get("role_used"), raw.get("outcome", "")
            )
        )
    return events


def required_span(cadence: Cadence, window: timedelta) -> timedelta:
    period = PERIOD.get(cadence)
    return window if period is None else period * MIN_RUNS


def analyze(
    events: Iterable[Event],
    registry: Registry,
    state: TenantState,
    window: timedelta,
    as_of: datetime,
    holds: dict[str, str] | None = None,
) -> UsageReport:
    holds = holds or {}
    logged = sorted((e for e in events if e.ts <= as_of), key=lambda e: e.ts)
    start = as_of - window
    coverage_start = max(start, logged[0].ts) if logged else None
    in_window = [e for e in logged if e.ts >= start]
    span = as_of - coverage_start if coverage_start else timedelta(0)

    owners: dict[str, str] = {}  # oid/appid -> NHI key
    for nhi_key, record in state.nhis.items():
        for ident in (record.principal_id, record.app_id):
            if ident:
                owners[ident] = nhi_key
    used: dict[str, dict[str, int]] = {}
    unattributed = 0
    for e in in_window:
        owner = owners.get(e.oid or "") or owners.get(e.appid or "")
        if owner is None:
            unattributed += e.oid is not None or e.appid is not None
            continue
        if e.outcome == "allowed" and e.role_used:
            tally = used.setdefault(owner, {})
            tally[e.role_used] = tally.get(e.role_used, 0) + 1

    logged_resources = {r.id for r in registry.resources.values() if r.managed}
    results = []
    for wf in sorted(registry.workflows.values(), key=lambda w: w.id):
        for wa in wf.agents:
            key = f"{wf.id}/{wa.ref}"
            granted = {
                p.resource: sorted(p.app_roles)
                for p in wa.permissions if p.resource in logged_resources
            }  # fmt: skip
            if not granted:
                continue
            counts = used.get(key, {})
            rec = state.nhis.get(key)
            need = required_span(wa.expected_cadence, window)
            created = rec.created_at if rec else None
            observed = span if created is None else min(span, max(as_of - created, timedelta(0)))
            unused = {
                res: missing
                for res, roles in granted.items()
                if (missing := [r for r in roles if r not in counts])
            }
            note = ""
            if rec is None:
                verdict, note = Verdict.SKIPPED, "not provisioned"
            elif key in holds:
                verdict, note = Verdict.SKIPPED, f"held by the lifecycle: {holds[key]}"
            elif wf.status is not WorkflowStatus.ACTIVE:
                verdict, note = Verdict.SKIPPED, f"workflow is {wf.status}"
            elif observed < need:
                verdict = Verdict.TOO_EARLY
                rhythm = (
                    "an on-demand agent needs the whole window"
                    if wa.expected_cadence is Cadence.ON_DEMAND
                    else f"a {wa.expected_cadence} agent needs {MIN_RUNS} runs"
                )
                since = "since it was created" if observed < span else "of the window"
                note = f"log covers {_fmt(observed)} {since}; {rhythm} ({_fmt(need)})"
                if need > window:
                    note += f" (raise --window to {_fmt(need)})"
            else:
                verdict = (
                    Verdict.OK if not unused else Verdict.UNUSED if counts else Verdict.DORMANT
                )
            results.append(
                NhiUsage(
                    key,
                    wf.id,
                    wa.ref,
                    wa.expected_cadence,
                    verdict,
                    granted,
                    counts,
                    unused if verdict in (Verdict.UNUSED, Verdict.DORMANT) else {},
                    rec.principal_id if rec else None,
                    note,
                    observed,
                )
            )
    return UsageReport(as_of, window, coverage_start, results, unattributed)


def _fmt(span: timedelta) -> str:
    hours = span.total_seconds() / 3600
    return f"{hours / 24:.0f}d" if hours >= 24 else f"{hours:.0f}h"


def write_report(report: UsageReport, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"usage-{report.as_of.strftime('%Y-%m-%d')}.json"
    path.write_bytes(json.dumps(report.to_json(), indent=2).encode("utf-8"))
    return path
