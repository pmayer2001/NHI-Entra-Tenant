"""L3 usage analytics (Phase 7): granted - used, scaled by expected cadence (NHI-012)."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from nhigov.reconcile.state import NhiRecord, TenantState
from nhigov.registry.loader import load_registry
from nhigov.registry.models import Cadence
from nhigov.usage.analyze import (
    Event,
    UsageReport,
    Verdict,
    analyze,
    load_events,
    parse_window,
)

REGISTRY, _ = load_registry(Path(__file__).parents[2] / "registry")
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
ROUTER = "wf-claims-triage/agent-router"  # daily; Metadata + Annotate
SUMMARIZER = "wf-claims-triage/agent-summarizer"  # daily; Redacted
SP_DEMO = "wf-sp-backend-demo/agent-router"  # on-demand; Metadata


def _state() -> TenantState:
    return TenantState(
        nhis={
            k: NhiRecord(backend="agent_id", principal_id=f"p-{k}", app_id=f"p-{k}")
            for k in (ROUTER, SUMMARIZER)
        }
        | {
            SP_DEMO: NhiRecord(
                backend="service_principal", principal_id="sp-demo", app_id="a-demo"
            ),
            "wf-lifecycle-test/agent-router": NhiRecord(backend="agent_id", principal_id="p-lt"),
        }
    )


def _call(key: str, role: str | None, days_ago: float, outcome: str = "allowed") -> Event:
    return Event(NOW - timedelta(days=days_ago), f"p-{key}", f"p-{key}", role, outcome)


def _run(
    events: list[Event], window: str = "30d", holds: dict[str, str] | None = None
) -> UsageReport:
    return analyze(events, REGISTRY, _state(), parse_window(window), NOW, holds)


def _result(report: UsageReport, key: str) -> Verdict:
    return next(r.verdict for r in report.results if r.key == key)


def test_an_over_granted_agent_is_flagged_with_the_registry_change() -> None:
    # The router lists records every day for 5 days but never writes a note.
    events = [_call(ROUTER, "Records.Read.Metadata", d) for d in range(5)]
    events += [_call(SUMMARIZER, "Records.Read.Redacted", d) for d in range(5)]
    report = _run(events)

    router = next(r for r in report.results if r.key == ROUTER)
    assert router.verdict is Verdict.UNUSED
    assert router.unused == {"res-sensitive-records": ["Records.Annotate"]}
    assert router.used == {"Records.Read.Metadata": 5}
    assert _result(report, SUMMARIZER) is Verdict.OK

    [finding] = report.findings
    assert finding.rule == "NHI-012"
    assert finding.object_id == f"p-{ROUTER}"
    assert "res-sensitive-records:Records.Annotate" in finding.message
    assert "registry/workflows/wf-claims-triage.yaml" in finding.remediation
    assert "nhigov apply" in finding.remediation


def test_a_daily_agent_is_not_judged_before_three_days_of_log() -> None:
    # Only a day of log: the router may simply not have needed to annotate yet.
    events = [_call(ROUTER, "Records.Read.Metadata", d) for d in (0, 0.5, 1)]
    report = _run(events)
    assert _result(report, ROUTER) is Verdict.TOO_EARLY
    assert report.findings == []


def test_a_registered_agent_that_never_calls_is_dormant() -> None:
    # The summarizer's calls give the log 5 days of coverage; the router never shows up.
    report = _run([_call(SUMMARIZER, "Records.Read.Redacted", d) for d in range(5)])
    assert _result(report, ROUTER) is Verdict.DORMANT
    [finding] = report.findings
    assert "no call used any granted role" in finding.message
    assert "status: suspended" in finding.remediation


def test_an_on_demand_agent_needs_the_whole_window() -> None:
    events = [_call(SUMMARIZER, "Records.Read.Redacted", 10)]
    assert _result(_run(events, "30d"), SP_DEMO) is Verdict.TOO_EARLY
    assert _result(_run(events, "7d"), SP_DEMO) is Verdict.DORMANT


def test_a_monthly_agent_asks_for_a_longer_window() -> None:
    registry = copy.deepcopy(REGISTRY)
    wf = registry.workflows["wf-claims-triage"]
    agents = [
        a.model_copy(update={"expected_cadence": Cadence.MONTHLY}) if a.ref == "agent-router" else a
        for a in wf.agents
    ]
    registry.workflows[wf.id] = wf.model_copy(update={"agents": agents})
    events = [_call(SUMMARIZER, "Records.Read.Redacted", d) for d in range(29)]
    report = analyze(events, registry, _state(), parse_window("30d"), NOW)
    router = next(r for r in report.results if r.key == ROUTER)
    assert router.verdict is Verdict.TOO_EARLY
    assert "raise --window to 90d" in router.note


def test_denied_calls_are_not_usage_and_strangers_are_counted() -> None:
    events = [_call(ROUTER, "Records.Read.Metadata", d) for d in range(5)]
    events.append(_call(ROUTER, None, 1, outcome="forbidden"))  # tried to annotate, refused
    events.append(
        Event(NOW - timedelta(days=1), "stranger", "stranger", "Records.Read.Metadata", "allowed")
    )
    report = _run(events)
    assert _result(report, ROUTER) is Verdict.UNUSED
    assert report.unattributed_calls == 1


def test_lifecycle_holds_and_events_outside_the_window_are_ignored() -> None:
    events = [_call(ROUTER, "Records.Annotate", 40)]  # before the window
    events += [_call(ROUTER, "Records.Read.Metadata", d) for d in range(5)]
    report = _run(events, holds={"wf-lifecycle-test/agent-router": "sponsor disabled"})
    assert _result(report, ROUTER) is Verdict.UNUSED
    held = next(r for r in report.results if r.key == "wf-lifecycle-test/agent-router")
    assert held.verdict is Verdict.SKIPPED
    assert "held by the lifecycle" in held.note


def test_graph_permissions_are_out_of_scope_for_l3() -> None:
    # The control plane only holds Graph roles: we don't log Graph usage (ADR-007).
    report = _run([])
    assert all(not r.key.startswith("wf-control-plane/") for r in report.results)
    assert report.coverage_start is None


@pytest.mark.parametrize("bad", ["30", "d", "0d", "-3d", "2w"])
def test_window_must_be_days_or_hours(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_window(bad)
    assert parse_window("12h") == timedelta(hours=12)


def test_load_events_skips_malformed_lines(tmp_path: Path) -> None:
    log = tmp_path / "usage.log"
    good = {"ts": "2026-11-01T02:26:29.109+00:00", "oid": "x", "appid": "x",
            "role_used": "Records.Read.Metadata", "outcome": "allowed"}  # fmt: skip
    log.write_text(json.dumps(good) + "\nnot json\n{}\n", encoding="utf-8")
    [event] = load_events(log)
    assert event.role_used == "Records.Read.Metadata"
    assert load_events(tmp_path / "missing.log") == []


def test_an_nhi_is_only_judged_on_time_since_it_was_created() -> None:
    # The log covers 5 days, but the router was created a day ago: too early to say.
    state = _state()
    state.nhis[ROUTER].created_at = NOW - timedelta(days=1)
    events = [_call(SUMMARIZER, "Records.Read.Redacted", d) for d in range(5)]
    report = analyze(events, REGISTRY, state, parse_window("30d"), NOW)
    router = next(r for r in report.results if r.key == ROUTER)
    assert router.verdict is Verdict.TOO_EARLY
    assert "since it was created" in router.note
