"""Agent stubs, skills and credential resolution (offline)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import respx

from nhigov.agents.identity import NotProvisioned, credentials_for
from nhigov.agents.skills import classify_priority, route_by_rules, summarize_text
from nhigov.agents.stubs import router, summarizer
from nhigov.reconcile.state import BlueprintRecord, NhiRecord, TenantState

API = "http://api.test"
NOW = datetime(2026, 11, 1, tzinfo=UTC)


def test_skills_are_pure_and_deterministic() -> None:
    assert summarize_text("one two three", max_words=2) == "one two… (3 words)"
    assert classify_priority({"amount": 9000}) == "high"
    assert classify_priority({"amount": 10}) == "low"
    fresh = {"status": "new", "created_at": "2026-10-25T00:00:00+00:00"}
    stale = {"status": "in_review", "created_at": "2026-09-01T00:00:00+00:00"}
    assert route_by_rules(fresh, NOW) == "intake"
    assert route_by_rules(stale, NOW) == "escalation"
    assert route_by_rules({"status": "closed", "created_at": fresh["created_at"]}, NOW) is None


@respx.mock
def test_summarizer_reads_only_the_records_it_is_given() -> None:
    route = respx.get(f"{API}/records/rec-0002").respond(
        json={
            "id": "rec-0002",
            "amount": 1200,
            "description": "a b c",
            "claimant_name": "[REDACTED]",
            "ssn": "[REDACTED]",
        }
    )
    with httpx.Client(base_url=API) as api:
        lines = summarizer(api, ["rec-0002"], 5)
    assert route.called
    assert lines == ["rec-0002: [medium] a b c (3 words)  claimant=[REDACTED] ssn=[REDACTED]"]


@respx.mock
def test_router_lists_then_annotates_and_reports_refusals() -> None:
    respx.get(f"{API}/records").respond(
        json=[
            {"id": "r1", "status": "new", "created_at": datetime.now(UTC).isoformat()},
            {"id": "r2", "status": "closed", "created_at": datetime.now(UTC).isoformat()},
        ]
    )
    respx.post(f"{API}/records/r1/notes").respond(403)  # e.g. the demo NHI: no Annotate
    with httpx.Client(base_url=API) as api:
        lines = router(api, [], 5)
    assert lines == [
        "r1: new -> intake (note refused: 403, this identity doesn't hold Records.Annotate)",
        "r2: closed, no routing needed",
    ]


def test_credentials_follow_the_backend(tmp_path: Path) -> None:
    state = TenantState(
        blueprints={"agent-a": BlueprintRecord(application_object_id="o", app_id="bp-app")},
        nhis={
            "wf-x/agent-a": NhiRecord(backend="agent_id", principal_id="p", app_id="ai-app",
                                      blueprint="agent-a"),
            "wf-y/agent-a": NhiRecord(backend="service_principal", principal_id="q",
                                      app_id="sp-app", application_object_id="o2"),
        },
    )  # fmt: skip
    agent = credentials_for("wf-x/agent-a", state, tmp_path)
    assert (agent.client_id, agent.blueprint_app_id) == ("ai-app", "bp-app")
    assert agent.pem == tmp_path / "bp-agent-a.pem"  # the blueprint's key, not the agent's
    sp = credentials_for("wf-y/agent-a", state, tmp_path)
    assert (sp.client_id, sp.blueprint_app_id) == ("sp-app", None)
    assert sp.pem == tmp_path / "nhi-wf-y-agent-a.pem"
    with pytest.raises(NotProvisioned):
        credentials_for("wf-z/agent-a", state, tmp_path)
