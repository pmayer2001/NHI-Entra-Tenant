"""Registry validation (valid passes, each kind of invalid fails).

Each case copies the real `registry/` folder, breaks exactly one thing, and
asserts the expected rule fires. Using the real registry as the baseline means
the example we ship is itself under test.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import Any

import pytest
import respx
import yaml
from typer.testing import CliRunner

from nhigov.cli import app
from nhigov.config import load_owner
from nhigov.graph.client import GraphClient
from nhigov.registry.findings import Finding, Severity
from nhigov.registry.loader import load_registry
from nhigov.registry.online import validate_online
from nhigov.registry.validate import validate_registry

REPO_REGISTRY = Path(__file__).parents[2] / "registry"
TODAY = date(2026, 10, 31)
CLAIMS = "workflows/wf-claims-triage.yaml"
CONTROL = "workflows/wf-control-plane.yaml"
SUMMARIZER = "agents/agent-summarizer.yaml"


@pytest.fixture
def reg_dir(tmp_path: Path) -> Path:
    return Path(shutil.copytree(REPO_REGISTRY, tmp_path / "registry"))


def mutate(reg_dir: Path, rel: str, change: Callable[[dict[str, Any]], object]) -> None:
    path = reg_dir / rel
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    change(data)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def run(reg_dir: Path) -> list[Finding]:
    registry, findings = load_registry(reg_dir, "contoso.example")
    return findings + validate_registry(registry, today=TODAY)


def errors(findings: list[Finding]) -> set[str]:
    return {f.rule for f in findings if f.severity is Severity.ERROR}


def test_example_registry_is_valid_with_no_warnings(reg_dir: Path) -> None:
    assert run(reg_dir) == []


def _first_grant(d: dict[str, Any]) -> list[str]:
    roles: list[str] = d["agents"][0]["permissions"][0]["app_roles"]
    return roles


CASES: list[tuple[str, str, Callable[[dict[str, Any]], object], str]] = [
    # (case id, file, mutation, rule expected to fire as an error)
    ("unknown-field-typo", CLAIMS, lambda d: d.update(sponsr=d.pop("sponsor")), "REG-000"),
    ("missing-sponsor-P6", CLAIMS, lambda d: d.pop("sponsor"), "REG-000"),
    ("skill-with-permissions-P5", SUMMARIZER,
     lambda d: d.update(skills=[{"name": "x", "permissions": []}]), "REG-000"),
    ("review-after-expiry", CLAIMS, lambda d: d.update(review_by=date(2027, 6, 1)), "REG-000"),
    ("bad-upn", CLAIMS, lambda d: d.update(sponsor="owner"), "REG-000"),
    ("unknown-agent-ref", CLAIMS, lambda d: d["agents"][0].update(ref="agent-ghost"), "REG-003"),
    ("unknown-resource", CLAIMS,
     lambda d: d["agents"][0]["permissions"][0].update(resource="res-ghost"), "REG-004"),
    ("unknown-role", CLAIMS, lambda d: _first_grant(d).append("Records.Delete"), "REG-005"),
    ("human-role-to-agent-P4", CLAIMS,
     lambda d: _first_grant(d).append("Records.Read.All"), "REG-006"),
    ("human-role-in-max-P4", SUMMARIZER,
     lambda d: d["max_permissions"][0]["app_roles"].append("Records.Read.All"), "REG-006"),
    ("grant-exceeds-max-P2", CLAIMS,
     lambda d: _first_grant(d).append("Records.Annotate"), "REG-007"),
    ("same-agent-twice-P3", CLAIMS,
     lambda d: d["agents"].append(dict(d["agents"][0])), "REG-008"),
    ("expires-too-far-P6", CLAIMS, lambda d: d.update(expires=date(2028, 6, 1)), "REG-009"),
    ("high-risk-without-exception", CONTROL, lambda d: d.pop("exception"), "REG-010"),
    ("exception-expired", CONTROL,
     lambda d: d["exception"].update(expires=date(2026, 1, 1)), "REG-010"),
    ("bad-workflow-name", CLAIMS, lambda d: d.update(id="claims-triage"), "REG-011"),
    ("control-plane-unregistered-P9", CONTROL, lambda d: d["agents"].pop(0), "REG-012"),
    ("control-plane-retired-P9", CONTROL, lambda d: d.update(status="retired"), "REG-012"),
    ("classification-too-low", CLAIMS,
     lambda d: d.update(data_classification="internal"), "REG-013"),
]  # fmt: skip


@pytest.mark.parametrize(
    ("rel", "change", "rule"), [c[1:] for c in CASES], ids=[c[0] for c in CASES]
)
def test_invalid_registry_fails(
    reg_dir: Path, rel: str, change: Callable[[dict[str, Any]], object], rule: str
) -> None:
    mutate(reg_dir, rel, change)
    assert rule in errors(run(reg_dir))


def test_every_rule_has_a_failing_case() -> None:
    """Adding a rule without a test should fail here."""
    from nhigov.registry import validate

    rules = {name.split("_")[1] for name in dir(validate) if name.startswith("reg_0")}
    tested = {rule.split("-")[1] for *_, rule in CASES} | {"001", "002", "014"}
    assert {f"{int(r):03d}" for r in rules} <= tested


def test_duplicate_id_across_files(reg_dir: Path) -> None:
    shutil.copy(reg_dir / SUMMARIZER, reg_dir / "agents" / "copy.yaml")
    assert "REG-001" in errors(run(reg_dir))


def test_missing_policy(reg_dir: Path) -> None:
    (reg_dir / "policy.yaml").unlink()
    assert "REG-002" in errors(run(reg_dir))


def test_unused_agent_is_a_warning_not_an_error(reg_dir: Path) -> None:
    mutate(reg_dir, CLAIMS, lambda d: d["agents"].pop(1))  # drop agent-router everywhere
    (reg_dir / "workflows" / "wf-sp-backend-demo.yaml").unlink()
    (reg_dir / "workflows" / "wf-lifecycle-test.yaml").unlink()
    findings = run(reg_dir)
    assert errors(findings) == set()
    assert [(f.rule, f.subject) for f in findings] == [("REG-014", "agent-router")]


def test_expired_active_workflow_is_a_warning(reg_dir: Path) -> None:
    registry, _ = load_registry(reg_dir, "contoso.example")
    later = validate_registry(registry, today=date(2027, 4, 15))
    assert ("REG-009", "wf-claims-triage") in {(f.rule, f.subject) for f in later}
    assert all(f.severity is Severity.WARNING for f in later if f.rule == "REG-009")


def test_yaml_syntax_error_is_reported_not_raised(reg_dir: Path) -> None:
    (reg_dir / CLAIMS).write_text("kind: Workflow\nid: [unclosed\n", encoding="utf-8")
    assert "REG-000" in errors(run(reg_dir))


def test_tenant_domain_is_substituted_not_committed(reg_dir: Path) -> None:
    assert "{tenant_domain}" in (reg_dir / CLAIMS).read_text(encoding="utf-8")
    registry, _ = load_registry(reg_dir, "contoso.example")
    assert registry.workflows["wf-claims-triage"].sponsor == "owner@contoso.example"


# ------------------------------------------------------------------ online (REG-020)

GRAPH_USERS = "https://graph.microsoft.com/v1.0/users/"


@respx.mock
def test_online_flags_missing_disabled_and_guest_people(reg_dir: Path) -> None:
    mutate(reg_dir, CLAIMS, lambda d: d.update(sponsor="gone@contoso.example"))
    mutate(reg_dir, CLAIMS, lambda d: d.update(business_owner="guest@contoso.example"))
    mutate(reg_dir, CONTROL, lambda d: d.update(business_owner="off@contoso.example"))
    respx.get(f"{GRAPH_USERS}gone@contoso.example").respond(404, json={"error": {"code": "x"}})
    respx.get(f"{GRAPH_USERS}guest@contoso.example").respond(
        json={"accountEnabled": True, "userType": "Guest"}
    )
    respx.get(f"{GRAPH_USERS}off@contoso.example").respond(
        json={"accountEnabled": False, "userType": "Member"}
    )
    for ok in ("owner", "test-departing-sponsor"):
        respx.get(f"{GRAPH_USERS}{ok}@contoso.example").respond(
            json={"accountEnabled": True, "userType": "Member"}
        )
    registry, _ = load_registry(reg_dir, "contoso.example")
    with GraphClient(lambda: "t", sleep=lambda _: None) as graph:
        found = {(f.severity, f.message.split()[-1]) for f in validate_online(registry, graph)}
    assert (Severity.ERROR, "tenant") in found  # "... not found in tenant"
    assert (Severity.ERROR, "disabled") in found
    assert any(sev is Severity.WARNING for sev, _ in found)  # guest


# ------------------------------------------------------------------ CLI


def test_cli_exit_codes(reg_dir: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    missing_config = ["--config", str(tmp_path / "none.yaml")]
    ok = runner.invoke(app, ["validate", "--registry", str(reg_dir), *missing_config])
    assert ok.exit_code == 0, ok.output
    assert "valid: 0 errors" in ok.output

    mutate(reg_dir, CLAIMS, lambda d: _first_grant(d).append("Records.Read.All"))
    bad = runner.invoke(app, ["validate", "--registry", str(reg_dir), *missing_config])
    assert bad.exit_code == 1
    assert "REG-006" in bad.output


def test_owner_and_domain_are_filled_in_from_config() -> None:
    # Committed files say "{owner}@{tenant_domain}"; whoever runs the tenant sets both.
    registry, _ = load_registry(REPO_REGISTRY, "contoso.example", "alice")
    wf = registry.workflows["wf-claims-triage"]
    assert wf.sponsor == wf.business_owner == "alice@contoso.example"
    assert load_owner(Path("missing.yaml"), {"NHIGOV_OWNER": " alice\n"}) == "alice"
