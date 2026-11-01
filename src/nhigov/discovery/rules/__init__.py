"""Discovery rules (CLAUDE.md §7), one module per rule. NHI-012 arrives in Phase 7."""

from __future__ import annotations

from nhigov.discovery.inventory import Inventory
from nhigov.discovery.rules import (
    nhi_001_shadow,
    nhi_002_no_sponsor,
    nhi_003_client_secret,
    nhi_004_credential_lifetime,
    nhi_005_high_risk_permission,
    nhi_006_directory_role,
    nhi_007_permission_drift,
    nhi_008_shared_nhi,
    nhi_009_human_role,
    nhi_010_past_expiry,
    nhi_011_blueprint_credentials,
    nhi_013_orphaned_agent,
)
from nhigov.discovery.rules.base import Finding, Rule, ScanContext

RULES: tuple[Rule, ...] = (
    nhi_001_shadow.RULE,
    nhi_002_no_sponsor.RULE,
    nhi_003_client_secret.RULE,
    nhi_004_credential_lifetime.RULE,
    nhi_005_high_risk_permission.RULE,
    nhi_006_directory_role.RULE,
    nhi_007_permission_drift.RULE,
    nhi_008_shared_nhi.RULE,
    nhi_009_human_role.RULE,
    nhi_010_past_expiry.RULE,
    nhi_011_blueprint_credentials.RULE,
    nhi_013_orphaned_agent.RULE,
)


def run_rules(inventory: Inventory, ctx: ScanContext) -> list[Finding]:
    findings = [f for rule in RULES for f in rule.run(inventory, ctx)]
    return sorted(findings, key=lambda f: (f.severity.rank, f.rule, f.display_name))
