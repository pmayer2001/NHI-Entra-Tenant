"""The scan pipeline: collect (as the scanner) -> inventory -> rules. Read-only."""

from __future__ import annotations

from datetime import datetime

from nhigov.config import Config
from nhigov.discovery.collectors import collect_all
from nhigov.discovery.inventory import Inventory, build_inventory
from nhigov.discovery.rules import run_rules
from nhigov.discovery.rules.base import Finding, ScanContext
from nhigov.graph.auth import scanner_token
from nhigov.graph.client import GraphClient
from nhigov.reconcile.state import TenantState
from nhigov.registry.loader import Registry


def control_plane_clients(cfg: Config) -> dict[str, str]:
    return {
        "nhigov-scanner": cfg.control_plane.scanner.client_id,
        "nhigov-provisioner": cfg.control_plane.provisioner.client_id,
    }


def collect_inventory(
    cfg: Config, registry: Registry, state: TenantState, now: datetime
) -> Inventory:
    sponsors = {wf.sponsor for wf in registry.workflows.values()}
    with GraphClient(scanner_token(cfg), base_url=cfg.graph.base_url) as scanner:
        raw = collect_all(scanner, cfg.tenant_id, sponsors)
    return build_inventory(raw, state, control_plane_clients(cfg), now)


def evaluate(
    inventory: Inventory, registry: Registry, state: TenantState, now: datetime
) -> list[Finding]:
    resource_sps = {
        rec.service_principal_id: rid
        for rid, rec in state.resources.items()
        if rec.service_principal_id
    }
    return run_rules(inventory, ScanContext(registry, now, resource_sps))
