"""Collectors: one module per Graph data source, all paged, all read-only.

`collect_all` returns the raw tenant snapshot that `inventory.build_inventory`
normalizes. Per-object calls (owners, assignments, credentials) are made only
for objects that belong to this tenant: Microsoft's hundreds of first-party
service principals are listed once and not expanded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from nhigov.discovery.collectors.applications import collect_applications
from nhigov.discovery.collectors.directory_roles import collect_directory_roles
from nhigov.discovery.collectors.grants import collect_delegated_grants
from nhigov.discovery.collectors.principals import collect_service_principals
from nhigov.discovery.collectors.users import collect_users
from nhigov.graph.client import GraphClient

JsonDict = dict[str, Any]


@dataclass
class RawTenant:
    tenant_id: str
    applications: list[JsonDict] = field(default_factory=list)
    blueprint_ids: set[str] = field(default_factory=set)
    service_principals: list[JsonDict] = field(default_factory=list)
    delegated_grants: list[JsonDict] = field(default_factory=list)
    directory_roles: dict[str, list[str]] = field(default_factory=dict)  # principal -> roles
    users: dict[str, JsonDict] = field(default_factory=dict)  # id and UPN -> user


def collect_all(graph: GraphClient, tenant_id: str, upns: set[str]) -> RawTenant:
    """`upns`: people the registry names (sponsors), looked up even if they own nothing."""
    applications, blueprint_ids = collect_applications(graph)
    local_app_ids = {a["appId"] for a in applications}
    sps = collect_service_principals(graph, tenant_id, local_app_ids)
    people = {
        o["id"]
        for obj in [*applications, *sps]
        for o in [*obj.get("owners", []), *obj.get("sponsors", [])]
        if o.get("@odata.type") == "#microsoft.graph.user"
    }
    return RawTenant(
        tenant_id=tenant_id,
        applications=applications,
        blueprint_ids=blueprint_ids,
        service_principals=sps,
        delegated_grants=collect_delegated_grants(graph),
        directory_roles=collect_directory_roles(graph),
        users=collect_users(graph, people | upns),
    )
