"""Normalize the raw snapshot into one record per NHI, linked to the registry.

One record per identity: an app registration and its service principal are one
NHI (the app holds credentials, the SP holds grants), and a blueprint plus its
blueprint principal are one blueprint.

Classification (§7):
  managed                 nhigov knows it (state file, or a control-plane client ID)
  microsoft-first-party   owned by Microsoft's tenant
  third-party-consented   owned by another organization, consented into this one
  shadow                  created in this tenant, but nhigov doesn't know it
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from nhigov.discovery.collectors import RawTenant
from nhigov.reconcile.state import TenantState

MICROSOFT_ORGS = {
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a",  # Microsoft Services
    "72f988bf-86f1-41af-91ab-2d7cd011db47",  # Microsoft
}
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

Classification = Literal["managed", "microsoft-first-party", "third-party-consented", "shadow"]
Kind = Literal["application", "agent_identity", "blueprint", "managed_identity", "resource"]


class Party(BaseModel):
    """An owner or sponsor."""

    id: str
    kind: Literal["user", "servicePrincipal", "other"]
    name: str | None = None
    enabled: bool | None = None
    member: bool | None = None  # False for guests


class Credential(BaseModel):
    kind: Literal["secret", "certificate", "federated"]
    on: Literal["application", "servicePrincipal"]
    name: str | None = None
    start: datetime | None = None
    end: datetime | None = None
    subject: str | None = None  # federated credentials: who may exchange tokens

    @property
    def lifetime_days(self) -> int | None:
        if self.start is None or self.end is None:
            return None
        return (self.end - self.start).days


class Grant(BaseModel):
    """An app role held by this NHI (an application permission)."""

    resource_id: str
    resource_name: str
    resource_app_id: str
    role_id: str
    role: str
    member_types: list[str] = Field(default_factory=list)


class Nhi(BaseModel):
    id: str  # service principal ID, or the application's ID if it has no SP
    kind: Kind
    display_name: str
    app_id: str | None = None
    application_object_id: str | None = None
    service_principal_id: str | None = None
    classification: Classification
    enabled: bool | None = None
    tags: list[str] = Field(default_factory=list)
    owners: list[Party] = Field(default_factory=list)
    sponsors: list[Party] = Field(default_factory=list)
    credentials: list[Credential] = Field(default_factory=list)
    grants: list[Grant] = Field(default_factory=list)
    delegated_scopes: list[str] = Field(default_factory=list)
    directory_roles: list[str] = Field(default_factory=list)
    blueprint_app_id: str | None = None  # agent identities
    blueprint_exists: bool | None = None
    # "workflow:<wf>/<agent>", "blueprint:<agent>", "resource:<id>", "control:<agent>"
    registry_keys: list[str] = Field(default_factory=list)
    workflows: list[str] = Field(default_factory=list)  # from registry keys and tags

    @property
    def tenant_owned(self) -> bool:
        return self.classification in ("managed", "shadow")


class Person(BaseModel):
    id: str
    upn: str
    enabled: bool
    member: bool


class Inventory(BaseModel):
    collected_at: datetime
    nhis: list[Nhi]
    people: dict[str, Person] = Field(default_factory=dict)  # by ID and lower-case UPN

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.model_dump_json(indent=2).encode("utf-8"))

    @classmethod
    def load(cls, path: Path) -> Inventory:
        return cls.model_validate_json(path.read_text(encoding="utf-8"))


# ------------------------------------------------------------------ building


def _dt(value: Any) -> datetime | None:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None


def _credentials(
    obj: dict[str, Any], on: Literal["application", "servicePrincipal"]
) -> list[Credential]:
    creds = [
        Credential(kind="secret", on=on, name=c.get("displayName"),
                   start=_dt(c.get("startDateTime")), end=_dt(c.get("endDateTime")))
        for c in obj.get("passwordCredentials") or []
    ] + [
        Credential(kind="certificate", on=on, name=c.get("displayName"),
                   start=_dt(c.get("startDateTime")), end=_dt(c.get("endDateTime")))
        for c in obj.get("keyCredentials") or []
    ]  # fmt: skip
    creds += [
        Credential(kind="federated", on=on, name=f.get("name"), subject=f.get("subject"))
        for f in obj.get("federatedIdentityCredentials") or []
    ]
    return creds


def _parties(objs: list[dict[str, Any]], people: dict[str, Person]) -> list[Party]:
    out = []
    for o in objs:
        odata = str(o.get("@odata.type", ""))
        kind: Literal["user", "servicePrincipal", "other"] = (
            "user" if odata.endswith(".user") or o["id"] in people
            else "servicePrincipal" if odata.endswith(".servicePrincipal")
            else "other"
        )  # fmt: skip
        person = people.get(o["id"])
        out.append(
            Party(
                id=o["id"], kind=kind,
                name=o.get("userPrincipalName") or o.get("displayName"),
                enabled=person.enabled if person else o.get("accountEnabled"),
                member=person.member if person else None,
            )
        )  # fmt: skip
    return out


def _registry_index(state: TenantState, control_clients: dict[str, str]) -> dict[str, str]:
    """Object ID or appId -> registry key."""
    index: dict[str, str] = {}
    for rid, res in state.resources.items():
        for oid in (res.application_object_id, res.service_principal_id):
            if oid:
                index[oid] = f"resource:{rid}"
    for agent, bp in state.blueprints.items():
        for oid in (bp.application_object_id, bp.principal_id):
            if oid:
                index[oid] = f"blueprint:{agent}"
    for key, nhi in state.nhis.items():
        for oid in (nhi.principal_id, nhi.application_object_id):
            if oid:
                index[oid] = f"workflow:{key}"
    for agent, client_id in control_clients.items():
        index[client_id] = f"control:{agent}"
    return index


def build_inventory(
    raw: RawTenant, state: TenantState, control_clients: dict[str, str], now: datetime
) -> Inventory:
    people = {
        k: Person(id=u["id"], upn=u["userPrincipalName"], enabled=bool(u.get("accountEnabled")),
                  member=u.get("userType") != "Guest")
        for k, u in raw.users.items()
    }  # fmt: skip
    index = _registry_index(state, control_clients)
    sps_by_id = {sp["id"]: sp for sp in raw.service_principals}
    apps_by_app_id = {a["appId"]: a for a in raw.applications}
    blueprint_app_ids = {a["appId"] for a in raw.applications if a["id"] in raw.blueprint_ids}
    delegated: dict[str, list[str]] = {}
    for g in raw.delegated_grants:
        delegated.setdefault(g["clientId"], []).extend(str(g.get("scope", "")).split())

    def grants_of(sp: dict[str, Any]) -> list[Grant]:
        out = []
        for a in sp.get("appRoleAssignments", []):
            res = sps_by_id.get(a["resourceId"], {})
            role: dict[str, Any] = next(
                (r for r in res.get("appRoles", []) if r["id"] == a["appRoleId"]), {}
            )
            out.append(Grant(
                resource_id=a["resourceId"], resource_name=res.get("displayName", "?"),
                resource_app_id=res.get("appId", "?"), role_id=a["appRoleId"],
                role=role.get("value") or a["appRoleId"],
                member_types=role.get("allowedMemberTypes", []),
            ))  # fmt: skip
        return out

    nhis: list[Nhi] = []
    seen_apps: set[str] = set()
    for sp in raw.service_principals:
        app = apps_by_app_id.get(sp["appId"])
        if app is not None:
            seen_apps.add(app["id"])
        keys = sorted({k for oid in (sp["id"], sp["appId"], (app or {}).get("id")) if oid
                       for k in [index.get(oid)] if k})  # fmt: skip
        org = sp.get("appOwnerOrganizationId")
        classification: Classification = (
            "managed" if keys
            else "microsoft-first-party" if org in MICROSOFT_ORGS
            else "shadow" if sp.get("local")
            else "third-party-consented"
        )  # fmt: skip
        kind: Kind = (
            "agent_identity" if sp.get("agentKind") == "agentIdentity"
            else "blueprint" if sp.get("agentKind") == "blueprintPrincipal"
            or (app is not None and app["id"] in raw.blueprint_ids)
            else "managed_identity" if sp.get("servicePrincipalType") == "ManagedIdentity"
            else "resource" if any(k.startswith("resource:") for k in keys)
            else "application"
        )  # fmt: skip
        tags = sorted({*(sp.get("tags") or []), *((app or {}).get("tags") or [])})
        bp_app_id = sp.get("agentIdentityBlueprintId")
        nhis.append(Nhi(
            id=sp["id"], kind=kind, display_name=sp.get("displayName", "?"), app_id=sp["appId"],
            application_object_id=(app or {}).get("id"), service_principal_id=sp["id"],
            classification=classification, enabled=sp.get("accountEnabled"), tags=tags,
            owners=_parties([*(app or {}).get("owners", []), *sp.get("owners", [])], people),
            sponsors=_parties([*(app or {}).get("sponsors", []), *sp.get("sponsors", [])], people),
            credentials=_credentials(app, "application") + _credentials(sp, "servicePrincipal")
            if app else _credentials(sp, "servicePrincipal"),
            grants=grants_of(sp), delegated_scopes=sorted(set(delegated.get(sp["id"], []))),
            directory_roles=sorted(raw.directory_roles.get(sp["id"], [])),
            blueprint_app_id=bp_app_id,
            blueprint_exists=(bp_app_id in blueprint_app_ids) if bp_app_id else None,
            registry_keys=keys, workflows=_workflows(keys, tags),
        ))  # fmt: skip

    for app in raw.applications:  # app registrations with no service principal
        if app["id"] in seen_apps:
            continue
        keys = sorted({k for oid in (app["id"], app["appId"]) for k in [index.get(oid)] if k})
        tags = sorted(app.get("tags") or [])
        nhis.append(Nhi(
            id=app["id"], kind="blueprint" if app["id"] in raw.blueprint_ids else "application",
            display_name=app.get("displayName", "?"), app_id=app["appId"],
            application_object_id=app["id"], classification="managed" if keys else "shadow",
            tags=tags, owners=_parties(app.get("owners", []), people),
            sponsors=_parties(app.get("sponsors", []), people),
            credentials=_credentials(app, "application"), registry_keys=keys,
            workflows=_workflows(keys, tags),
        ))  # fmt: skip
    return Inventory(collected_at=now, nhis=nhis, people=people)


def _workflows(keys: list[str], tags: list[str]) -> list[str]:
    found = {k.split(":", 1)[1].split("/")[0] for k in keys if k.startswith("workflow:")}
    found |= {"wf-control-plane" for k in keys if k.startswith("control:")}
    found |= {t.split("=", 1)[1] for t in tags if t.startswith("nhigov:workflow=")}
    return sorted(found)
