"""An in-memory Entra tenant behind respx, for plan/apply tests.

It reproduces behaviour seen on the live tenant (or documented), because a fake
that's kinder than Entra lets a non-converging reconciler pass:
* objects come back with extra fields and defaults filled in;
* a new service principal gets its application's tags, whatever was sent;
* keyCredentials come back without `key`, identified by `customKeyIdentifier`;
* an enabled app role can't be deleted;
* reading sponsors needs AgentIdentity.ReadWrite.All, which the scanner lacks (403);
* agent identities have no tags, and appId == id;
* objects created seconds ago can be "not found" (configurable lag);
* a new blueprint principal is granted Graph AgentIdentity.CreateAsManager, and that
  grant can't be deleted (system-managed).
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import uuid
from typing import Any

import httpx
import respx

V1 = "/v1.0/"
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
BP_TYPE = "Microsoft.Graph.AgentIdentityBlueprint"
AUTO_GRANT = "AgentIdentity.CreateAsManager"


def _json(data: Any, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=data)


def _error(status: int, code: str, message: str = "") -> httpx.Response:
    return _json({"error": {"code": code, "message": message or code}}, status)


def _name_filter(request: httpx.Request) -> str:
    return request.url.params["$filter"].split("'")[1]


class FakeTenant:
    def __init__(
        self, sp_lag_failures: int = 0, agent_lag_failures: int = 0, fic_name_lag: int = 0
    ) -> None:
        self.apps: dict[str, dict[str, Any]] = {}
        self.sps: dict[str, dict[str, Any]] = {}
        self.assignments: dict[str, list[dict[str, Any]]] = {}
        self.fics: dict[str, list[dict[str, Any]]] = {}  # application object ID -> FICs
        self.users: dict[str, str] = {}
        # A deleted credential's name stays taken for this many POSTs (replication lag).
        self.fic_name_lag = fic_name_lag
        self.fic_names_lagging: dict[str, int] = {}
        self.sp_lag_failures = sp_lag_failures
        self.agent_lag_failures = agent_lag_failures
        self.writes: list[str] = []

    # ------------------------------------------------------------------ seeding

    def add_user(self, upn: str) -> str:
        self.users[upn] = str(uuid.uuid5(uuid.NAMESPACE_DNS, upn))
        return self.users[upn]

    def add_graph_sp(self, roles: list[str]) -> None:
        self.sps["graph-sp"] = {
            "id": "graph-sp", "appId": GRAPH_APP_ID, "kind": "sp", "tags": [],
            "appRoles": [{"id": f"role-{r}", "value": r} for r in roles],
        }  # fmt: skip

    def add_client(self, sp_id: str, app_id: str, graph_roles: list[str]) -> None:
        self.sps[sp_id] = {"id": sp_id, "appId": app_id, "kind": "sp", "tags": []}
        self.assignments[sp_id] = [
            {"id": f"a-{sp_id}-{r}", "resourceId": "graph-sp", "appRoleId": f"role-{r}"}
            for r in graph_roles
        ]

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _key_creds(creds: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = []
        for c in creds:
            thumb = base64.b64encode(hashlib.sha1(base64.b64decode(c["key"])).digest()).decode()  # noqa: S324
            out.append({
                "customKeyIdentifier": thumb, "displayName": c.get("displayName"),
                "type": c["type"], "usage": c["usage"], "keyId": str(uuid.uuid4()),
            })  # fmt: skip
        return out

    @staticmethod
    def _as_graph_returns(app: dict[str, Any]) -> dict[str, Any]:
        app = copy.deepcopy(app)
        app.setdefault("tags", [])
        app.setdefault("keyCredentials", [])
        app["api"] = {
            "acceptMappedClaims": None, "knownClientApplications": [],
            "oauth2PermissionScopes": [], "preAuthorizedApplications": [],
            "requestedAccessTokenVersion": None, **(app.get("api") or {}),
        }  # fmt: skip
        for role in app.get("appRoles", []):
            role["origin"] = "Application"
        claims = app.get("optionalClaims") or {}
        app["optionalClaims"] = {
            "idToken": [], "saml2Token": [],
            "accessToken": [{**c, "source": None} for c in claims.get("accessToken", [])],
        }  # fmt: skip
        return app

    def blueprints(self) -> list[dict[str, Any]]:
        return [a for a in self.apps.values() if a.get("@odata.type") == BP_TYPE]

    def agents(self) -> list[dict[str, Any]]:
        return [s for s in self.sps.values() if s["kind"] == "agentIdentity"]

    # ------------------------------------------------------------------ routes

    def install(self) -> None:
        def user(request: httpx.Request, upn: str) -> httpx.Response:
            if upn not in self.users:
                return _error(404, "Request_ResourceNotFound")
            return _json({"id": self.users[upn]})

        # applications ------------------------------------------------
        def list_apps(request: httpx.Request) -> httpx.Response:
            name = _name_filter(request)
            return _json({"value": [a for a in self.apps.values() if a["displayName"] == name]})

        def list_blueprints(request: httpx.Request) -> httpx.Response:
            name = _name_filter(request)
            return _json({"value": [a for a in self.blueprints() if a["displayName"] == name]})

        def create_app(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            oid, app_id = str(uuid.uuid4()), str(uuid.uuid4())
            body.pop("sponsors@odata.bind", None)
            if "keyCredentials" in body:
                body["keyCredentials"] = self._key_creds(body["keyCredentials"])
            self.apps[oid] = self._as_graph_returns({**body, "id": oid, "appId": app_id})
            self.writes.append("POST applications")
            return _json(self.apps[oid], 201)

        def get_app(request: httpx.Request, oid: str) -> httpx.Response:
            if oid not in self.apps:
                return _error(404, "Request_ResourceNotFound")
            return _json(self.apps[oid])

        def patch_app(request: httpx.Request, oid: str) -> httpx.Response:
            if oid not in self.apps:
                return _error(404, "Request_ResourceNotFound")
            body = json.loads(request.content)
            roles = body.get("appRoles")
            if roles is not None:
                kept = {r["id"] for r in roles}
                for r in self.apps[oid].get("appRoles", []):
                    if r["id"] not in kept and r["isEnabled"]:
                        return _error(400, "CannotDeleteEnabledRole")
            if "keyCredentials" in body:
                body["keyCredentials"] = self._key_creds(body["keyCredentials"])
            self.apps[oid] = self._as_graph_returns({**self.apps[oid], **body})
            self.writes.append("PATCH applications")
            return httpx.Response(204)

        def forbidden(request: httpx.Request, **_: str) -> httpx.Response:
            return _error(403, "Authorization_RequestDenied", "Insufficient privileges")

        # service principals ------------------------------------------
        def by_app_id(kind: str | None) -> Any:
            def handler(request: httpx.Request) -> httpx.Response:
                app_id = _name_filter(request)
                found = [
                    s for s in self.sps.values()
                    if s["appId"] == app_id and (kind is None or s["kind"] == kind)
                ]  # fmt: skip
                return _json({"value": found})

            return handler

        def create_sp(request: httpx.Request) -> httpx.Response:
            if self.sp_lag_failures:
                self.sp_lag_failures -= 1
                return _error(403, "Authorization_RequestDenied")
            body = json.loads(request.content)
            app = next(a for a in self.apps.values() if a["appId"] == body["appId"])
            oid = str(uuid.uuid4())
            # Observed live: the new SP gets its application's tags.
            self.sps[oid] = {
                "accountEnabled": True, "appRoleAssignmentRequired": False, **body,
                "tags": [*app.get("tags", []), "WindowsAzureActiveDirectoryIntegratedApp"],
                "id": oid, "kind": "sp",
            }  # fmt: skip
            self.writes.append("POST servicePrincipals")
            return _json(self.sps[oid], 201)

        def patch_sp(request: httpx.Request, oid: str) -> httpx.Response:
            self.sps[oid].update(json.loads(request.content))
            self.writes.append("PATCH servicePrincipals")
            return httpx.Response(204)

        def create_bp_principal(request: httpx.Request) -> httpx.Response:
            app_id = json.loads(request.content)["appId"]
            if not any(a["appId"] == app_id for a in self.blueprints()):
                return _error(400, "Request_BadRequest", "blueprint does not exist")
            oid = str(uuid.uuid4())
            self.sps[oid] = {"id": oid, "appId": app_id, "kind": "blueprintPrincipal", "tags": []}
            # Observed live: Entra grants every new blueprint principal this role.
            graph = self.sps.get("graph-sp", {})
            if any(r["value"] == AUTO_GRANT for r in graph.get("appRoles", [])):
                auto = {"id": f"auto-{oid}", "resourceId": "graph-sp"}
                self.assignments[oid] = [{**auto, "appRoleId": f"role-{AUTO_GRANT}"}]
            self.writes.append("POST blueprintPrincipal")
            return _json(self.sps[oid], 201)

        def list_agents(request: httpx.Request) -> httpx.Response:
            name = _name_filter(request)
            return _json({"value": [s for s in self.agents() if s["displayName"] == name]})

        def create_agent(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            bp_app_id = body["agentIdentityBlueprintId"]
            has_principal = any(
                s["kind"] == "blueprintPrincipal" and s["appId"] == bp_app_id
                for s in self.sps.values()
            )
            if self.agent_lag_failures or not has_principal:
                self.agent_lag_failures = max(0, self.agent_lag_failures - 1)
                return _error(400, "Request_BadRequest", "blueprint principal does not exist")
            oid = str(uuid.uuid4())
            self.sps[oid] = {
                "id": oid, "appId": oid, "kind": "agentIdentity", "accountEnabled": True,
                "displayName": body["displayName"], "agentIdentityBlueprintId": bp_app_id,
            }  # fmt: skip
            self.writes.append("POST agentIdentity")
            return _json(self.sps[oid], 201)

        def get_agent(request: httpx.Request, oid: str) -> httpx.Response:
            sp = self.sps.get(oid)
            if sp is None or sp["kind"] != "agentIdentity":
                return _error(404, "Request_ResourceNotFound")
            return _json(sp)

        def patch_agent(request: httpx.Request, oid: str) -> httpx.Response:
            body = json.loads(request.content)
            if set(body) - {"accountEnabled"}:  # EnableDisable.All covers accountEnabled only
                return _error(403, "Authorization_RequestDenied")
            self.sps[oid].update(body)
            self.writes.append("PATCH agentIdentity")
            return httpx.Response(204)

        # federated identity credentials ------------------------------
        def list_fics(request: httpx.Request, oid: str) -> httpx.Response:
            if oid not in self.apps:
                return _error(404, "Request_ResourceNotFound")
            return _json({"value": self.fics.get(oid, [])})

        def add_fic(request: httpx.Request, oid: str) -> httpx.Response:
            if oid not in self.apps:
                return _error(404, "Request_ResourceNotFound")
            body = json.loads(request.content)
            if self.fic_names_lagging.get(body["name"], 0) > 0:
                self.fic_names_lagging[body["name"]] -= 1
                return _error(409, "Request_MultipleObjectsWithSameKeyValue")
            if any(f["name"] == body["name"] for f in self.fics.get(oid, [])):
                return _error(409, "Request_MultipleObjectsWithSameKeyValue")
            fic = {"id": str(uuid.uuid4()), **body}
            self.fics.setdefault(oid, []).append(fic)
            self.writes.append("POST federatedIdentityCredential")
            return _json(fic, 201)

        def delete_fic(request: httpx.Request, oid: str, fid: str) -> httpx.Response:
            for f in self.fics.get(oid, []):
                if f["id"] == fid:
                    self.fic_names_lagging[f["name"]] = self.fic_name_lag
            self.fics[oid] = [f for f in self.fics.get(oid, []) if f["id"] != fid]
            self.writes.append("DELETE federatedIdentityCredential")
            return httpx.Response(204)

        # role assignments --------------------------------------------
        def list_assignments(request: httpx.Request, oid: str) -> httpx.Response:
            return _json({"value": self.assignments.get(oid, [])})

        def add_assignment(request: httpx.Request, oid: str) -> httpx.Response:
            body = json.loads(request.content)
            if oid not in self.sps or body["resourceId"] not in self.sps:
                return _error(400, "Request_BadRequest", "principal does not exist")
            a = {"id": str(uuid.uuid4()), **body}
            self.assignments.setdefault(oid, []).append(a)
            self.writes.append("POST appRoleAssignment")
            return _json(a, 201)

        def delete_assignment(request: httpx.Request, oid: str, aid: str) -> httpx.Response:
            if aid.startswith("auto-"):  # observed live: system-managed, not deletable
                message = "EntitlementGrants can be updated only through a source."
                return _error(400, "Request_BadRequest", message)
            self.assignments[oid] = [a for a in self.assignments.get(oid, []) if a["id"] != aid]
            self.writes.append("DELETE appRoleAssignment")
            return httpx.Response(204)

        R = r"(?P<oid>[^/]+)"
        BP = r"microsoft\.graph\.agentIdentityBlueprint"
        routes: list[tuple[str, str, Any]] = [
            ("GET", r"users/(?P<upn>[^/]+)", user),
            ("GET", r"applications/microsoft\.graph\.agentIdentityBlueprint", list_blueprints),
            ("GET", rf"applications/{R}/{BP}/sponsors", forbidden),
            ("GET", rf"applications/{R}/(?:{BP}/)?federatedIdentityCredentials", list_fics),
            ("POST", rf"applications/{R}/(?:{BP}/)?federatedIdentityCredentials", add_fic),
            ("DELETE", rf"applications/{R}/(?:{BP}/)?federatedIdentityCredentials/(?P<fid>[^/]+)",
             delete_fic),
            ("GET", rf"applications/{R}/microsoft\.graph\.agentIdentityBlueprint", get_app),
            ("PATCH", rf"applications/{R}/microsoft\.graph\.agentIdentityBlueprint", patch_app),
            ("GET", r"applications", list_apps),
            ("POST", r"applications", create_app),
            ("GET", rf"applications/{R}", get_app),
            ("PATCH", rf"applications/{R}", patch_app),
            ("GET", r"servicePrincipals/microsoft\.graph\.agentIdentityBlueprintPrincipal",
             by_app_id("blueprintPrincipal")),
            ("POST", r"servicePrincipals/microsoft\.graph\.agentIdentityBlueprintPrincipal",
             create_bp_principal),
            ("GET", r"servicePrincipals/microsoft\.graph\.agentIdentity", list_agents),
            ("POST", r"servicePrincipals/microsoft\.graph\.agentIdentity", create_agent),
            ("GET", rf"servicePrincipals/{R}/microsoft\.graph\.agentIdentity/sponsors", forbidden),
            ("GET", rf"servicePrincipals/{R}/microsoft\.graph\.agentIdentity", get_agent),
            ("PATCH", rf"servicePrincipals/{R}/microsoft\.graph\.agentIdentity", patch_agent),
            ("GET", rf"servicePrincipals/{R}/appRoleAssignments", list_assignments),
            ("POST", rf"servicePrincipals/{R}/appRoleAssignments", add_assignment),
            ("DELETE", rf"servicePrincipals/{R}/appRoleAssignments/(?P<aid>[^/]+)",
             delete_assignment),
            ("GET", r"servicePrincipals", by_app_id(None)),
            ("POST", r"servicePrincipals", create_sp),
            ("PATCH", rf"servicePrincipals/{R}", patch_sp),
        ]  # fmt: skip
        for method, path, handler in routes:
            respx.route(method=method, path__regex=rf"^{V1}{path}$").mock(side_effect=handler)
