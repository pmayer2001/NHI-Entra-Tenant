"""Service-principal fallback backend: one app registration + SP per NHI (ADR-003).

Unlike Agent ID, each NHI has its *own* credential, so a stolen key reaches one
NHI only; the cost is no blueprint to manage them as a family, and no native
sponsor field (P6 is enforced from the registry alone on this backend).
"""

from __future__ import annotations

from nhigov.backends.agent_id import LOCAL_RUNTIME_LABEL, credential_notes
from nhigov.backends.base import Principals
from nhigov.certs import key_credential, load_local_cert
from nhigov.reconcile.desired import Desired, DesiredNhi
from nhigov.reconcile.engine import IdentityPlan, JsonDict, PlanContext, PlanError, Step
from nhigov.registry.models import Backend

APP_SELECT = "id,appId,displayName,tags,signInAudience,keyCredentials"
SP_SELECT = "id,appId,accountEnabled,tags"


def nhi_tags(nhi: DesiredNhi) -> list[str]:
    return ["nhigov:managed", f"nhigov:workflow={nhi.workflow_id}", f"nhigov:agent={nhi.agent_id}"]


class ServicePrincipalBackend:
    kind = Backend.SERVICE_PRINCIPAL

    def plan(self, ctx: PlanContext, desired: Desired, plan: IdentityPlan) -> Principals:
        principals: Principals = {}
        for nhi in desired.nhis.values():
            if nhi.backend is not self.kind:
                continue
            found, exists = self._plan_nhi(ctx, nhi, plan)
            if exists:
                principals[nhi.key] = found
        return principals

    def _find_app(self, ctx: PlanContext, nhi: DesiredNhi) -> JsonDict | None:
        rec = ctx.state.nhis.get(nhi.key)
        if rec is not None and rec.application_object_id:
            app = ctx.get_or_none(
                f"applications/{rec.application_object_id}", APP_SELECT, after_create=True
            )
            if app is None:
                raise PlanError(
                    f"state says {nhi.name} is {rec.application_object_id}, but the tenant doesn't "
                    "return it; check Entra before editing state (plan won't recreate it)"
                )
            return app
        app = ctx.find_by_name("applications", nhi.name, APP_SELECT)
        if app is not None and "nhigov:managed" not in (app.get("tags") or []):
            raise PlanError(f"{nhi.name} exists but isn't tagged nhigov:managed; won't adopt it")
        return app

    def _plan_nhi(
        self, ctx: PlanContext, nhi: DesiredNhi, plan: IdentityPlan
    ) -> tuple[str | None, bool]:
        app = self._find_app(ctx, nhi)
        tags = nhi_tags(nhi)
        if app is None:
            if not nhi.should_be_enabled:
                if nhi.should_exist:
                    plan.notes.append(f"{nhi.name}: workflow is {nhi.status}; not creating it")
                return None, False
            body: JsonDict = {
                "displayName": nhi.name,
                "signInAudience": "AzureADMyOrg",
                "tags": tags,
            }
            cert = load_local_cert(nhi.name, ctx.cert_dir)
            if cert is None:
                plan.notes.append(
                    f"{nhi.name}: no local certificate; run `nhigov cert new {nhi.name}` "
                    "(created without one; plan again to add it)"
                )
            else:
                body["keyCredentials"] = [key_credential(cert, LOCAL_RUNTIME_LABEL)]
            shown = {**body, "keyCredentials": ["<public certificate>"]} if cert else body
            plan.steps += [
                Step(
                    "spnhi.create",
                    nhi.key,
                    f"app registration {nhi.name}",
                    "POST /v1.0/applications",
                    body,
                    (f"body: {shown}",),
                ),
                Step(
                    "spnhi.principal",
                    nhi.key,
                    f"service principal for {nhi.name}",
                    "POST /v1.0/servicePrincipals",
                    {"tags": tags},
                ),
            ]
            return None, True

        sp_list = ctx.graph.get(
            "servicePrincipals",
            params={"$filter": f"appId eq '{app['appId']}'", "$select": SP_SELECT},
        ).get("value", [])
        sp = sp_list[0] if sp_list else None
        found = {
            "backend": self.kind.value,
            "principal_id": sp["id"] if sp else None,
            "app_id": app["appId"],
            "application_object_id": app["id"],
            "blueprint": None,
        }
        rec = ctx.state.nhis.get(nhi.key)
        if rec is None or rec.model_dump(exclude={"created_at"}) != found:
            plan.steps.append(
                Step("spnhi.adopt", nhi.key, f"app registration {nhi.name}", "(state only)", found)
            )

        patch: JsonDict = {}
        missing = [t for t in tags if t not in (app.get("tags") or [])]
        if missing:
            patch["tags"] = [*(app.get("tags") or []), *missing]
        if app.get("signInAudience") != "AzureADMyOrg":
            patch["signInAudience"] = "AzureADMyOrg"
        if patch:
            plan.steps.append(
                Step(
                    "spnhi.update",
                    nhi.key,
                    f"app registration {nhi.name}",
                    f"PATCH /v1.0/applications/{app['id']}",
                    patch,
                    tuple(sorted(patch)),
                )
            )
        cred, notes = credential_notes(ctx, nhi.name, app.get("keyCredentials") or [], nhi.name)
        plan.notes += notes
        if cred:
            plan.steps.append(
                Step(
                    "spnhi.credential",
                    nhi.key,
                    f"certificate on {nhi.name} (public key only)",
                    f"PATCH /v1.0/applications/{app['id']}",
                    cred,
                    ("keyCredentials",),
                )
            )

        if sp is None:
            if nhi.should_be_enabled:
                plan.steps.append(
                    Step(
                        "spnhi.principal",
                        nhi.key,
                        f"service principal for {nhi.name}",
                        "POST /v1.0/servicePrincipals",
                        {"tags": tags},
                    )
                )
                return None, True
            return None, False
        if not nhi.should_exist:
            plan.notes.append(f"{nhi.name}: exists, but its workflow is 'requested'")
        elif sp.get("accountEnabled", True) != nhi.should_be_enabled:
            op = "enable" if nhi.should_be_enabled else "disable"
            plan.steps.append(
                Step(
                    f"spnhi.{op}",
                    nhi.key,
                    f"service principal {nhi.name} (workflow {nhi.status})",
                    f"PATCH /v1.0/servicePrincipals/{sp['id']}",
                    {"accountEnabled": nhi.should_be_enabled},
                )
            )
        principal_id: str = sp["id"]
        return principal_id, nhi.should_exist
