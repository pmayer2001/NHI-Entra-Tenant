"""Entra Agent ID backend: blueprint per agent definition, agent identity per NHI.

Request shapes come from the Phase 0 spike, which created exactly these objects:
blueprint (POST /applications with @odata.type), certificate (PATCH on the
typed-cast URL), blueprint principal, then agent identities from the blueprint.

Agent identities can't be tagged (Phase 0, W04), so one found by name is only
adopted when it was created from *our* blueprint: name alone isn't proof.
"""

from __future__ import annotations

from nhigov.backends.base import Principals
from nhigov.certs import key_credential, load_local_cert
from nhigov.reconcile.desired import Desired, DesiredBlueprint, DesiredNhi
from nhigov.reconcile.engine import IdentityPlan, JsonDict, PlanContext, PlanError, Step
from nhigov.registry.models import Backend

BP_COLLECTION = "applications/microsoft.graph.agentIdentityBlueprint"
BP_PRINCIPALS = "servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal"
AGENTS = "servicePrincipals/microsoft.graph.agentIdentity"
BP_SELECT = "id,appId,displayName,tags,keyCredentials"
AGENT_SELECT = "id,appId,displayName,accountEnabled,agentIdentityBlueprintId"
LOCAL_RUNTIME_LABEL = "nhigov local runtime"


def credential_notes(
    ctx: PlanContext, cert_name: str, current: list[JsonDict], label: str
) -> tuple[JsonDict | None, list[str]]:
    """(keyCredentials body to upload, or None; notes). Uploads only when there's no
    credential yet: replacing one is rotation, a lifecycle action (§8, Phase 6)."""
    cert = load_local_cert(cert_name, ctx.cert_dir)
    if cert is None:
        return None, [
            f"{label}: no local certificate; run `nhigov cert new {cert_name}`, then plan again"
        ]
    notes = []
    policy = ctx.registry.policy
    max_days = policy.max_credential_lifetime_days if policy else 180
    # The certificate's own lifetime, not "expiry minus today": comparing a UTC expiry
    # with a local date was off by one in the evening (found on the live run).
    if cert.lifetime_days > max_days:
        notes.append(
            f"{label}: local certificate is valid {cert.lifetime_days} days, over the "
            f"{max_days}-day policy (NHI-004)"
        )
    if cert.not_after.date() < ctx.today:
        notes.append(f"{label}: local certificate expired on {cert.not_after.date()}")
    if any(k.get("customKeyIdentifier") == cert.thumbprint_b64 for k in current):
        return None, notes
    if current:
        return None, [
            *notes,
            f"{label}: has a credential that isn't the local certificate; rotation is a "
            "Phase 6 lifecycle action, so plan leaves it alone",
        ]
    return {"keyCredentials": [key_credential(cert, LOCAL_RUNTIME_LABEL)]}, notes


class AgentIdBackend:
    kind = Backend.AGENT_ID

    def plan(self, ctx: PlanContext, desired: Desired, plan: IdentityPlan) -> Principals:
        bp_app_ids: dict[str, str | None] = {
            agent_id: self._plan_blueprint(ctx, bp, plan)
            for agent_id, bp in desired.blueprints.items()
        }
        principals: Principals = {}
        for nhi in desired.nhis.values():
            if nhi.backend is not self.kind:
                continue
            found, exists = self._plan_agent(ctx, nhi, bp_app_ids.get(nhi.agent_id), plan)
            if exists:
                principals[nhi.key] = found
        return principals

    # ------------------------------------------------------------------ blueprints

    def _plan_blueprint(
        self, ctx: PlanContext, bp: DesiredBlueprint, plan: IdentityPlan
    ) -> str | None:
        """Returns the blueprint's appId if it exists now, else None (created by this plan)."""
        rec = ctx.state.blueprints.get(bp.agent_id)
        if rec is not None:
            app = ctx.get_or_none(
                f"applications/{rec.application_object_id}/microsoft.graph.agentIdentityBlueprint",
                BP_SELECT,
                after_create=True,
            )
            if app is None:
                raise PlanError(
                    f"state says {bp.name} is {rec.application_object_id}, but the tenant doesn't "
                    "return it; check Entra before editing state (plan won't recreate it)"
                )
        else:
            app = ctx.find_by_name(BP_COLLECTION, bp.name, BP_SELECT)
            if app is not None and "nhigov:managed" not in (app.get("tags") or []):
                raise PlanError(f"{bp.name} exists but isn't tagged nhigov:managed; won't adopt it")

        if app is None:
            plan.steps.append(
                Step(
                    "blueprint.create",
                    bp.agent_id,
                    f"blueprint {bp.name}",
                    "POST /v1.0/applications",
                    {
                        "@odata.type": "Microsoft.Graph.AgentIdentityBlueprint",
                        "displayName": bp.name,
                        "sponsors@odata.bind": ctx.sponsor_bind(bp.sponsor_upns),
                        "tags": ["nhigov:managed", f"nhigov:agent={bp.agent_id}"],
                    },
                )
            )
            plan.steps.append(self._principal_step(bp))
            body, notes = credential_notes(ctx, bp.name, [], bp.name)
            plan.notes += notes
            if body:
                plan.steps.append(self._credential_step(bp, body))
            return None

        principal = ctx.graph.get(
            BP_PRINCIPALS, params={"$filter": f"appId eq '{app['appId']}'", "$select": "id"}
        ).get("value", [])
        found = {
            "application_object_id": app["id"],
            "app_id": app["appId"],
            "principal_id": principal[0]["id"] if principal else None,
        }
        if rec is None or rec.model_dump() != found:
            plan.steps.append(
                Step("blueprint.adopt", bp.agent_id, f"blueprint {bp.name}", "(state only)", found)
            )
        if not principal:
            plan.steps.append(self._principal_step(bp))
        else:
            self._plan_principal_grants(ctx, bp, principal[0]["id"], plan)
        body, notes = credential_notes(ctx, bp.name, app.get("keyCredentials") or [], bp.name)
        plan.notes += notes
        if body:
            plan.steps.append(self._credential_step(bp, body))
        if note := ctx.sponsors_note(
            f"applications/{app['id']}/microsoft.graph.agentIdentityBlueprint/sponsors",
            bp.sponsor_upns,
            bp.name,
        ):
            plan.notes.append(note)
        app_id: str = app["appId"]
        return app_id

    @staticmethod
    def _allowed_graph_roles(ctx: PlanContext) -> tuple[str, dict[str, str], set[str]]:
        graph_sp, roles = ctx.graph_sp()
        policy = ctx.registry.policy
        allowed = set(policy.blueprint_graph_grants) if policy else set()
        return graph_sp, roles, {rid for rid, value in roles.items() if value in allowed}

    @staticmethod
    def _principal_step(bp: DesiredBlueprint) -> Step:
        return Step(
            "blueprint.principal",
            bp.agent_id,
            f"blueprint principal for {bp.name}",
            f"POST /v1.0/{BP_PRINCIPALS}",
            {"appId": f"<{bp.name}.appId>"},
        )

    def _plan_principal_grants(
        self, ctx: PlanContext, bp: DesiredBlueprint, principal: str, plan: IdentityPlan
    ) -> None:
        """A blueprint principal holds only the Graph roles policy allows: least privilege for
        the object whose key reaches all its agents. Entra's own CreateAsManager grant is
        system-managed (can't be revoked), so policy lists it; anything else is revoked."""
        graph_sp, roles, keep = self._allowed_graph_roles(ctx)
        for a in ctx.graph.list_all(f"servicePrincipals/{principal}/appRoleAssignments"):
            if a.get("resourceId") == graph_sp and a["appRoleId"] not in keep:
                role = roles.get(a["appRoleId"], a["appRoleId"])
                plan.steps.append(
                    Step(
                        "blueprint.revoke",
                        bp.agent_id,
                        f"Graph {role} from the principal of {bp.name} (not in policy)",
                        f"DELETE /v1.0/servicePrincipals/{principal}/appRoleAssignments/{a['id']}",
                        {"assignmentId": a["id"], "role": role},
                    )
                )

    @staticmethod
    def _credential_step(bp: DesiredBlueprint, body: JsonDict) -> Step:
        shown = {
            "keyCredentials": [{**k, "key": "<public certificate>"} for k in body["keyCredentials"]]
        }
        return Step(
            "blueprint.credential",
            bp.agent_id,
            f"certificate on {bp.name} (public key only)",
            f"PATCH /v1.0/applications/<{bp.name}.id>/microsoft.graph.agentIdentityBlueprint",
            body,
            (f"display: {shown['keyCredentials'][0]['displayName']}",),
        )

    # ------------------------------------------------------------------ agent identities

    def _plan_agent(
        self, ctx: PlanContext, nhi: DesiredNhi, bp_app_id: str | None, plan: IdentityPlan
    ) -> tuple[str | None, bool]:
        """(principal ID if it exists now, whether it will exist after apply)."""
        rec = ctx.state.nhis.get(nhi.key)
        if rec is not None and rec.principal_id:
            agent = ctx.get_or_none(
                f"servicePrincipals/{rec.principal_id}/microsoft.graph.agentIdentity",
                AGENT_SELECT,
                after_create=True,
            )
            if agent is None:
                raise PlanError(
                    f"state says {nhi.name} is {rec.principal_id}, but the tenant doesn't return "
                    "it; check Entra before editing state (plan won't recreate it)"
                )
        else:
            agent = ctx.find_by_name(AGENTS, nhi.name, AGENT_SELECT)
            if agent is not None and agent.get("agentIdentityBlueprintId") != bp_app_id:
                raise PlanError(
                    f"{nhi.name} exists but wasn't created from bp-{nhi.agent_id}; agent "
                    "identities can't be tagged, so a name match alone isn't enough to adopt it"
                )

        if agent is None:
            if not nhi.should_be_enabled:
                if nhi.should_exist:
                    plan.notes.append(f"{nhi.name}: workflow is {nhi.status}; not creating it")
                return None, False
            plan.steps.append(
                Step(
                    "agent.create",
                    nhi.key,
                    f"agent identity {nhi.name}",
                    f"POST /v1.0/{AGENTS}",
                    {
                        "displayName": nhi.name,
                        "agentIdentityBlueprintId": f"<bp-{nhi.agent_id}.appId>",
                        "sponsors@odata.bind": ctx.sponsor_bind((nhi.sponsor_upn,)),
                    },
                )
            )
            return None, True

        if agent.get("agentIdentityBlueprintId") != bp_app_id and bp_app_id is not None:
            raise PlanError(f"{nhi.name} belongs to a different blueprint than bp-{nhi.agent_id}")
        found = {
            "backend": self.kind.value,
            "principal_id": agent["id"],
            "app_id": agent["appId"],
            "application_object_id": None,
            "blueprint": nhi.agent_id,
        }
        if rec is None or rec.model_dump(exclude={"created_at"}) != found:
            plan.steps.append(
                Step("agent.adopt", nhi.key, f"agent identity {nhi.name}", "(state only)", found)
            )
        if not nhi.should_exist:
            plan.notes.append(f"{nhi.name}: exists, but its workflow is 'requested'")
        elif agent.get("accountEnabled") != nhi.should_be_enabled:
            op = "enable" if nhi.should_be_enabled else "disable"
            plan.steps.append(
                Step(
                    f"agent.{op}",
                    nhi.key,
                    f"agent identity {nhi.name} (workflow {nhi.status})",
                    f"PATCH /v1.0/servicePrincipals/{agent['id']}/microsoft.graph.agentIdentity",
                    {"accountEnabled": nhi.should_be_enabled},
                )
            )
        if note := ctx.sponsors_note(
            f"servicePrincipals/{agent['id']}/microsoft.graph.agentIdentity/sponsors",
            (nhi.sponsor_upn,),
            nhi.name,
        ):
            plan.notes.append(note)
        principal_id: str = agent["id"]
        return principal_id, nhi.should_exist
