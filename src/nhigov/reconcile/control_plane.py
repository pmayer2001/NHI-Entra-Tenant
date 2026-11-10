"""Report-only check of the control plane's Graph permissions and CI sign-in (P9).

The provisioner and scanner were bootstrapped by hand and are never changed by
`apply` (decided 2026-11-01): a reconciler able to edit the
provisioner's own permissions is one bug away from granting itself more.
So plan compares what they hold with wf-control-plane.yaml and reports drift.

The same goes for their federated credentials, which are added by hand: an app
whose registry runtimes include `github-actions` should hold exactly the one
nhigov would create, and any other is a sign-in path nobody declared. Entra
stores a subject with a stray newline or space without complaint and then never
matches it (observed live), so a mismatch is shown with repr().
"""

from __future__ import annotations

from nhigov.graph.client import GraphClient
from nhigov.reconcile.desired import ControlPlaneGrants
from nhigov.reconcile.federated import EXCHANGE_AUDIENCE, GITHUB_ISSUER, WantedFic

MICROSOFT_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"


def graph_roles_held(graph: GraphClient, client_app_id: str) -> list[str] | None:
    """Microsoft Graph application permissions held by an app, or None if it isn't found."""
    sps = graph.get(
        "servicePrincipals", params={"$filter": f"appId eq '{client_app_id}'", "$select": "id"}
    ).get("value", [])
    graph_sp = graph.get(
        "servicePrincipals",
        params={"$filter": f"appId eq '{MICROSOFT_GRAPH_APP_ID}'", "$select": "id,appRoles"},
    ).get("value", [])
    if not sps or not graph_sp:
        return None
    names = {str(r["id"]): str(r["value"]) for r in graph_sp[0].get("appRoles", [])}
    return sorted(
        names.get(str(a["appRoleId"]), str(a["appRoleId"]))
        for a in graph.list_all(f"servicePrincipals/{sps[0]['id']}/appRoleAssignments")
        if a.get("resourceId") == graph_sp[0]["id"]
    )


def federated_notes(
    graph: GraphClient, cp: ControlPlaneGrants, client_id: str, subject_repo: str | None
) -> list[str]:
    apps = graph.get(
        "applications", params={"$filter": f"appId eq '{client_id}'", "$select": "id"}
    ).get("value", [])
    if not apps:
        return [f"{cp.agent_id}: app registration not found; federated credentials not checked"]
    found = graph.list_all(f"applications/{apps[0]['id']}/federatedIdentityCredentials")
    want = WantedFic(cp.workflow_id, subject_repo) if cp.in_github and subject_repo else None
    notes, matched = [], False
    for fic in found:
        name, subject = fic.get("name"), fic.get("subject")
        if (
            want is not None
            and name == want.name
            and fic.get("issuer") == GITHUB_ISSUER
            and subject == want.subject
            and list(fic.get("audiences") or []) == [EXCHANGE_AUDIENCE]
        ):
            matched = True
        elif want is not None and name == want.name:
            notes.append(
                f"{cp.agent_id}: federated credential {name} doesn't match; subject is "
                f"{subject!r}, expected {want.subject!r} (issuer {fic.get('issuer')}, "
                f"audiences {fic.get('audiences')}); fix it in the portal"
            )
        else:
            notes.append(
                f"{cp.agent_id}: undeclared federated credential {name!r} ({subject!r}); "
                "the registry doesn't list it, and it can mint tokens; remove it or declare "
                "the runtime"
            )
    if want is not None and not matched and not any(want.name in n for n in notes):
        notes.append(
            f"{cp.agent_id}: runs in GitHub Actions but has no federated credential "
            f"{want.name}; add it by hand (`nhigov ci vars` prints it)"
        )
    if want is not None and matched:
        notes.append(f"{cp.agent_id}: federated credential {want.name} matches")
    return notes


def control_plane_notes(
    graph: GraphClient,
    expected: list[ControlPlaneGrants],
    client_ids: dict[str, str],
    subject_repo: str | None = None,
) -> list[str]:
    notes = []
    for cp in expected:
        client_id = client_ids.get(cp.agent_id)
        if client_id is None:
            notes.append(f"{cp.agent_id}: no client ID in config.yaml; Graph grants not checked")
            continue
        held = graph_roles_held(graph, client_id)
        if held is None:
            notes.append(f"{cp.agent_id}: service principal not found in the tenant")
            continue
        missing = sorted(set(cp.graph_roles) - set(held))
        extra = sorted(set(held) - set(cp.graph_roles))
        if missing:
            notes.append(f"{cp.agent_id}: registry declares but tenant lacks {', '.join(missing)}")
        if extra:
            notes.append(f"{cp.agent_id}: holds undeclared {', '.join(extra)} (NHI-007 drift)")
        if not missing and not extra:
            notes.append(f"{cp.agent_id}: Graph grants match the registry ({len(held)})")
        notes += federated_notes(graph, cp, client_id, subject_repo)
    return notes
