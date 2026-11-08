"""Decide each NHI's lifecycle state and what's due (pure: no Graph calls).

    requested ─apply─▶ active ─(expires-N)─▶ expiring ─(expires)─▶ disabled
                         ▲                      │                     │ (grace)
                         └── renewed in registry┘                     ▼
                                                                soft-deleted ─(30d)─▶ purged

Inputs: the registry (what should be), a discovery inventory (what is, read as
the scanner), the state file (which object is which) and the lifecycle state
(when each condition started). Output: one row per NHI and the actions due.
`run.py` executes them; nothing here writes.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Literal

from nhigov.discovery.inventory import Inventory, Nhi
from nhigov.lifecycle.state import LifecycleRecord, LifecycleState
from nhigov.reconcile.desired import DesiredNhi, build_desired
from nhigov.reconcile.state import TenantState
from nhigov.registry.loader import Registry
from nhigov.registry.models import Backend, Policy, Workflow, WorkflowStatus

SOFT_DELETE_DAYS = 30  # Entra keeps deleted applications/SPs restorable this long

ActionKind = Literal["notice", "disable", "delete", "release"]


@dataclass(frozen=True)
class Action:
    kind: ActionKind
    key: str  # "<workflow>/<agent>"
    name: str
    reason: str
    ref: str = ""  # notices: the dated key, so each notice is sent once


@dataclass(frozen=True)
class Row:
    key: str
    name: str
    state: str  # requested | active | expiring | disabled | soft-deleted | purged | not provisioned
    detail: str = ""
    next_step: str = ""


@dataclass
class LifecyclePlan:
    rows: list[Row] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    state: LifecycleState = field(default_factory=LifecycleState)  # updated copy


def _sponsor_problem(inventory: Inventory, wf: Workflow) -> str | None:
    person = inventory.people.get(wf.sponsor.lower())
    if person is None:
        return f"sponsor {wf.sponsor} no longer exists"
    if not person.enabled:
        return f"sponsor {wf.sponsor} is disabled"
    if not person.member:
        return f"sponsor {wf.sponsor} is a guest"
    return None


def _track(rec: LifecycleRecord, condition: str, active: bool, today: date) -> date | None:
    """Record when a condition was first seen; forget it once it clears."""
    if active:
        return rec.conditions.setdefault(condition, today)
    rec.conditions.pop(condition, None)
    return None


def evaluate(
    registry: Registry,
    inventory: Inventory,
    tenant: TenantState,
    lifecycle: LifecycleState,
    today: date,
    default_backend: Backend = Backend.AGENT_ID,
) -> LifecyclePlan:
    policy = registry.policy
    if policy is None:
        raise ValueError("the registry has no policy")
    plan = LifecyclePlan(state=copy.deepcopy(lifecycle))
    by_id = {n.id: n for n in inventory.nhis}
    desired = build_desired(registry, default_backend)

    for key, nhi in sorted(desired.nhis.items()):
        wf = registry.workflows[nhi.workflow_id]
        rec = plan.state.nhis.setdefault(key, LifecycleRecord())
        state_rec = tenant.nhis.get(key)
        live = by_id.get(state_rec.principal_id) if state_rec and state_rec.principal_id else None

        if state_rec is None or live is None:
            plan.rows.append(_absent_row(key, nhi, rec, today))
            continue
        _evaluate_present(plan, key, nhi, wf, rec, live, inventory, today, policy)

    # Records for NHIs no longer in the registry at all are kept (history), not acted on.
    return plan


def _absent_row(key: str, nhi: DesiredNhi, rec: LifecycleRecord, today: date) -> Row:
    if rec.deleted_on is not None:
        purge = rec.deleted_on + timedelta(days=SOFT_DELETE_DAYS)
        if today >= purge:
            return Row(key, nhi.name, "purged", f"deleted {rec.deleted_on}, past Entra's 30 days")
        return Row(key, nhi.name, "soft-deleted", f"deleted {rec.deleted_on}",
                   f"restorable until {purge}, then Entra purges it")  # fmt: skip
    if nhi.status is WorkflowStatus.REQUESTED:
        return Row(key, nhi.name, "requested", "awaiting approval", "set status: active")
    return Row(key, nhi.name, "not provisioned", "", "run `nhigov apply`")


def _evaluate_present(
    plan: LifecyclePlan,
    key: str,
    nhi: DesiredNhi,
    wf: Workflow,
    rec: LifecycleRecord,
    live: Nhi,
    inventory: Inventory,
    today: date,
    policy: Policy,
) -> None:
    enabled = live.enabled is not False
    if not enabled and rec.disabled_on is None:
        rec.disabled_on = today
    if enabled:
        rec.disabled_on = None

    def act(kind: ActionKind, reason: str, ref: str = "") -> None:
        plan.actions.append(Action(kind, key, nhi.name, reason, ref))

    # --- retirement: disable, then soft-delete after grace -----------------------
    # Retirement supersedes holds: the NHI stays off because the registry says so, so a
    # hold is never released (that would suggest re-enabling) and no notices go out.
    # The grace runs from when the NHI was disabled, whatever disabled it.
    if wf.status is WorkflowStatus.RETIRED:
        if enabled:
            act("disable", "workflow retired")
            plan.rows.append(Row(key, nhi.name, "active", "workflow retired", "disable now"))
            return
        disabled_on = rec.disabled_on or today
        due = disabled_on + timedelta(days=policy.retirement_grace_days)
        if today >= due:
            act("delete", f"retired; disabled since {disabled_on}")
            plan.rows.append(Row(key, nhi.name, "disabled", "workflow retired", "soft-delete now"))
        else:
            plan.rows.append(Row(key, nhi.name, "disabled", "workflow retired",
                                 f"soft-delete on {due}"))  # fmt: skip
        return

    # --- conditions that put a hold on the NHI ---------------------------------
    sponsor_issue = _sponsor_problem(inventory, wf)
    sponsor_since = _track(rec, "sponsor", sponsor_issue is not None, today)
    expired = wf.status is WorkflowStatus.ACTIVE and wf.expires < today
    _track(rec, "expired", expired, today)

    hold: str | None = None
    if expired:
        hold = f"expired on {wf.expires}"
    elif sponsor_issue and sponsor_since is not None:
        due = sponsor_since + timedelta(days=policy.sponsor_grace_days)
        if today >= due:
            hold = f"{sponsor_issue} since {sponsor_since}"

    if hold:
        if enabled or rec.hold != hold:
            # If it's already off in Entra, this still records the hold so apply keeps it off.
            act("disable", hold)
    elif rec.hold:
        act("release", f"cause cleared ({rec.hold}); run `nhigov apply` to re-enable")

    # --- notices: expiry and review dates approaching (not once it's held off) -----
    notice_window = timedelta(days=policy.expiry_notice_days)
    for label, when in (("expires", wf.expires), ("review due", wf.review_by)):
        if hold:
            break
        if today <= when <= today + notice_window or (label == "review due" and when < today):
            notice_key = f"{label}:{when}"
            if notice_key not in rec.notices:
                act(
                    "notice",
                    f"{wf.id} {label} {when}; sponsor {wf.sponsor} to renew or retire",
                    notice_key,
                )

    # --- the row ------------------------------------------------------------------
    if hold:
        plan.rows.append(
            Row(
                key,
                nhi.name,
                "disabled",
                f"held: {hold}",
                "fix the cause, then `nhigov lifecycle run` releases the hold",
            )
        )
    elif not enabled:
        plan.rows.append(Row(key, nhi.name, "disabled", f"workflow {wf.status}", ""))
    elif sponsor_issue and sponsor_since is not None:
        due = sponsor_since + timedelta(days=policy.sponsor_grace_days)
        plan.rows.append(Row(key, nhi.name, "active", f"{sponsor_issue} (seen {sponsor_since})",
                             f"disable on {due} unless a new sponsor is named"))  # fmt: skip
    elif wf.expires <= today + notice_window:
        plan.rows.append(Row(key, nhi.name, "expiring", f"expires {wf.expires}",
                             "renew dates in the registry, or retire"))  # fmt: skip
    else:
        plan.rows.append(Row(key, nhi.name, "active", f"expires {wf.expires}",
                             f"review by {wf.review_by}"))  # fmt: skip
