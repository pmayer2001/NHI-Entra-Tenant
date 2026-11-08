"""Certificate rotation without downtime (ADR-012): add new, verify, then remove old.

Never remove first. addKey/removeKey need a proof of possession signed by a key
the object already has, so rotation must happen while the current certificate
is still valid; once every certificate has expired, only a PATCH can recover.

How the keys are written (`--method`, live findings 2026-11-01):
  patch               the provisioner PATCHes keyCredentials to [old, new], then [new].
                      Graph never returns public key bytes, so this only works because
                      we hold every key on the object locally; anything else is refused.
                      Default for blueprints: addKey as the blueprint itself got 403
                      (it would need AgentIdentityBlueprint.AddRemoveCreds.All, which
                      covers every blueprint in the tenant).
  addkey-self         addKey/removeKey as the target itself, Graph token from its own
                      certificate ("an application doesn't need any permission to roll
                      its own keys"). Default for service-principal-backend NHIs.
  (addKey as the provisioner was tried live with the proof's `iss` = the blueprint
  and = the provisioner: both 401 MissingOrMalformed. Removed.)

Targets:
  bp-<agent>            a blueprint (Agent ID): verified by getting a token for one of
                        its agents (T1 -> T2), the same path the agents use
  nhi-<workflow>-<agent> a service-principal-backend NHI: verified with an app token
"""

from __future__ import annotations

import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

import httpx

from nhigov.agent_auth import (
    TokenError,
    agent_identity_token,
    app_token,
    blueprint_exchange_token,
    proof_of_possession,
)
from nhigov.certs import (
    DEFAULT_CERT_DIR,
    LocalCert,
    generate_self_signed,
    key_credential,
    load_local_cert,
)
from nhigov.graph.auth import GRAPH_DEFAULT_SCOPE
from nhigov.graph.client import GraphClient
from nhigov.reconcile.engine import LAG_BACKOFF, PlanError
from nhigov.reconcile.state import TenantState

LABEL = "nhigov local runtime"


@dataclass(frozen=True)
class Target:
    name: str  # also the certificate file name
    application_object_id: str
    app_id: str
    base: str  # Graph path addKey/removeKey hang off
    verify_client_id: str  # whose token proves the new key works
    is_blueprint: bool


def resolve(name: str, tenant: TenantState) -> Target:
    if name.startswith("bp-"):
        agent = name.removeprefix("bp-")
        bp = tenant.blueprints.get(agent)
        if bp is None:
            raise PlanError(f"{name} isn't in state")
        agents = [n for n in tenant.nhis.values() if n.blueprint == agent and n.app_id]
        if not agents:
            raise PlanError(f"{name} has no agent identity to verify a new key with")
        return Target(
            name, bp.application_object_id, bp.app_id,
            f"applications/{bp.application_object_id}/microsoft.graph.agentIdentityBlueprint",
            str(agents[0].app_id), True,
        )  # fmt: skip
    for key, rec in tenant.nhis.items():
        workflow, agent = key.split("/", 1)
        if f"nhi-{workflow}-{agent}" == name and rec.backend == "service_principal":
            assert rec.application_object_id and rec.app_id
            base = f"applications/{rec.application_object_id}"
            return Target(name, rec.application_object_id, rec.app_id, base, rec.app_id, False)
    raise PlanError(f"{name} isn't a blueprint or service-principal NHI in state")


class Method(StrEnum):
    PATCH = "patch"
    ADDKEY_SELF = "addkey-self"


def default_method(t: Target) -> Method:
    return Method.PATCH if t.is_blueprint else Method.ADDKEY_SELF


class KeyWriter(Protocol):
    """Puts the new key on the object, and later takes the old one off."""

    def describe(self, t: Target) -> tuple[str, str]: ...

    def add(self, t: Target, keys: list[dict[str, Any]], current: LocalCert, current_pem: Path,
            new: LocalCert) -> str: ...  # fmt: skip

    def remove(self, t: Target, old: list[dict[str, Any]], new: LocalCert,
               new_pem: Path) -> str: ...  # fmt: skip


@dataclass
class AddKeyWriter:
    """addKey/removeKey with a proof of possession, sent by whoever `client_for` logs in as."""

    client_for: Callable[[Path], GraphClient]  # pem -> a client logged in with that key
    proof_iss: str  # object ID of the application making the request
    caller: str

    def describe(self, t: Target) -> tuple[str, str]:
        return (
            f"POST /v1.0/{t.base}/addKey  as {self.caller}, proof signed with the CURRENT key",
            f"POST /v1.0/{t.base}/removeKey  for the old key, as {self.caller}, proof signed "
            "with the NEW key",
        )

    def add(self, t: Target, keys: list[dict[str, Any]], current: LocalCert, current_pem: Path,
            new: LocalCert) -> str:  # fmt: skip
        with self.client_for(current_pem) as client:
            client.post(f"{t.base}/addKey", {
                "keyCredential": key_credential(new, LABEL),
                "passwordCredential": None,
                "proof": proof_of_possession(current_pem, self.proof_iss),
            })  # fmt: skip
        return f"added the new key with addKey (as {self.caller}, proved with the current one)"

    def remove(self, t: Target, old: list[dict[str, Any]], new: LocalCert,
               new_pem: Path) -> str:  # fmt: skip
        with self.client_for(new_pem) as client:
            for k in old:
                client.post(f"{t.base}/removeKey", {
                    "keyId": k["keyId"], "proof": proof_of_possession(new_pem, self.proof_iss),
                })  # fmt: skip
        return f"removed the old key with removeKey ({len(old)})"


@dataclass
class PatchWriter:
    """PATCH keyCredentials as the provisioner. A PATCH replaces the whole list and Graph
    never returns public key bytes, so every key on the object must be one we hold."""

    provisioner: GraphClient

    def describe(self, t: Target) -> tuple[str, str]:
        return (
            f"PATCH /v1.0/{t.base}  keyCredentials = [current, new]  as nhigov-provisioner",
            f"PATCH /v1.0/{t.base}  keyCredentials = [new]  as nhigov-provisioner",
        )

    def add(self, t: Target, keys: list[dict[str, Any]], current: LocalCert, current_pem: Path,
            new: LocalCert) -> str:  # fmt: skip
        held = {current.thumbprint_b64, new.thumbprint_b64}
        unknown = [k.get("displayName") or k.get("keyId") for k in keys
                   if k.get("customKeyIdentifier") not in held]  # fmt: skip
        if unknown:
            raise PlanError(
                f"{t.name} has keys this machine doesn't hold ({', '.join(map(str, unknown))}); "
                "a PATCH would delete them. Remove them deliberately or use --method addkey-*."
            )
        body = {"keyCredentials": [key_credential(current, LABEL), key_credential(new, LABEL)]}
        self.provisioner.patch(t.base, body)
        return "added the new key next to the current one (PATCH, as nhigov-provisioner)"

    def remove(self, t: Target, old: list[dict[str, Any]], new: LocalCert,
               new_pem: Path) -> str:  # fmt: skip
        self.provisioner.patch(t.base, {"keyCredentials": [key_credential(new, LABEL)]})
        return f"removed the old key ({len(old)}): keyCredentials = [new] (PATCH)"


def self_service_client(
    http: httpx.Client, tenant_id: str, t: Target, base_url: str
) -> Callable[[Path], GraphClient]:
    """A GraphClient that authenticates *as the target*, with the key in `pem`."""

    def make(pem: Path) -> GraphClient:
        token: list[str] = []

        def provider() -> str:
            if not token:  # one token per client; it outlives the rotation
                token.append(app_token(http, tenant_id, t.app_id, pem, GRAPH_DEFAULT_SCOPE))
            return token[0]

        return GraphClient(provider, base_url=base_url)

    return make


def plan_text(t: Target, writer: KeyWriter, cert_dir: Path, days: int) -> list[str]:
    add, remove = writer.describe(t)
    return [
        f"1. create a new {days}-day certificate: {cert_dir}/{t.name}.next.pem (local)",
        f"2. {add}",
        "3. verify: get a token with the NEW key"
        + (" for one of its agents (T1 -> T2)" if t.is_blueprint else ""),
        f"4. {remove}  (only if step 3 worked)",
        f"5. local files: {t.name}.pem -> {t.name}.retired-<date>.pem; .next -> {t.name}.pem",
    ]


def _verify(
    http: httpx.Client, tenant_id: str, t: Target, pem: Path, scope: str,
    sleep: Callable[[float], None],
) -> None:  # fmt: skip
    """A new key can take a few seconds to be accepted everywhere (replication)."""
    for delay in (*LAG_BACKOFF, None):
        try:
            if t.is_blueprint:
                t1 = blueprint_exchange_token(http, tenant_id, t.app_id, pem, t.verify_client_id)
                agent_identity_token(http, tenant_id, t.verify_client_id, t1, scope)
            else:
                app_token(http, tenant_id, t.app_id, pem, scope)
            return
        except TokenError:
            if delay is None:
                raise
            sleep(delay)


def rotate(
    graph: GraphClient,
    writer: KeyWriter,
    http: httpx.Client,
    tenant_id: str,
    t: Target,
    scope: str,
    days: int,
    today: date,
    cert_dir: Path = DEFAULT_CERT_DIR,
    sleep: Callable[[float], None] = time.sleep,
) -> list[str]:
    cert_dir = cert_dir.expanduser()
    current_pem = cert_dir / f"{t.name}.pem"
    current = load_local_cert(t.name, cert_dir)
    if current is None or not current_pem.exists():
        raise PlanError(f"no current certificate {current_pem}: rotation needs the old key")

    keys: list[dict[str, Any]] = graph.get(t.base, params={"$select": "id,keyCredentials"}).get(
        "keyCredentials", []
    )
    old = [k for k in keys if k.get("customKeyIdentifier") == current.thumbprint_b64]
    if not old:
        raise PlanError(f"{t.name}'s current local certificate isn't on the object in Entra")

    log = []
    next_name = f"{t.name}.next"
    if not (cert_dir / f"{next_name}.pem").exists():
        generate_self_signed(next_name, cert_dir, days)
    new = load_local_cert(next_name, cert_dir)
    assert new is not None
    new_pem = cert_dir / f"{next_name}.pem"
    log.append(f"created {new_pem.name} (valid {new.lifetime_days} days)")

    if not any(k.get("customKeyIdentifier") == new.thumbprint_b64 for k in keys):
        log.append(writer.add(t, keys, current, current_pem, new))

    try:
        _verify(http, tenant_id, t, new_pem, scope, sleep)
    except TokenError as exc:
        raise PlanError(
            f"the new key didn't work ({exc}); the old key was NOT removed. Both are on "
            "the object; re-run rotate to retry the check."
        ) from None
    log.append("verified: a token was issued with the new key")

    log.append(writer.remove(t, old, new, new_pem))

    for ext in ("pem", "cer"):
        shutil.move(cert_dir / f"{t.name}.{ext}", cert_dir / f"{t.name}.retired-{today}.{ext}")
        shutil.move(cert_dir / f"{next_name}.{ext}", cert_dir / f"{t.name}.{ext}")
    log.append(f"{t.name}.pem is now the new key; the old one is kept as .retired-{today}")
    return log
