"""NHI-003: a client secret on the NHI (P7)."""

from __future__ import annotations

from collections.abc import Iterator

from nhigov.discovery.inventory import Inventory, Nhi
from nhigov.discovery.rules.base import Rule, ScanContext, Severity


def check(inv: Inventory, ctx: ScanContext) -> Iterator[tuple[Nhi, str]]:
    for nhi in inv.nhis:
        if not nhi.tenant_owned:
            continue
        secrets = [c for c in nhi.credentials if c.kind == "secret"]
        if secrets:
            ends = ", ".join(str(c.end.date()) if c.end else "?" for c in secrets)
            yield nhi, f"{len(secrets)} client secret(s) on the {secrets[0].on} (expire {ends})"


RULE = Rule(
    "NHI-003", "Client secret present", Severity.HIGH,
    "A secret is a reusable password: it can be copied from a config file, a log or a "
    "laptop and used from anywhere. Most NHI compromises start with one (P7).",
    "Replace it with a certificate or a federated credential, verify, then remove the "
    "secret. The tenant app management policy should block new ones (Phase 6).",
    check,
)  # fmt: skip
