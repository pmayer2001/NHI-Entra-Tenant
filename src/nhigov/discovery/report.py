"""Scan outputs: reports/inventory-<date>.json, findings-<date>.json and a markdown summary.

reports/ is git-ignored: these files hold real object IDs and display names.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from nhigov.discovery.inventory import Inventory
from nhigov.discovery.rules.base import Finding


def render_markdown(inventory: Inventory, findings: list[Finding]) -> str:
    by_class = Counter(n.classification for n in inventory.nhis)
    by_severity = Counter(f.severity.value for f in findings)
    lines = [
        f"# NHI scan, {inventory.collected_at:%Y-%m-%d %H:%M} UTC",
        "",
        "## Inventory",
        "",
        "| Classification | NHIs |",
        "|---|---|",
        *[f"| {c} | {by_class[c]} |" for c in sorted(by_class)],
        "",
        f"## Findings ({len(findings)})",
        "",
        " · ".join(
            f"**{s}**: {by_severity[s]}"
            for s in ("critical", "high", "medium", "low")
            if by_severity[s]
        )
        or "None.",
        "",
    ]
    if findings:
        lines += ["| Severity | Rule | NHI | Finding |", "|---|---|---|---|"]
        for f in findings:
            msg = f.message.replace("|", "\\|")
            lines.append(f"| {f.severity.value} | {f.rule} | {f.display_name} | {msg} |")
        lines += ["", "## How to fix", ""]
        for rule in sorted({f.rule for f in findings}):
            first = next(f for f in findings if f.rule == rule)
            lines += [f"- **{rule}**: {first.remediation}"]
    return "\n".join(lines) + "\n"


def write_reports(
    inventory: Inventory, findings: list[Finding], out_dir: Path, when: datetime
) -> list[Path]:
    stamp = when.strftime("%Y-%m-%d")
    out_dir.mkdir(parents=True, exist_ok=True)
    inventory_path = out_dir / f"inventory-{stamp}.json"
    findings_path = out_dir / f"findings-{stamp}.json"
    summary_path = out_dir / f"findings-{stamp}.md"
    inventory.save(inventory_path)
    findings_path.write_bytes(
        json.dumps([f.model_dump(mode="json") | {"key": f.key} for f in findings], indent=2).encode(
            "utf-8"
        )
    )
    summary_path.write_bytes(render_markdown(inventory, findings).encode("utf-8"))
    return [inventory_path, findings_path, summary_path]
