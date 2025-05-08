"""Reporter (rules 4.6/6): stable findings JSON plus a human-readable summary."""
from __future__ import annotations

import json
from typing import Dict, List

from .models import SEVERITY_RANK, Finding, findings_to_json


def to_json(findings: List[Finding]) -> str:
    return findings_to_json(findings)


def write_json(findings: List[Finding], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(findings_to_json(findings))
        f.write("\n")


def human_summary(findings: List[Finding], skipped: List[str] = None) -> str:
    lines: List[str] = []
    by_sev: Dict[str, int] = {}
    for f in findings:
        if f.severity == "none":
            continue
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    total = sum(by_sev.values())
    lines.append("=" * 70)
    lines.append(f"deepsleuth: {total} finding(s)")
    if by_sev:
        order = ["critical", "high", "medium", "low"]
        lines.append("  " + "  ".join(f"{s}={by_sev[s]}" for s in order if s in by_sev))
    lines.append("=" * 70)
    for f in sorted(findings, key=lambda x: x.sort_key()):
        if f.severity == "none":
            continue
        tool = f.tool_name or "-"
        lines.append(
            f"[{f.severity.upper():8}] {f.category:22} @ {f.evidence_location:18} "
            f"tool={tool}"
        )
        lines.append(f"           {f.rationale}")
        lines.append(f"           (detector={f.detector_id} method={f.detection_method} "
                     f"confidence={f.confidence})")
        gd = f.raw.get("gate_decision")
        if gd:
            lines.append(f"           gate_decision={gd}")
    if skipped:
        lines.append("-" * 70)
        lines.append("Skipped coverage / notes:")
        for s in skipped:
            lines.append(f"  - {s}")
    lines.append("=" * 70)
    return "\n".join(lines)


def max_severity_rank(findings: List[Finding]) -> int:
    r = 0
    for f in findings:
        r = max(r, SEVERITY_RANK[f.severity])
    return r

# TODO: revisit before 1.0
