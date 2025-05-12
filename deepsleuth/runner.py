"""Detector runner.

Executes registered detectors over a ScanContext, phase by phase, with graceful
degradation (a detector that raises never crashes the scan — it is logged as a
low-severity 'other' note so coverage is visible, see the runner rules). Deduplicates by
(target, tool, mechanism) and returns findings in stable order.
"""
from __future__ import annotations

import traceback
from typing import Dict, List, Optional

from . import detectors as _detectors  # ensures registration
from .calibration import calibrate
from .context import ScanContext
from .detectors.base import Detector, all_detectors, detectors_for_phase
from .models import Finding


def run_phase(ctx: ScanContext, phase: str,
              collect_errors: Optional[List[str]] = None) -> List[Finding]:
    """Run every applicable detector for ``phase``, then run every finding
    through the shared calibration layer (Part B) — this is the single hook
    point both Frontend A (proxy / proxy-eval) and Frontend B (batch scanner,
    via :func:`run_all`) call, so calibration is identical everywhere without
    either frontend having to remember to invoke it."""
    out: List[Finding] = []
    for det in detectors_for_phase(phase):
        if not det.applicable(ctx):
            continue
        try:
            out.extend(det.run(ctx) or [])
        except Exception as exc:  # never let one detector break the run
            msg = f"detector {det.id} raised {type(exc).__name__}: {exc}"
            if collect_errors is not None:
                collect_errors.append(msg + "\n" + traceback.format_exc())
            out.append(Finding(
                category="other", evidence_location="source", severity="none",
                detection_method="detector-error", confidence="low",
                rationale=f"Detector '{det.id}' failed to run; coverage incomplete.",
                evidence={"error": str(exc), "detector": det.id},
                target_id=ctx.target.target_id, source_kind="static-code",
                detector_id=det.id,
            ))
    return calibrate(out, ctx)


def run_all(ctx: ScanContext, phases=None,
            collect_errors: Optional[List[str]] = None) -> List[Finding]:
    phases = phases or ("tool listing", "precall", "response", "multicall")
    findings: List[Finding] = []
    for ph in phases:
        findings.extend(run_phase(ctx, ph, collect_errors))
    return dedup(findings)


def dedup(findings: List[Finding]) -> List[Finding]:
    best: Dict[tuple, Finding] = {}
    from .models import SEVERITY_RANK
    for f in findings:
        k = f.dedup_key()
        cur = best.get(k)
        if cur is None or SEVERITY_RANK[f.severity] > SEVERITY_RANK[cur.severity]:
            best[k] = f
    return sorted(best.values(), key=lambda f: f.sort_key())


def registry_summary() -> List[Dict[str, str]]:
    rows = []
    for d in sorted(all_detectors(), key=lambda x: (x.phase, x.id)):
        rows.append({
            "id": d.id, "category": d.category,
            "evidence_location": d.evidence_location, "phase": d.phase,
            "requires": ",".join(sorted(d.requires)),
        })
    return rows
