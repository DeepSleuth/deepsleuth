"""Shared helpers for detectors."""
from __future__ import annotations

from typing import Any, Dict, Optional

from ..context import ScanContext
from ..models import Finding


def mk(ctx: ScanContext, *, detector_id: str, category: str, evidence_location: str,
       severity: str, detection_method: str, confidence: str, rationale: str,
       evidence: Dict[str, Any], source_kind: str, tool_name: Optional[str] = None,
       raw: Optional[Dict[str, Any]] = None) -> Finding:
    server_name = None
    if ctx.server_info and isinstance(ctx.server_info, dict):
        server_name = ctx.server_info.get("name")
    server_name = server_name or ctx.target.server_name
    return Finding(
        category=category,
        evidence_location=evidence_location,
        severity=severity,
        detection_method=detection_method,
        confidence=confidence,
        rationale=rationale,
        evidence=evidence,
        raw=raw or {},
        target_id=ctx.target.target_id,
        server_name=server_name,
        tool_name=tool_name,
        source_kind=source_kind,
        detector_id=detector_id,
    )
