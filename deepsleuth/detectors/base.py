"""Detector base + registry (rule 4.5).

A detector is a small unit with an ``id``, a primary ``category`` and
``evidence_location`` (for docs/registry), the ``phase`` at which it runs, a
``requires`` set of context capabilities, and a ``run(ctx) -> [Finding]``.

Detectors are *pure functions over a Context*. They are written once in the core
and run unchanged in both frontends — the runner selects which phase(s) to execute
depending on the frontend and which context layers are present.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Set

from ..context import ScanContext
from ..models import Finding

# capabilities a detector may require to be meaningful
CAP_MANIFEST = "manifest"     # a tool listing (declared metadata) exists
CAP_SOURCE = "source"         # parsed implementation source exists
CAP_DYNAMIC = "dynamic"       # live calls/responses were captured
CAP_PACKAGE = "package"       # package manifests exist
CAP_IDENTITY = "identity"     # serverInfo captured


@dataclass
class Detector:
    id: str
    category: str
    evidence_location: str
    phase: str
    run: Callable[[ScanContext], List[Finding]]
    requires: Set[str] = field(default_factory=set)
    rationale: str = ""

    def applicable(self, ctx: ScanContext) -> bool:
        caps = _context_caps(ctx)
        return self.requires.issubset(caps)


def _context_caps(ctx: ScanContext) -> Set[str]:
    caps: Set[str] = set()
    if ctx.tools or ctx.resources or ctx.prompts:
        caps.add(CAP_MANIFEST)
    if ctx.source_modules or any(t.source for t in ctx.all_contracts()):
        caps.add(CAP_SOURCE)
    if ctx.calls or ctx.pending_call or ctx.tools_relisted is not None:
        caps.add(CAP_DYNAMIC)
    if ctx.package_manifests:
        caps.add(CAP_PACKAGE)
    if ctx.server_info:
        caps.add(CAP_IDENTITY)
    return caps


_REGISTRY: List[Detector] = []


def register(detector: Detector) -> Detector:
    _REGISTRY.append(detector)
    return detector


def all_detectors() -> List[Detector]:
    return list(_REGISTRY)


def detectors_for_phase(phase: str) -> List[Detector]:
    return [d for d in _REGISTRY if d.phase == phase]


def clear_registry() -> None:  # for tests
    _REGISTRY.clear()
