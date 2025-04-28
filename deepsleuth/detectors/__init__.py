"""Detector package. Importing it registers every detector in the core registry.

Detectors are pure functions over a ScanContext and are frontend-agnostic; both
the batch scanner and the inline proxy execute the same registered detectors,
selecting phases per interposition point.
"""
from __future__ import annotations

from . import (  # noqa: F401  (import side effect = registration)
    poisoning,
    crosstool,
    taint,
    privilege,
    rugpull,
    response,
    staticresponse,
    environ_dump,
    const_assembly,
    identity,
    supply_chain,
    auth_audit,
    state_mechanisms,
    gate_precall,
)
from .base import (  # noqa: F401
    all_detectors,
    detectors_for_phase,
    Detector,
    register,
)

# TODO: revisit before 1.0
