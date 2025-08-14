"""Core data models: the output-schema Finding, the Target (rule 4.1), and the
enumerations the rest of the scanner shares.

Everything here is deterministic and JSON-serializable. Findings are ordered by a
stable sort key so that ``same input -> byte-identical output`` (hard constraint
rule 3.3).
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .version import SCANNER_NAME, git_commit

SCHEMA_VERSION = "1.0.0"

# --- fixed enums from the brief (rule 6) -----------------------------------------

CATEGORIES = (
    "tool-poisoning",
    "agent-config-poisoning",
    "tool-shadowing",
    "prompt-injection",
    "credential-exposure",
    "command-injection",
    "path-traversal",
    "ssrf",
    "data-exfiltration",
    "confused-deputy",
    "auth-misconfiguration",
    "denial-of-service",
    "excessive-privilege",
    "supply-chain",
    "information-disclosure",
    "client-side-vulnerability",
    "other",
)

EVIDENCE_LOCATIONS = (
    "tool description",
    "name",
    "schema",
    "source",
    "runtime-response",
    "multi-call-state",
    "server-identity",
    "install-time-script",
)

SEVERITIES = ("none", "low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
CONFIDENCES = ("low", "medium", "high")

# source.kind values keyed to which layer produced the finding
SOURCE_KINDS = ("dynamic-runtime", "static-code", "static-manifest")


@dataclass
class Finding:
    category: str
    evidence_location: str
    severity: str
    detection_method: str
    confidence: str
    rationale: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)
    # target attribution
    target_id: str = ""
    server_name: Optional[str] = None
    tool_name: Optional[str] = None
    # which layer produced it -> source.kind
    source_kind: str = "static-code"
    # detector id, kept in raw for traceability
    detector_id: str = ""

    def __post_init__(self) -> None:
        assert self.category in CATEGORIES, f"bad category {self.category!r}"
        assert self.evidence_location in EVIDENCE_LOCATIONS, (
            f"bad evidence_location {self.evidence_location!r}"
        )
        assert self.severity in SEVERITIES, f"bad severity {self.severity!r}"
        assert self.confidence in CONFIDENCES, f"bad confidence {self.confidence!r}"
        assert self.source_kind in SOURCE_KINDS, f"bad source_kind {self.source_kind!r}"

    # -- serialization --------------------------------------------------------
    def to_schema(self) -> Dict[str, Any]:
        raw = dict(self.raw)
        raw.setdefault("detector_id", self.detector_id)
        return {
            "schema_version": SCHEMA_VERSION,
            "source": {
                "name": SCANNER_NAME,
                "kind": self.source_kind,
                "version_or_commit": git_commit(),
            },
            "target": {
                "target_id": self.target_id,
                "server_name": self.server_name,
                "tool_name": self.tool_name,
            },
            "category": self.category,
            "evidence_location": self.evidence_location,
            "severity": self.severity,
            "detection_method": self.detection_method,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "evidence": self.evidence,
            "raw": raw,
        }

    def dedup_key(self) -> tuple:
        """One record per distinct (target, tool, mechanism).

        rule P0.6: findings with no per-tool attribution at all (supply-chain
        install-hook/typosquat findings are targetless — ``tool_name`` is
        ``None``) still need an evidence discriminator, or every distinct bad
        hook / typosquatted dependency on one manifest collapses into a
        single record. Folding in the hook name / dependency name / schema
        parameter name (when the finding carries one) fixes that without
        touching detectors whose per-instance evidence is expected to vary
        run-to-run for the SAME mechanism (a decoy canary value, a response
        excerpt, a source line) — those are deliberately left out so "one
        record per mechanism" does not become "one record per occurrence".
        """
        discriminator = (
            self.evidence.get("hook")
            or self.evidence.get("dependency")
            or self.evidence.get("param")
            or self.evidence.get("other_tool")
            or self.evidence.get("colliding_key")
            or self.evidence.get("json_path")
            or ""
        )
        return (
            self.target_id,
            self.tool_name or "",
            self.category,
            self.evidence_location,
            self.detector_id,
            discriminator,
        )

    def sort_key(self) -> tuple:
        # highest severity first, then stable lexical ordering for reproducibility
        return (
            -SEVERITY_RANK[self.severity],
            self.category,
            self.evidence_location,
            self.tool_name or "",
            self.detector_id,
            hashlib.sha1(
                json.dumps(self.evidence, sort_keys=True, default=str).encode()
            ).hexdigest(),
        )


# --- Target model (rule 4.1) ------------------------------------------------------


@dataclass
class SourceFile:
    path: str
    language: str  # "python" | "javascript" | "typescript" | "other"
    text: str


@dataclass
class Target:
    target_id: str
    # launch spec (may be empty for source-only scans)
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    cwd: Optional[str] = None
    server_name: Optional[str] = None  # declared name from config, if any
    # v6-W4 — the key of the mcp.json / servers entry this launch came from
    # (None for a source directory, a single file or a raw launch command).
    # The handshake's serverInfo.name is compared against it.
    config_entry: Optional[str] = None
    # discovered material
    root_dir: Optional[str] = None
    source_files: List[SourceFile] = field(default_factory=list)
    package_manifests: Dict[str, str] = field(default_factory=dict)  # path -> text
    # runtime flavor guess for the sandbox base image
    runtime: str = "unknown"  # "python" | "node" | "unknown"

    def launchable(self) -> bool:
        return bool(self.command)


def findings_to_json(findings: List[Finding], indent: int = 2) -> str:
    ordered = sorted(findings, key=lambda f: f.sort_key())
    return json.dumps([f.to_schema() for f in ordered], indent=indent, default=str)
