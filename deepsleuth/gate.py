"""The gate — deterministic policy over findings (interposition point 2/3).

The gate is the shared decision layer for Frontend A. It is a pure function over a
set of findings plus a :class:`Policy`, so it is identical in the live proxy and in
headless ``proxy-eval``, and it is unit-testable without any live client.

Posture (default, rule 4.7): human-in-the-loop on uncertainty.

* clean (no finding at/above the report floor) -> ``allow``
* high / critical                              -> ``block`` (a policy flag may
  downgrade to ``confirm`` so a fully-informed user can override)
* uncertain / low-medium                       -> ``confirm`` (pause, surface the
  risk log to the user via MCP elicitation, wait for approval)

A ``confirm`` that cannot be resolved (client lacks elicitation, or
``--fail-closed``) becomes ``block`` — never a silent allow.

No LLM, no randomness: same findings + same policy -> same decision.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .models import CONFIDENCES, SEVERITY_RANK, Finding

CONFIDENCE_RANK = {c: i for i, c in enumerate(CONFIDENCES)}

# gate decisions (recorded on raw.gate_decision)
ALLOW = "allow"
ALLOW_ANNOTATE = "allow_annotate"
CONFIRM = "confirm"
BLOCK = "block"
DECISIONS = (ALLOW, ALLOW_ANNOTATE, CONFIRM, BLOCK)

# startup (tools/list) per-tool actions
PASS = "pass"
ANNOTATE = "annotate"
WITHHOLD = "withhold"

# response actions
REDACT = "redact"


@dataclass
class Policy:
    """Deterministic policy file. Loaded from JSON or a small flat-YAML
    subset; every key has a safe default so a missing/partial file still works."""

    # --- gate (tools/call) ---
    block_high: bool = True            # high/critical -> block (else -> confirm)
    confirm_low_medium: bool = True    # low/medium -> confirm (else -> allow_annotate)
    fail_closed: bool = False          # unresolved confirm -> block
    remember_approvals: bool = True    # an approved identical call is not re-prompted

    # --- startup (tools/list audit) ---
    withhold_threshold: str = "high"   # withhold a tool poisoned at/above this sev
    annotate_poisoned: bool = True     # annotate (vs. silently pass) sub-threshold poison

    # --- response scan ---
    response_block_threshold: str = "high"   # block a response at/above this sev
    response_annotate: bool = True           # annotate sub-threshold responses

    # --- reporting ---
    min_report_severity: str = "low"   # findings below this are informational only

    # --- v4-8 declared capabilities ---
    # A finding tagged ``raw.declared_capability`` (an ``ast-taint`` sink the
    # tool's own description openly declares: "runs the command you give
    # it", "fetches the URL") keeps its full grade in the report. With this
    # key on, the gate treats such a finding as ``confirm`` instead of
    # ``block`` and the startup audit annotates instead of withholding —
    # the operator has decided a declared capability is theirs to approve
    # per call. Anything NOT tagged is unaffected.
    allow_declared_capabilities: bool = False

    # provenance for the run log
    source_path: Optional[str] = None

    # ------------------------------------------------------------------ loading
    @classmethod
    def default(cls) -> "Policy":
        return cls()

    @classmethod
    def load(cls, path: Optional[str]) -> "Policy":
        if not path:
            return cls.default()
        if not os.path.isfile(path):
            raise FileNotFoundError(f"policy file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        data = _parse_policy_text(text)
        pol = cls.default()
        for k, v in data.items():
            if hasattr(pol, k):
                setattr(pol, k, v)
        pol.source_path = os.path.abspath(path)
        return pol

    def to_dict(self) -> Dict[str, Any]:
        return {
            "block_high": self.block_high,
            "confirm_low_medium": self.confirm_low_medium,
            "fail_closed": self.fail_closed,
            "remember_approvals": self.remember_approvals,
            "withhold_threshold": self.withhold_threshold,
            "annotate_poisoned": self.annotate_poisoned,
            "response_block_threshold": self.response_block_threshold,
            "response_annotate": self.response_annotate,
            "min_report_severity": self.min_report_severity,
            "allow_declared_capabilities": self.allow_declared_capabilities,
            "source_path": self.source_path,
        }


_BOOL_KEYS = {"block_high", "confirm_low_medium", "fail_closed", "remember_approvals",
              "annotate_poisoned", "response_annotate", "allow_declared_capabilities"}


def _coerce(key: str, val: Any) -> Any:
    if key in _BOOL_KEYS and isinstance(val, str):
        return val.strip().lower() in ("1", "true", "yes", "on")
    return val


def _parse_policy_text(text: str) -> Dict[str, Any]:
    """Parse JSON, or a tiny flat ``key: value`` YAML subset (deterministic, no
    dependency). Only scalar values are supported in the flat parser — enough for
    this policy, and documented as such."""
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            return {str(k): v for k, v in json.loads(stripped).items()}
        except json.JSONDecodeError:
            pass
    out: Dict[str, Any] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if not key:
            continue
        low = val.lower()
        if low in ("true", "false"):
            out[key] = (low == "true")
        else:
            out[key] = val
        out[key] = _coerce(key, out[key])
    return out


# ---------------------------------------------------------------------------
# decision logic (pure)


def worst_rank(findings: List[Finding], floor: str = "low") -> int:
    """Highest severity rank among findings at/above ``floor`` (0 if none).

    rule P0.5: severity ALONE never drives an enforcement decision — only findings
    whose confidence is also medium or high are eligible here. ``ARCHITECTURE.md``
    documents the gate as acting on severity AND confidence together; a
    low-confidence finding (even a high-severity one) must not by itself block,
    confirm or withhold a call — it is annotated instead (see
    ``low_confidence_rank``/the callers below)."""
    floor_rank = SEVERITY_RANK[floor]
    r = 0
    for f in findings:
        if CONFIDENCE_RANK.get(f.confidence, 0) < CONFIDENCE_RANK["medium"]:
            continue
        fr = SEVERITY_RANK[f.severity]
        if fr >= floor_rank and fr > r:
            r = fr
    return r


def low_confidence_rank(findings: List[Finding], floor: str = "low") -> int:
    """Highest severity rank among findings at/above ``floor`` whose confidence
    is LOW — i.e. findings that exist (and are worth surfacing) but must never
    by themselves block/confirm/withhold. Used only to decide whether to
    annotate when no medium/high-confidence finding was strong enough to act
    on."""
    floor_rank = SEVERITY_RANK[floor]
    r = 0
    for f in findings:
        if CONFIDENCE_RANK.get(f.confidence, 0) >= CONFIDENCE_RANK["medium"]:
            continue
        fr = SEVERITY_RANK[f.severity]
        if fr >= floor_rank and fr > r:
            r = fr
    return r


def is_declared_capability(f: Finding) -> bool:
    """A finding the detector tagged as reaching a capability the
    tool's own description openly declares (``raw.declared_capability``)."""
    return bool((getattr(f, "raw", None) or {}).get("declared_capability"))


def _undeclared(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if not is_declared_capability(f)]


def gate_decision(findings: List[Finding], policy: Policy) -> Tuple[str, str]:
    """Map a set of pre-call findings to a gate decision + human reason.

    Pure and deterministic. ``confirm`` is *not yet resolved* here — the caller
    resolves it against elicitation support / fail-closed via
    :func:`resolve_confirm`. This keeps the policy identical in live and headless
    modes.

    rule P0.5: only medium/high-confidence findings may confirm or block. A
    finding that clears the severity bar but has low confidence never gates
    the call on its own — it downgrades to ``allow_annotate`` (allow, with a
    warning), because a low-confidence signal is exactly the shape of an
    honest tool that merely looks superficially similar to an attack."""
    floor = policy.min_report_severity
    rank = worst_rank(findings, floor)
    if rank == 0:
        if low_confidence_rank(findings, floor) > 0:
            return ALLOW_ANNOTATE, "only low-confidence findings — allowed, with a warning"
        return ALLOW, "no finding at or above the report floor"
    if rank >= SEVERITY_RANK["high"]:
        if policy.block_high:
            # v4-8 — when every finding at the blocking bar is a declared
            # capability and the policy allows those, confirm instead.
            if (policy.allow_declared_capabilities
                    and worst_rank(_undeclared(findings), floor) < SEVERITY_RANK["high"]):
                return CONFIRM, ("high/critical finding on a capability the tool openly "
                                 "declares — allow_declared_capabilities: confirm instead of block")
            return BLOCK, "high/critical finding (medium/high confidence) — blocked by default posture"
        return CONFIRM, "high/critical finding (medium/high confidence) — policy downgraded to confirm"
    # low / medium
    if policy.confirm_low_medium:
        return CONFIRM, "uncertain low/medium finding — human confirmation required"
    return ALLOW_ANNOTATE, "low/medium finding — annotated, not blocked (policy)"


def resolve_confirm(decision: str, policy: Policy, *,
                    elicitation_supported: bool,
                    approved: Optional[bool] = None) -> Tuple[str, str]:
    """Resolve a ``confirm`` to a final forward/deny action.

    * ``approved is True``  -> allow (user approved via elicitation)
    * ``approved is False`` -> block (user denied)
    * ``approved is None``  -> unresolved: block if no elicitation or fail-closed,
      else stay ``confirm`` (the caller will actually prompt)."""
    if decision != CONFIRM:
        return decision, ""
    if approved is True:
        return ALLOW, "user approved via elicitation"
    if approved is False:
        return BLOCK, "user denied via elicitation"
    if not elicitation_supported:
        return BLOCK, "client lacks elicitation — fail-closed fallback to block"
    if policy.fail_closed:
        return BLOCK, "--fail-closed: unresolved confirm becomes block"
    return CONFIRM, "awaiting user confirmation"


def startup_action(poison_findings: List[Finding], policy: Policy) -> Tuple[str, str]:
    """Per-tool action at the tools/list audit (interposition point 1).

    rule P0.5: withholding a tool is the harshest action this interposition point
    has, so it requires a medium/high-confidence finding (``worst_rank``
    already filters on that). A low-confidence finding still gets surfaced —
    at most as an annotation — never a silent withhold."""
    rank = worst_rank(poison_findings, policy.min_report_severity)
    if rank == 0:
        if low_confidence_rank(poison_findings, policy.min_report_severity) > 0:
            return ANNOTATE, "only low-confidence poisoning signal — annotated, not withheld"
        return PASS, "clean"
    if rank >= SEVERITY_RANK[policy.withhold_threshold]:
        # v4-8 — a declared capability is annotated, never withheld, when
        # the policy allows declared capabilities (and nothing undeclared
        # reaches the threshold on its own).
        if (policy.allow_declared_capabilities
                and worst_rank(_undeclared(poison_findings), policy.min_report_severity)
                < SEVERITY_RANK[policy.withhold_threshold]):
            return ANNOTATE, ("finding at/above the withhold threshold is a capability the "
                              "tool openly declares — allow_declared_capabilities: annotated, "
                              "not withheld")
        return WITHHOLD, f"poisoning at/above '{policy.withhold_threshold}' (medium/high confidence) — tool withheld"
    if policy.annotate_poisoned:
        return ANNOTATE, "sub-threshold poisoning — description annotated with a warning"
    return PASS, "sub-threshold poisoning — passed (policy)"


def response_action(resp_findings: List[Finding], policy: Policy) -> Tuple[str, str]:
    """Action for a scanned response (interposition point 3).

    rule P0.5: blocking a response requires medium/high confidence; a
    low-confidence finding is annotated (the agent still sees a warning) but
    never silently blocked on confidence alone."""
    rank = worst_rank(resp_findings, policy.min_report_severity)
    if rank == 0:
        if low_confidence_rank(resp_findings, policy.min_report_severity) > 0:
            return ANNOTATE, "only low-confidence response signal — annotated, not blocked"
        return PASS, "clean"
    if rank >= SEVERITY_RANK[policy.response_block_threshold]:
        return BLOCK, f"response finding at/above '{policy.response_block_threshold}' (medium/high confidence) — blocked"
    if policy.response_annotate:
        return ANNOTATE, "response annotated with a warning the agent will read"
    return PASS, "sub-threshold response finding — passed (policy)"


@dataclass
class ApprovalMemory:
    """Remembers approved identical calls for the session."""
    enabled: bool = True
    _approved: set = field(default_factory=set)

    @staticmethod
    def key(tool: str, arguments: Any) -> str:
        return tool + "\x00" + json.dumps(arguments, sort_keys=True, default=str)

    def remember(self, tool: str, arguments: Any) -> None:
        if self.enabled:
            self._approved.add(self.key(tool, arguments))

    def is_approved(self, tool: str, arguments: Any) -> bool:
        return self.enabled and self.key(tool, arguments) in self._approved
