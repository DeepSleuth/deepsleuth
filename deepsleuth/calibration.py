"""The shared, ADDITIVE calibration layer.

Architecture (the core idea of this pass): detectors run at full sensitivity and
ALWAYS emit their finding into the output JSON — recall is preserved, nothing is
deleted or threshold-silenced. This module runs immediately after every detector
phase (see ``runner.run_phase``, called identically by both Frontend A and
Frontend B) and does exactly one thing: it sets each finding's ``confidence``
from a deterministic **contradiction + corroboration** signal. It never deletes a
finding, never changes its ``severity``, and never invents a category — it only
ranks findings so the gate (which acts on ``severity`` + ``confidence`` together,
per the rule 6/ACTIONABLE-bar contract) can tell a genuine attack from an honestly
self-described tool that merely has the same *shape*.

Two kinds of findings reach the pipeline:

1. **Self-proving mechanisms** (``UNCONDITIONAL_DETECTOR_IDS``). For these the
   contradiction is inherent to the evidence itself — a planted canary
   surfacing in an unrelated response, a decisive agent-directed instruction
   delivered through a tool's output, runtime metadata that mutated after
   inspection, a hint proven false by observed behavior, a tainted flow into a
   dangerous sink, a dangerous install-time payload. There is no "honest tool
   that looks like this" — so calibration passes these through untouched
   (Part A: "no threshold may suppress it").
2. **Contract-claim findings** (auth/audit, tool-poisoning corroboration,
   supply-chain hook shape). For these we compute an explicit contradiction/
   corroboration signal from data the detector already exposes on
   ``finding.raw`` and set confidence from it, generically, in one place —
   instead of leaving the precision decision scattered across each detector
   (Part B).

No LLM, no randomness: same findings + same context -> same confidence, always.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

from .context import ScanContext
from .models import Finding

CONF_RANK = {"low": 0, "medium": 1, "high": 2}

# Part A's three restored-recall mechanisms, plus every other detector that
# already gates strictly on a self-proving contradiction (a hint contradicted
# by observed behavior, a tainted source->sink path, a runtime metadata/
# response mutation, unicode/encoding concealment). Calibration never lowers
# these — the mechanism itself IS the contradiction.
UNCONDITIONAL_DETECTOR_IDS = frozenset({
    "response-leak",            # rule 5.5 / Part A.1 — planted canary surfaced
    "response-oversharing",     # rule 5.5/P2.2 — response shape exceeds declared scope
    "response-injection",       # rule 5.3a / Part A.2 — decisive directive in output
    "rugpull-runtime",          # rule 5.2 — metadata/response mutated after tool listing
    "hint-violation",           # rule 5.4 — declared hint contradicted by behavior
    "auth-control-ineffective", # rule 5.9 — a present control proven not to gate
    "session-reuse",            # rule 5.9/P5.2 — ownership-less lookup by shared/guessable id
    "covert-collection",        # rule 5.5 — silent cross-tool collection + concealed exposer
    "ast-taint",                # rule 5.3b/5.6 — tainted flow into a dangerous sink
    "name-obfuscation",         # rule 5.1 — unicode spoofing is self-proving
    "desc-obfuscation",         # rule 5.1 — concealed content is self-proving
    "static-response-poisoning",  # rule P2.1 — same strict response-grading as
                                   # response-injection, just read from source
})


def calibrate(findings: List[Finding], ctx: ScanContext) -> List[Finding]:
    """Additive: sets ``finding.confidence`` in place; never removes a finding,
    never touches ``severity``. Both frontends call this via
    :func:`deepsleuth.runner.run_phase`, so behavior is identical everywhere."""
    if not findings:
        return findings
    _calibrate_auth_audit(findings)
    _calibrate_supply_chain(findings)
    _calibrate_tool_shadowing(findings)
    _corroborate_poisoning_across_evidence_locations(findings)
    _calibrate_environ_dump(findings)
    _corroborate_state_drift_instruction(findings)
    return findings


# ---------------------------------------------------------------------------
# auth/audit family (Part B): "never actionable on mere absence of a check;
# actionable only when a check is claimed-but-absent or present-but-
# ineffective." auth-control-ineffective is already a proven contradiction
# (unconditional, above). auth-gap/audit-gap fire only on a *claimed*
# requirement with nothing in the body at all — that is already a real
# contradiction, but its strength varies: a claim on a tool that also has
# real destructive/sensitive capability is strong corroboration (a genuine gap
# in something that matters); a claim on an otherwise low-stakes tool is
# weaker (as likely to be an external-middleware dependency the static pass
# cannot see as a real gap) — report it, but don't let the gate act on it.


def _calibrate_auth_audit(findings: List[Finding]) -> None:
    for f in findings:
        if f.detector_id not in ("auth-gap", "audit-gap"):
            continue
        corroborated = bool(f.raw.get("destructive") or f.raw.get("sensitive_named"))
        f.confidence = "medium" if corroborated else "low"
        f.raw["calibration"] = (
            "declared-but-absent claim corroborated by real destructive/"
            "sensitive capability on the same tool" if corroborated else
            "declared-but-absent claim with no destructive/sensitive "
            "corroboration on this tool -- report-only; enforcement may live "
            "in middleware this static pass cannot see"
        )


# ---------------------------------------------------------------------------
# supply-chain family (Part A.3): a hook is actionable on its own once it
# reaches one of the four unambiguous shapes (network call, credential-path
# read, obfuscated payload, or a bundled non-build script whose OWN content
# reaches one of those shapes) — the detector tags this on ``raw
# ["dangerous_shape"]``. A hook whose only signal is a soft structural note
# (typosquat edit-distance, a custom install command class, an in-tree build
# backend) has no further corroboration this static pass can add, so its
# detector-assigned (already low/medium) confidence stands.


def _calibrate_supply_chain(findings: List[Finding]) -> None:
    for f in findings:
        if f.detector_id != "supply-chain":
            continue
        if f.raw.get("dangerous_shape"):
            f.confidence = "high"
            f.raw.setdefault(
                "calibration",
                "network/credential-path/obfuscated-payload/dangerous-referenced"
                "-script is a self-proving contradiction for an install step",
            )


# ---------------------------------------------------------------------------
# tool-shadowing family (Part B): "actionable only on a claim to be/replace/
# override a distinct, separately-named entity; self-reference or common
# verbs -> not actionable." The detector already gates the *decisive*
# identity-assertion finding on exactly that (a shadow verb whose object is a
# genuinely foreign entity, v5-7, with a SELF_REF exclusion) -- that gate IS the
# contradiction check, so its high/medium stands unconditionally. What
# calibration adds: a bare handshake name mismatch is corroborated only when
# the mismatch is paired with an authority-claiming word AND no plausible
# self-identity match -- already true of how the detector computes it, so we
# simply confirm/keep it at its already-conservative "low" (soft signal, rule 5.7
# docstring: "possible identity spoofing"). Left explicit (rather than
# silently falling through) so the contract is visible in one place.


def _calibrate_tool_shadowing(findings: List[Finding]) -> None:
    for f in findings:
        if f.detector_id != "server-identity":
            continue
        f.raw.setdefault(
            "calibration",
            "handshake identity vs. configured identity is a soft signal on its "
            "own -- kept at low confidence unless corroborated by another "
            "finding on the same target",
        )


# ---------------------------------------------------------------------------
# tool-poisoning corroboration (Part B, "+ corroboration"): the SAME tool
# poisoned across MULTIPLE distinct evidence locations (its description AND
# its schema, or its description AND its name) is materially stronger
# evidence than a single non-decisive match -- an honest tool essentially
# never has agent-directed language leak into two independent surfaces at
# once. This only ever RAISES confidence (additive; never lowers a finding a
# detector already trusts).


def _corroborate_poisoning_across_evidence_locations(findings: List[Finding]) -> None:
    by_tool: Dict[Tuple[str, str], List[Finding]] = {}
    for f in findings:
        if f.category not in ("tool-poisoning", "agent-config-poisoning"):
            continue
        if f.severity == "none":
            continue
        if (f.raw or {}).get("informational"):
            continue  # v5-1 — an informational note corroborates nothing
        by_tool.setdefault((f.target_id, f.tool_name or ""), []).append(f)
    for (_target, _tool), group in by_tool.items():
        locs = {f.evidence_location for f in group}
        if len(locs) < 2:
            continue
        for f in group:
            if CONF_RANK[f.confidence] < CONF_RANK["high"]:
                f.confidence = "high"
                f.raw["calibration"] = (
                    "corroborated: a poisoning mechanism was observed across "
                    f"multiple independent evidence locations {sorted(locs)} on "
                    "the same tool"
                )


# ---------------------------------------------------------------------------
# v6-W3 environment dump: the source SHAPE (the whole mapping reaches a
# return) is graded high severity / medium confidence by the detector. What
# calibration adds is the contract-vs-behavior corroboration: a tool that
# carries a description which says nothing about the environment is returning
# something its contract never promised -> confidence high. A tool that
# declares it (capability lane, low/low) is left exactly as the detector graded
# it -- calibration never touches a declared-capability note (v3-1.1).


def _calibrate_environ_dump(findings: List[Finding]) -> None:
    for f in findings:
        if f.detector_id != "environ-dump":
            continue
        if (f.raw or {}).get("declared_capability"):
            continue
        if (f.raw or {}).get("description_mismatch") and CONF_RANK[f.confidence] < CONF_RANK["high"]:
            f.confidence = "high"
            f.raw["calibration"] = (
                "corroborated: the tool returns the whole process environment and "
                "its description (present) does not mention the environment at all")


# ---------------------------------------------------------------------------
# v6-W2 state-drift instruction: a repeated identical call whose NEW response
# carries an agent-directed instruction is graded high severity / medium
# confidence by the detector (a new matcher defaults to medium). The drift +
# a source-level call-counter / time / env gate on the SAME tool (the
# detector records it on ``raw.source_gate``) is the classic rug-pull pair:
# the gate explains WHY the response flipped, so the two together are
# corroboration -> confidence high.


def _corroborate_state_drift_instruction(findings: List[Finding]) -> None:
    for f in findings:
        if f.detector_id != "rugpull-runtime" or f.detection_method != "response-diff-instruction":
            continue
        if (f.raw or {}).get("source_gate") and CONF_RANK[f.confidence] < CONF_RANK["high"]:
            f.confidence = "high"
            f.raw["calibration"] = (
                "corroborated: the drifted response carries an agent-directed "
                "instruction AND the same tool's source gates behavior on a "
                "call counter / time / env toggle")
