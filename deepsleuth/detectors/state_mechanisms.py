"""Cross-tool, module-wide static mechanisms that no single-function view
catches: an ownership-less session/identifier lookup (rule P5.2), an audit trail
that is present in form but not substance (rule 5.9 widened), and covert
cross-tool data collection (rule 5.5 source corroboration). All three reason over
a *whole module* (multiple tool functions at once), which is why they live
here rather than in ``privilege.py``/``auth_audit.py`` (single-tool contract
checks) — see ``analysis.pyast`` for the mechanism-level rationale on each.
"""
from __future__ import annotations

from typing import List

from ..analysis.pyast import (
    analyze_audit_trail,
    analyze_covert_collection,
    analyze_session_reuse,
)
from ..context import ScanContext
from ..models import Finding
from .base import CAP_SOURCE, Detector, register
from ._util import mk


def _run_session_reuse(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    for path, tree, _text, _g in ctx.source_modules:
        for issue in analyze_session_reuse(tree):
            out.append(mk(
                ctx, detector_id="session-reuse", category="confused-deputy",
                evidence_location="source", severity="high", confidence="high",
                detection_method="ownership-check-analysis",
                rationale=("Tool looks up and returns a record from server-side state "
                           f"using '{issue['lookup_param']}' as the sole key, with no "
                           "comparison of the looked-up record against any other "
                           "supplied value — possessing the identifier is treated as "
                           "sufficient proof of ownership, so a guessed/observed/shared "
                           "identifier issued to one caller discloses another caller's "
                           "data."),
                evidence={"tool": issue["tool"], "lookup_param": issue["lookup_param"],
                          "store": issue["store"], "other_params": issue["other_params"],
                          "module": path},
                source_kind="static-code", tool_name=issue["tool"],
            ))
    return out


def _run_audit_trail(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    for path, tree, text, _g in ctx.source_modules:
        for issue in analyze_audit_trail(tree, text):
            if issue["kind"] == "no_log":
                rationale = (
                    f"Server exposes '{issue['exposer']}' as a queryable audit trail "
                    f"(a structural declaration that actions are logged), but the "
                    f"destructive tool '{issue['tool']}' contributes nothing to it at "
                    "all — the audit trail exists in form but not in substance for "
                    "this action.")
            elif issue["kind"] == "partial_log":
                rationale = (
                    f"Server exposes '{issue['exposer']}' as a queryable audit trail, "
                    f"and '{issue['tool']}' DOES log on at least one of its branches — "
                    "but a DIFFERENT state-changing branch of the SAME tool "
                    f"(around line {issue.get('unlogged_branch_line')}) contributes "
                    "nothing to the log at all. A branch that logs makes the whole "
                    "function look compliant while a sibling branch silently skips "
                    "the audit trail for the same kind of destructive action.")
            else:
                rationale = (
                    f"Server exposes '{issue['exposer']}' as a queryable audit trail, "
                    f"but the destructive tool '{issue['tool']}' only ever logs a "
                    "hard-coded, generic entry with no trace of the actual action "
                    "taken -- a log that can never reflect what happened.")
            out.append(mk(
                ctx, detector_id="audit-trail-ineffective",
                category="auth-misconfiguration",
                evidence_location="source", severity="medium", confidence="medium",
                detection_method="declared-log-vs-implemented-audit",
                rationale=rationale,
                evidence={"tool": issue["tool"], "log": issue["log"],
                          "exposer": issue["exposer"], "kind": issue["kind"],
                          "unlogged_branch_line": issue.get("unlogged_branch_line"),
                          "module": path},
                source_kind="static-code", tool_name=issue["tool"],
            ))
    return out


def _run_covert_collection(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    for path, tree, _text, _g in ctx.source_modules:
        for issue in analyze_covert_collection(tree):
            out.append(mk(
                ctx, detector_id="covert-collection", category="data-exfiltration",
                evidence_location="source", severity="high", confidence="high",
                detection_method="silent-collector-vs-concealed-exposer",
                rationale=(f"Tool '{issue['collector']}' silently persists its own "
                           f"caller-supplied arguments into '{issue['store']}', a store "
                           "its own description never mentions, and the only way to "
                           f"read it back is '{issue['exposer']}', a concealed/"
                           "undocumented tool -- a covert cross-tool collection "
                           "mechanism invisible to anyone reading either tool's "
                           "description alone."),
                evidence={"collector": issue["collector"], "exposer": issue["exposer"],
                          "store": issue["store"], "module": path},
                source_kind="static-code", tool_name=issue["collector"],
            ))
    return out


register(Detector(
    id="session-reuse", category="confused-deputy", evidence_location="source",
    phase="tool listing", run=_run_session_reuse, requires={CAP_SOURCE},
    rationale=("A session/token-shaped identifier used as the only key into shared "
               "server state, with no verification that the presenter is who it was "
               "issued to, is a confused-deputy/BOLA shape independent of whether the "
               "identifier itself is guessable or merely observable -- generalizes "
               "across any identifier vocabulary naming a session/auth handle."),
))

register(Detector(
    id="audit-trail-ineffective", category="auth-misconfiguration",
    evidence_location="source", phase="listing", run=_run_audit_trail,
    requires={CAP_SOURCE},
    rationale=("A dedicated 'read the audit trail' tool is itself a structural "
               "declaration that the server logs actions -- no English promise "
               "required. A destructive tool that skips it, or only ever appends a "
               "constant string, contradicts that declaration exactly like a "
               "hint-vs-behavior mismatch."),
))

register(Detector(
    id="covert-collection", category="data-exfiltration", evidence_location="source",
    phase="listing", run=_run_covert_collection, requires={CAP_SOURCE},
    rationale=("A tool that persists caller-supplied data into a store its own "
               "description never mentions, retrievable only through a separate "
               "concealed/undocumented tool, is a covert collection channel -- the "
               "mechanism a manifest-only or single-tool-at-a-time scan cannot see "
               "because no individual tool's contract looks wrong in isolation."),
))
