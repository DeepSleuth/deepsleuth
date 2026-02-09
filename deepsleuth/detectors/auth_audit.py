"""rule 5.9 — auth / audit gaps, and rule P3.2 — "control present but ineffective".

v1 fired on the *lexical absence* of an auth/logging token, which legitimately-
designed, honestly-unauthenticated tools trip constantly (P1.1: the single
biggest false-positive source) while simultaneously missing real bypasses whose
code merely *contains* an auth-shaped word (P3.2: a poor-recall failure mode of
the same lexical check — see ``auth_evidence`` below).

v2 principle (declared contract vs. actual behavior, applied to auth): absence of
a visible check is NOT itself evidence of a vulnerability — a benign,
legitimately-unauthenticated utility tool must not fire. We only report when
there is a *positive* signal:

1. **A control is present but provably ineffective** (``auth-control-ineffective``,
   rule P3.2). Control-flow reasoning (``analysis.pyast.analyze_auth_control``) finds
   an auth-shaped call or a permission-shaped parameter and proves it cannot the gate
   the action: the result is discarded, the parameter is never consulted, or no
   branch halts when the check fails. This is a verifiable contradiction, not a
   guess, so it is reported at real severity/confidence and *replaces* the old
   absence heuristic's recall for exactly the cases that heuristic missed (a
   lexical "auth" token in a dead parameter name used to read as "has an auth
   check").
2. **The declared contract explicitly promises authorization, but no signal of
   any kind exists in the body** (``auth-gap``). Only fires when the
   tool description/name itself claims a requirement ("requires authorization",
   "admin only", ...) — i.e. a real declared-vs-implemented contradiction — not
   on the mere shape of the tool (destructive-sounding name, no visible check).
3. **audit-gap** mirrors this for logging: only fires when the description
   explicitly promises an audit trail that the body does not implement.
4. **weak-session** is unchanged: it fires on a *positive* bad pattern (a
   session/token assigned from a guessable source), not an absence.

All four remain low/medium severity and confidence — even a real hit here is a
softer signal than a confirmed taint path or hint violation (rule 3.1/DETECTORS.md).
"""
from __future__ import annotations

import re
from typing import List

from ..context import ScanContext
from ..models import Finding
from .base import CAP_SOURCE, Detector, register
from ._util import mk

SENSITIVE_NAME = re.compile(
    r"\b(delete|remove|drop|truncate|purge|wipe|revoke|grant|transfer|pay|"
    r"payment|wire|refund|admin|sudo|escalat\w+|disable|deactivate|shutdown|"
    r"exec|execute|deploy|password|secret|credential|key)\b", re.IGNORECASE)
# rule P0.10: the short-string-literal branch is dropped outright — a short
# CONSTANT string is not a "guessable source", it is an honest fixed value
# (``token_type = "Bearer"``, an OAuth token-type label, is the textbook
# case: eight characters, matched the old ``['"][^'"]{0,8}['"]`` branch, and
# has nothing to do with predictable session identifiers). A genuinely
# guessable source is a runtime value an attacker can predict or enumerate:
# wall-clock time, a process id, a monotonically increasing counter — never a
# literal the source code itself hard-codes.
GUESSABLE_SESSION = re.compile(
    r"(session|token|api_?key|nonce|secret)\w*\s*=\s*"
    r"(str\()?(time\.time|datetime\.now|os\.getpid|itertools\.count|"
    r"self\.counter|counter\s*\+)",
    re.IGNORECASE)

# a real declared-requirement claim, not just an auth-adjacent word
DECLARED_AUTH_REQUIRED = re.compile(
    r"\brequires?\b.{0,30}\b(authoriz\w*|authenticat\w*|permission\w*|login|"
    r"admin\w*|role|token|credential\w*|privilege\w*)\b|"
    r"\b(authoriz\w*|authenticat\w*|admin)\w*\s+(only|required)\b|"
    r"\bmust\s+be\s+(authoriz\w*|authenticat\w*|logged\s?in|an?\s+admin)\b|"
    r"\brestrict(ed)?\s+to\b.{0,20}\b(admin\w*|authoriz\w*)\b",
    re.IGNORECASE)
DECLARED_AUDIT_REQUIRED = re.compile(
    r"\b(audit(s|ed|ing)?(\s+(trail|log))?|logg(ed|ing|s)\b.{0,15}\b(action|event|"
    r"call|request)s?)\b.{0,25}\b(is|are|will\s+be)?\s*(record|log|track|kept|"
    r"maintain)\w*|\brecords?\s+(an?\s+)?(audit|log)\b", re.IGNORECASE)


def _run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    for c in ctx.all_contracts():
        if not c.source:
            continue
        f = c.source.facts
        destructive = bool(f.behavior_labels() & {"deletes-files", "spawns-process",
                                                   "code-execution",
                                                   "mutates-server-state"})
        sensitive_named = bool(SENSITIVE_NAME.search(f"{c.name} {c.description}"))
        blob = f"{c.name} {c.description}"

        # 1) a control is present but provably does not gate the action (rule P3.2)
        if f.auth_effective is False:
            sev = "high" if (destructive or sensitive_named) else "medium"
            out.append(mk(
                ctx, detector_id="auth-control-ineffective",
                category="auth-misconfiguration",
                evidence_location="source", severity=sev, confidence="high",
                detection_method="auth-control-flow-analysis",
                rationale=("An authorization control is present (a check is called "
                           "or a permission parameter is accepted) but source "
                           f"control-flow shows it never gates the action: {f.auth_evidence}."
                           " This is a verifiable contradiction, not an absence."),
                evidence={"tool": c.name, "reason": f.auth_evidence,
                          "behavior": sorted(f.behavior_labels()),
                          "module": c.source.module_path},
                source_kind="static-code", tool_name=c.name,
            ))
        # 2) declared contract explicitly promises authorization but no signal
        #    of any kind exists in the implementation
        elif f.auth_effective is None and DECLARED_AUTH_REQUIRED.search(blob):
            # calibration (Part B) decides the final confidence from these
            # raw corroboration signals — see calibration._calibrate_auth_audit.
            out.append(mk(
                ctx, detector_id="auth-gap", category="auth-misconfiguration",
                evidence_location="source", severity="medium", confidence="medium",
                detection_method="declared-vs-implemented-auth",
                rationale=("Description/name explicitly declares an authorization "
                           "requirement, but the implementation contains no "
                           "auth-shaped check or parameter at all — the declared "
                           "contract is contradicted by the implementation "
                           "(enforcement may still live in middleware this static "
                           "pass cannot see)."),
                evidence={"tool": c.name, "declared_excerpt": blob[:200]},
                source_kind="static-code", tool_name=c.name,
                raw={"destructive": destructive, "sensitive_named": sensitive_named},
            ))

        # 3) audit-gap: only when the contract explicitly promises an audit trail
        if destructive and not f.has_logging and DECLARED_AUDIT_REQUIRED.search(blob):
            out.append(mk(
                ctx, detector_id="audit-gap", category="auth-misconfiguration",
                evidence_location="source", severity="low", confidence="low",
                detection_method="declared-vs-implemented-audit",
                rationale=("Description explicitly promises an audit trail for this "
                           "destructive/state-changing tool, but no logging call is "
                           "visible in its body — declared contract contradicted."),
                evidence={"tool": c.name, "behavior": sorted(f.behavior_labels()),
                          "declared_excerpt": blob[:200],
                          "module": c.source.module_path},
                source_kind="static-code", tool_name=c.name,
                raw={"destructive": destructive, "sensitive_named": sensitive_named},
            ))
    # 4) guessable session id anywhere in source (a positive bad pattern, not
    #    an absence)
    for path, tree, text, _g in ctx.source_modules:
        m = GUESSABLE_SESSION.search(text)
        if m:
            out.append(mk(
                ctx, detector_id="weak-session", category="auth-misconfiguration",
                evidence_location="source", severity="low", confidence="low",
                detection_method="guessable-identifier",
                rationale=("A session/token/secret identifier is derived from a "
                           "guessable source (time/counter/pid/short literal) — "
                           "predictable identifiers enable cross-session reuse."),
                evidence={"match": m.group(0)[:120], "module": path},
                source_kind="static-code", tool_name=None,
            ))
    return out


register(Detector(
    id="auth-gap", category="auth-misconfiguration", evidence_location="source",
    phase="tool listing", run=_run, requires={CAP_SOURCE},
    rationale=("Absence of a visible check is not itself evidence of a "
               "vulnerability — it is what every legitimately-unauthenticated "
               "utility tool looks like. We only report a *positive* "
               "contradiction: either the implementation proves a present auth "
               "signal does not gate the action (auth-control-ineffective, "
               "rule P3.2), or the declared contract explicitly promises "
               "authorization/audit that the implementation does not have at "
               "all."),
))
