"""Pre-call the gate detectors (rule 4.7 interposition point 2).

Run in the ``precall`` phase against ``ctx.pending_call`` — one pending tools/call
plus the target tool's contract and accumulated state. They surface the per-call
risks the gate maps to allow / elicit / block:

* an argument carrying a credential/secret-shaped value (or a planted decoy canary)
  toward a tool whose contract does not justify holding secrets and which can
  reach the network — a confused-deputy / exfiltration hard rule,
* a call to a tool that source analysis shows has a taint path to a dangerous sink
  — the call may trigger command/code injection,
* invoking a tool that declares readOnly but whose implementation mutates state.

Written once; the batch frontend can also run them per synthesized call.
"""
from __future__ import annotations

import re
from typing import List

from ..analysis.pyast import is_secret_hint_name
from ..context import CANARIES, ScanContext, _walk_strings
from ..models import Finding
from .base import CAP_DYNAMIC, Detector, register
from ._util import mk
from .privilege import MUTATING
from .response import SECRET_VALUE_RE

# rule P0.7: whole-token match now lives in analysis.pyast.is_secret_hint_name
# (shared with argument synthesis) — a bare substring regex is what let
# "author" (contains "auth") register as a secret-shaped argument key.
# For free-text tool description prose (not an identifier — spaces, not
# camelCase/underscores, separate its words) a plain word-boundary regex is
# the right tool: \bauth\b matches the standalone word "auth" but not the
# "auth" inside "author", because there is no word boundary between the 'h'
# and the 'o' of "author".
_SECRET_HINT_PROSE_RE = re.compile(
    r"\b(password|secret|token|api[_-]?key|credential|private[_-]?key|ssh|"
    r"auth(?:oriz\w*|entic\w*)?)\b", re.IGNORECASE)


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    from math import log2
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in counts.values())


def _looks_secret(value: str, key: str) -> bool:
    if not isinstance(value, str) or len(value) < 8:
        return False
    if SECRET_VALUE_RE.search(value):
        return True
    if CANARIES.is_canary(value) and ("SECRET" in value or "AKIA" in value
                                      or value.startswith("sk-")):
        return True
    # secret-shaped: named like a secret AND high-entropy token-ish
    if is_secret_hint_name(key) and len(value) >= 12 and _shannon(value) > 3.4 \
            and not re.search(r"\s", value):
        return True
    return False


def _run(ctx: ScanContext) -> List[Finding]:
    call = ctx.pending_call
    if call is None:
        return []
    out: List[Finding] = []
    contract = ctx.tool_by_name(call.tool_name)
    desc = (contract.description if contract else "") or ""
    desc_secret_ok = bool(_SECRET_HINT_PROSE_RE.search(desc)) or \
        bool(re.search(r"\b(login|vault|store|encrypt|sign)\b", desc, re.I))
    net_capable = bool(contract and contract.source and contract.source.facts.network)

    # 1) secret-shaped argument toward an unjustified / network-capable tool
    for value, path in _walk_strings(call.arguments):
        key = path.split(".")[-1].split("[")[0]
        if _looks_secret(value, key):
            if net_capable and not desc_secret_ok:
                sev, conf, cat = "high", "high", "confused-deputy"
            elif not desc_secret_ok:
                sev, conf, cat = "medium", "medium", "data-exfiltration"
            else:
                continue
            out.append(mk(
                ctx, detector_id="gate-secret-arg", category=cat,
                evidence_location="schema", severity=sev, confidence=conf,
                detection_method="precall-arg-scan",
                rationale=("Call passes a credential/secret-shaped value in argument "
                           f"'{path}' to a tool whose described scope does not justify "
                           "handling secrets"
                           + (" and which can reach the network" if net_capable else "")
                           + " — confused-deputy / exfiltration risk."),
                evidence={"tool": call.tool_name, "arg_path": path,
                          "network_capable": net_capable,
                          "value_shape": "canary" if CANARIES.is_canary(value)
                          else "secret-pattern"},
                source_kind="dynamic-runtime", tool_name=call.tool_name,
                raw={"gate_relevant": True},
            ))
            break

    # 2) call to a tool with a source taint path to a dangerous sink
    if contract and contract.source:
        tainted_sinks = [s for s in contract.source.facts.sinks
                         if s.tainted and s.kind in ("command-exec", "code-exec",
                                                      "deserialize")]
        if tainted_sinks and call.arguments:
            s = tainted_sinks[0]
            out.append(mk(
                ctx, detector_id="gate-taint-call", category="command-injection",
                evidence_location="schema", severity="high", confidence="medium",
                detection_method="precall-taint-match",
                rationale=("Invoking a tool whose source has an unsanitized taint path "
                           f"from parameters to a {s.kind} sink ({s.call}); this call "
                           "supplies arguments that can drive that sink."),
                evidence={"tool": call.tool_name, "sink": s.call, "line": s.lineno,
                          "arguments_keys": sorted(call.arguments.keys())},
                source_kind="dynamic-runtime", tool_name=call.tool_name,
                raw={"gate_relevant": True},
            ))

    # 3) readOnly-declared tool that source shows mutates
    if contract and contract.declared_readonly() is True and contract.source:
        if contract.source.facts.behavior_labels() & MUTATING:
            out.append(mk(
                ctx, detector_id="gate-readonly-call", category="excessive-privilege",
                evidence_location="schema", severity="high", confidence="high",
                detection_method="precall-hint-vs-behavior",
                rationale=("Invoking a tool that declares readOnlyHint=true but whose "
                           "implementation mutates state — the call will have side "
                           "effects the contract denies."),
                evidence={"tool": call.tool_name,
                          "behavior": sorted(contract.source.facts.behavior_labels())},
                source_kind="dynamic-runtime", tool_name=call.tool_name,
                raw={"gate_relevant": True},
            ))
    return out


register(Detector(
    id="gate-precall", category="confused-deputy", evidence_location="schema",
    phase="precall", run=_run, requires={CAP_DYNAMIC},
    rationale=("The gate needs per-call signals: a secret heading to an unjustified "
               "sink, a call that can drive a known taint path, or a readOnly tool "
               "being invoked in a mutating way. These are the affirmative conditions "
               "that justify pausing or blocking a specific call rather than the tool "
               "in general."),
))
