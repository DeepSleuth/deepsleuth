"""v6-W6 — the obfuscation signal for strings assembled from constants.

``static-response-poisoning`` and the description poison families read string
LITERALS. A string assembled at runtime from integer constants --
``"".join(chr(c) for c in (73, 103, ...))``, ``chr(73) + chr(103) + ...``,
``bytes([...]).decode()``, a loop appending ``chr(c)`` for each ``c`` of a
constant tuple -- never appears as a literal. Constant folding
(``analysis/constfold.py``) recovers the string (and ``static-response-poisoning``
grades the folded literal exactly like a written one); THIS detector reports the
assembly itself: building a returned or compared string out of a chain of
``chr()`` calls on constants has no purpose except hiding it from a reader,
even when the folded text happens to look benign.

The distinguishing feature is CONSTANTS, not the ``chr`` call: ``chr``/``ord``
applied to a caller-supplied value (a Caesar/ROT encoder, a decoder) never folds
and is never reported, a ``range()``-defined alphabet is a formula, and a
standard codec (``base64``) is not touched.

Grading: low severity / medium confidence for the bare assembly (spec: "low/medium");
medium severity when the folded text itself carries an agent-directed mechanism
family (the poison grading in ``static-response-poisoning`` is the full-severity
path; this keeps the obfuscation visible beside it).
"""
from __future__ import annotations

from typing import List

from ..analysis.textrules import analyze_text
from ..context import ScanContext
from ..models import Finding
from .base import CAP_SOURCE, Detector, register
from ._util import mk


def _run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    for c in ctx.all_contracts():
        if not c.source or c.source.facts is None:
            continue
        recs = getattr(c.source.facts, "assembled_strings", None) or []
        if not recs:
            continue
        returned = [r for r in recs if r.get("usage") == "returned"]
        chosen = returned or recs
        rec = chosen[0]
        text = rec.get("text") or ""
        try:
            rr = analyze_text(text)
            fams = sorted(f for f in rr.families if f != "sensitive_reference")
        except Exception:
            fams = []
        sev = "medium" if fams else "low"
        usage = rec.get("usage") or "returned"
        category = "prompt-injection" if returned else "other"
        out.append(mk(
            ctx, detector_id="const-string-assembly", category=category,
            evidence_location="source", severity=sev, confidence="medium",
            detection_method="chr-constant-chain",
            rationale=(f"Tool '{c.name}' builds a string character-by-character from "
                       f"constants ({rec.get('chr_calls', 0)} chr()/byte codepoints, no "
                       f"caller input involved) and "
                       f"{'returns' if usage == 'returned' else 'compares against'}"
                       f" it -- a literal-matcher-evading assembly with no benign purpose."
                       + (f" The folded text carries agent-directed mechanism(s) {fams}."
                          if fams else "")),
            evidence={"folded_text": text[:300], "usage": usage,
                      "chr_calls": rec.get("chr_calls", 0), "line": rec.get("lineno"),
                      "code": rec.get("snippet", "")[:160],
                      "module": rec.get("module") or c.source.module_path,
                      "via": rec.get("via") or "", "families": fams},
            source_kind="static-code", tool_name=c.name,
            raw={"obfuscation": "chr-constant-chain"},
        ))
    return out


register(Detector(
    id="const-string-assembly", category="prompt-injection", evidence_location="source",
    phase="tool listing", run=_run, requires={CAP_SOURCE},
    rationale=("A returned or compared string assembled from a chain of chr() calls on "
               "constants is hidden from every literal-based matcher; the assembly "
               "itself is the obfuscation, independent of what it spells."),
))
