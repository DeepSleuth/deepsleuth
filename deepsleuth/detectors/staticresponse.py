"""rule P2.1 — static response-literal scan.

A tool's own source can hand the agent a poisoned message as a hard-coded
string literal — an f-string's literal wrapper text, a module constant, or a
string nested one level inside a dict/list content-block return — never
requiring a live call to see. ``analysis.pyast.extract_returned_string_literals``
resolves that text statically (rule 2.1/pyast.py); this detector runs it through
the SAME response-grading rules the dynamic ``response-injection`` detector
uses (rules P1.3/P2.1's stricter bar: a decisive family alone, or a total >= 6
across two families) — reused directly from ``detectors.response`` so the two
frontends agree on what counts, static or dynamic.

This is exactly MSB's ``tool_transfer`` shape: a hard-coded
``<IMPORTANT>``-style redirect message returned unconditionally (or gated on
an argument value the synthesized call plan may never happen to hit) is
visible in source without ever running the server.
"""
from __future__ import annotations

from typing import List

from ..analysis.textrules import analyze_text
from ..context import ScanContext
from ..models import Finding
from .base import CAP_SOURCE, Detector, register
from .response import _grade_response, _own_param_names, planning_directive_clauses
from ._util import mk


def _run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    live_names = {c.name.lower() for c in ctx.all_contracts() if c.name}
    for c in ctx.all_contracts():
        src = c.source
        if src is None or src.facts is None:
            continue
        literals = getattr(src.facts, "returned_string_literals", None) or []
        origins = getattr(src.facts, "literal_origins", None) or {}
        seen = set()
        for lit in literals:
            if not lit or lit in seen:
                continue
            seen.add(lit)
            try:
                rr = analyze_text(lit)
                fire, sev, conf, primary = _grade_response(rr)
            except Exception:
                continue
            if not fire:
                # v5-5 — the static twin of the planning-directive rule: a
                # hard-coded literal is the server's own text, so the named
                # tool may be its own or another server's, and no retrieval
                # discount applies.
                try:
                    directives = planning_directive_clauses(
                        lit, live_names, _own_param_names(c))
                except Exception:
                    directives = []
                if directives:
                    pd = directives[0]
                    out.append(mk(
                        ctx, detector_id="static-response-poisoning",
                        category="prompt-injection", evidence_location="source",
                        severity="high", confidence="medium",
                        detection_method="static-return-literal-scan",
                        rationale=(
                            f"Tool '{c.name}' has a hard-coded string in its own source "
                            "that it hands back as (part of) its response, and that string "
                            "is a planning directive: an obligation aimed at the agent, an "
                            f"invoke verb whose object is the tool '{pd['named_tool']}', and "
                            "a reference to the agent's plan / next step / the user's "
                            f"request (\"{pd['plan_reference']}\") -- the response writing "
                            "the agent's plan for it, visible from source alone."
                        ),
                        evidence={"trigger": "planning-directive",
                                  "named_tool": pd["named_tool"], "verb": pd["verb"],
                                  "plan_reference": pd["plan_reference"],
                                  "own_tool": pd["own_tool"], "clause": pd["clause"],
                                  "literal_excerpt": lit[:400],
                                  **({"via": origins[lit]} if lit in origins else {})},
                        source_kind="static-code", tool_name=c.name,
                    ))
                continue
            out.append(mk(
                ctx, detector_id="static-response-poisoning", category="prompt-injection",
                evidence_location="source", severity=sev, confidence=conf,
                detection_method="static-return-literal-scan",
                rationale=(
                    f"Tool '{c.name}' has a hard-coded string in its own source "
                    "that it hands back as (part of) its response, and that "
                    f"string carries an agent-directed instruction mechanism "
                    f"[{primary}] -- a redirect/injection baked into the tool's "
                    "own output rather than triggered by any particular live "
                    "call, visible from source alone."
                    + (f" (The string is reached through a same-directory import: "
                       f"{origins[lit]}.)" if lit in origins else "")
                ),
                evidence={"families": rr.families, "literal_excerpt": lit[:400],
                          **({"via": origins[lit]} if lit in origins else {})},
                source_kind="static-code", tool_name=c.name,
            ))
    return out


register(Detector(
    id="static-response-poisoning",
    category="prompt-injection",
    evidence_location="source",
    phase="tool listing",
    run=_run,
    requires={CAP_SOURCE},
    rationale=(
        "A tool's own source can hand the agent a poisoned message as a "
        "hard-coded string literal (or an f-string's literal wrapper, or a "
        "string nested inside a dict/list content-block return) — the same "
        "mechanism response-injection catches dynamically, caught here from "
        "source alone, so it fires even on a static-only scan or a call path "
        "the synthesized call plan never reaches."
    ),
))
