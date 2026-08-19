"""rule 5.2 — rug-pull / behavior-flip / state-dependent behavior.

Three complementary views, none visible to a manifest-only scanner:

* source (listing phase): control flow gated on a *call counter*, *wall-clock/date*
  or an *environment toggle* that switches a tool's behavior — a branch whose only
  purpose is "act differently later." Gated for precision (call-counter and time
  gates are rare in honest tools; env gates only flagged when they guard mutating/
  exec/network behavior).
* runtime listing diff (multicall phase): re-list tools after exercising the
  server and diff against the first listing — any changed name/description/schema
  at runtime is a strong rug-pull signal.
* runtime response diff (multicall phase): a repeated *identical* call whose later
  response introduces an injection/leak mechanism the first did not.
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

from ..analysis.textrules import _clauses, analyze_text, instruction_shift_hits
from ..context import CallRecord, ScanContext, ToolContract
from ..models import Finding
from .base import CAP_DYNAMIC, CAP_SOURCE, Detector, register
from .poisoning import _grade as _grade_description
from ._util import mk

_VOLATILE = re.compile(
    r"\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}[:\d.]*z?|"       # iso timestamps
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|"  # uuid
    r"\d+(\.\d+)?",                                       # numbers
    re.IGNORECASE)


def _devolatile(s: str) -> str:
    return _VOLATILE.sub("#", s or "")


# rule 5.5/Part-A.1 (widened) — a cross-call leak does not require the leaked
# value to be a literal canary WE planted; a server can just as easily
# generate its own derived secret (a reset code, a one-time token) keyed to
# an identity and surface it through a completely different tool once that
# identity is queried again. The canary-based ``response-leak`` detector
# (context.CrossCallState) can only ever catch a value we ourselves supplied
# as an argument — it is structurally blind to a value the SERVER invents.
# The generalizing signal here is textual, not identity-based: a
# sensitive-labeled value (the "<label> is/was/: <value>" shape used by
# password-reset codes, OTPs, session tokens, ...) that is ABSENT from an
# identical repeated call's first response and PRESENT in a later one proves
# the value only exists because of an intervening, unrelated call — the same
# "repeated call, response drifts" evidence rugpull-runtime already gathers,
# just graded on secret-shape instead of injection-shape.
_SECRET_LABEL_VALUE_RE = re.compile(
    r"\b(?:api[ _-]?keys?|access[ _-]?keys?|secret[ _-]?keys?|private[ _-]?keys?|"
    r"passwords?|passwd|tokens?|credentials?|client[ _-]?secrets?|"
    r"reset[ _-]?codes?|verification[ _-]?codes?|security[ _-]?codes?|"
    r"access[ _-]?codes?|otp|pin(?:[ _-]?codes?)?|"
    r"one[ -]?time[ _-]?(?:codes?|passwords?|pins?))\b"
    r"[a-z0-9 _'\"()-]{0,20}?\b(?:is|was|[:=])\s*['\"]?([A-Za-z0-9][\w.\-]{2,60})",
    re.IGNORECASE,
)


def _labeled_secret_values(text: str):
    return {m.group(1) for m in _SECRET_LABEL_VALUE_RE.finditer(text or "")}


# ---- source rug-pull gates ---------------------------------------------------


def _run_source(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    for c in ctx.all_contracts():
        if not c.source:
            continue
        f = c.source.facts
        exec_or_mut = (f.spawns_proc or f.code_exec or f.network
                       or bool(f.behavior_labels() & {"writes-filesystem",
                                                       "deletes-files",
                                                       "mutates-server-state"}))
        if f.uses_call_counter_gate:
            out.append(mk(
                ctx, detector_id="rugpull-source", category="other",
                evidence_location="source", severity="medium", confidence="medium",
                detection_method="control-flow-the gate",
                rationale=("Tool behavior is gated on a call-counter / invocation "
                           "count — behaving differently after N calls is the "
                           "structural shape of a rug-pull."),
                evidence={"gate": "call-counter", "snippets": f.gate_snippets[:3],
                          "module": c.source.module_path},
                source_kind="static-code", tool_name=c.name,
            ))
        if f.uses_time_gate:
            sev = "medium" if exec_or_mut else "low"
            out.append(mk(
                ctx, detector_id="rugpull-source", category="other",
                evidence_location="source", severity=sev,
                confidence="medium" if exec_or_mut else "low",
                detection_method="control-flow-gate",
                rationale=("Tool behavior is gated on wall-clock time/date — a "
                           "time-delayed behavior switch is a rug-pull mechanism."),
                evidence={"gate": "wall-clock-time", "snippets": f.gate_snippets[:3],
                          "module": c.source.module_path},
                source_kind="static-code", tool_name=c.name,
            ))
        if f.uses_env_gate and exec_or_mut:
            out.append(mk(
                ctx, detector_id="rugpull-source", category="other",
                evidence_location="source", severity="low", confidence="low",
                detection_method="control-flow-gate",
                rationale=("An environment-variable toggle guards mutating/exec/"
                           "network behavior — an external switch that can flip the "
                           "tool's behavior after deployment."),
                evidence={"gate": "env-toggle", "snippets": f.gate_snippets[:3],
                          "module": c.source.module_path},
                source_kind="static-code", tool_name=c.name,
            ))
        # rule 2.2 — a runtime rewrite of a function's __doc__ or of registered
        # tool metadata: the declared contract a client inspected at listing
        # time is not the same code the server carries at call time.
        if f.mutates_tool_metadata:
            gated = f.uses_call_counter_gate or f.uses_time_gate or f.uses_env_gate
            # rule P4.3 — scan the TEXT actually assigned to the docstring with
            # the same description rules a declared description gets, so a
            # rewrite is graded on what it says, not just on the fact that a
            # rewrite happened: high when the new text itself carries an
            # agent-directed instruction mechanism, OR when the rewrite sits
            # behind a counter/time/env gate (the classic "passes inspection,
            # changes later" shape even if the new text reads as plain
            # prose); informational (low/low) when it is plain prose with no
            # gate at all — still worth recording, just not alarming.
            mutation_texts = f.tool_metadata_mutation_texts or []
            carries_instruction = False
            instruction_families: List[str] = []
            for text in mutation_texts:
                rr = analyze_text(text)
                fire, _, _, primary = _grade_description(rr)
                if fire:
                    carries_instruction = True
                    if primary and primary not in instruction_families:
                        instruction_families.append(primary)
            if carries_instruction or gated:
                sev, conf = "high", "high"
            else:
                sev, conf = "low", "low"
            reason_bits = []
            if carries_instruction:
                reason_bits.append(f"the rewritten text itself carries an agent-directed "
                                   f"instruction mechanism {instruction_families}")
            if gated:
                reason_bits.append("the rewrite sits behind the same call-counter/time/env "
                                   "gate already flagged above — the classic 'passes "
                                   "inspection, changes later' rug-pull shape")
            reason = ("; ".join(reason_bits) if reason_bits else
                     "the rewritten text is plain prose with no instruction mechanism and "
                     "no gate — recorded as an informational note")
            out.append(mk(
                ctx, detector_id="runtime-metadata-mutation", category="tool-poisoning",
                evidence_location="source", severity=sev, confidence=conf,
                detection_method="ast-metadata-assignment",
                rationale=(
                    "Source assigns to a function's __doc__ or to a tool-registry-"
                    "shaped description/instructions/annotations attribute at "
                    "runtime — the declared contract a client inspects at listing "
                    f"time is not fixed; it can be rewritten by the server's own "
                    f"code after that ({reason})."
                ),
                evidence={"snippets": f.tool_metadata_mutation_snippets[:3],
                          "mutation_texts": mutation_texts[:3],
                          "carries_instruction": carries_instruction,
                          "instruction_families": instruction_families,
                          "gated": gated, "module": c.source.module_path},
                source_kind="static-code", tool_name=c.name,
            ))
    return out


# ---- runtime listing + response diffs ---------------------------------------


def _drift_delta(first_text: str, later_text: str) -> str:
    """The clauses of ``later_text`` that are NOT in ``first_text`` once
    volatile tokens (timestamps / ids / numbers) are stripped -- the text the
    state drift actually introduced."""
    base = {_devolatile(c).strip().lower() for c in _clauses(first_text or "")}
    new = [c for c in _clauses(later_text or "")
           if _devolatile(c).strip().lower() not in base]
    return ". ".join(new)


def _drift_instruction(ctx: ScanContext, tool: str, first, later):
    """v6-W2 -- content-analyze the text a state drift introduced. Returns
    ``None`` or a dict of what in the NEW text speaks to the agent: the
    drift-scoped instruction-shift matcher, the response-injection matcher
    (``response._grade_response`` over the families), and the planning-
    directive clause matcher. Plain drift (counters, timestamps, declared
    state) returns None and stays a note."""
    from .response import _grade_response, _own_param_names, planning_directive_clauses
    delta = _drift_delta(first.response_text, later.response_text)
    if not delta.strip():
        return None
    shift = instruction_shift_hits(delta)
    rr = analyze_text(delta)
    fire_r, _sev, _conf, primary = _grade_response(rr)
    live = {c.name.lower() for c in ctx.all_contracts() if c.name}
    plans = planning_directive_clauses(delta, live, _own_param_names(ctx.tool_by_name(tool), later))
    if not (shift["fires"] or fire_r or plans):
        return None
    return {"delta": delta[:400], "shift": shift,
            "families": rr.families if fire_r else {},
            "primary_family": primary if fire_r else "",
            "planning_directives": plans[:3]}


def _source_gates(ctx: ScanContext, tool: str) -> List[str]:
    c = ctx.tool_by_name(tool)
    if not c or not c.source or c.source.facts is None:
        return []
    f = c.source.facts
    out = []
    if getattr(f, "uses_call_counter_gate", False):
        out.append("call-counter")
    elif getattr(f, "counter_gate_thresholds", None):
        # v6 — a counter gate living in a helper module the tool calls
        out.append("call-counter")
    if getattr(f, "uses_time_gate", False):
        out.append("wall-clock-time")
    if getattr(f, "uses_env_gate", False):
        out.append("env-toggle")
    return out


def _contract_sig(c: ToolContract) -> Tuple:
    import json
    return (c.description or "",
            json.dumps(c.input_schema, sort_keys=True, default=str),
            json.dumps(c.hints, sort_keys=True, default=str))


def _run_runtime(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []

    # 1) tools/list re-diff
    if ctx.tools_relisted is not None:
        before = {c.name: c for c in ctx.tools}
        after = {c.name: c for c in ctx.tools_relisted}
        for name in sorted(set(before) | set(after)):
            b, a = before.get(name), after.get(name)
            if b is None:
                out.append(_relist_finding(ctx, name, "tool-added", None, _contract_sig(a)))
            elif a is None:
                out.append(_relist_finding(ctx, name, "tool-removed", _contract_sig(b), None))
            elif _contract_sig(b) != _contract_sig(a):
                out.append(_relist_finding(ctx, name, "metadata-changed",
                                           _contract_sig(b), _contract_sig(a),
                                           b=b, a=a))

    # 2) response diff across repeated identical calls
    groups: Dict[Tuple[str, str], List[CallRecord]] = {}
    for call in ctx.calls:
        import json
        key = (call.tool_name, json.dumps(call.arguments, sort_keys=True, default=str))
        groups.setdefault(key, []).append(call)
    for (tool, _args), recs in sorted(groups.items()):
        if len(recs) < 2:
            continue
        first = recs[0]
        first_mech = set(analyze_text(first.response_text).families)
        first_secrets = _labeled_secret_values(first.response_text)
        # rule 3.8 — for a tool that DECLARES idempotentHint=true, the repeated-
        # call comparison must keep numbers (the ordinary ``_devolatile``
        # fallback strips every number, so a credits balance drifting
        # 15 -> 20 compares EQUAL and the violation is invisible: "the
        # response diff strips all numbers, so 15 and 20 compare equal").
        contract = ctx.tool_by_name(tool)
        declared_idempotent = bool(contract and contract.hints.get("idempotentHint") is True)
        for later in recs[1:]:
            later_mech = set(analyze_text(later.response_text).families)
            new_mech = later_mech - first_mech
            later_secrets = _labeled_secret_values(later.response_text)
            new_secrets = later_secrets - first_secrets
            if new_mech:
                out.append(mk(
                    ctx, detector_id="rugpull-runtime", category="prompt-injection",
                    evidence_location="multi-call-state", severity="high",
                    confidence="high", detection_method="response-diff",
                    rationale=("An identical repeated call produced a later response "
                               "that introduced injection mechanism(s) "
                               f"{sorted(new_mech)} absent from the first — a runtime "
                               "behavior flip (rug-pull)."),
                    evidence={"tool": tool, "new_mechanisms": sorted(new_mech),
                              "first_excerpt": first.response_text[:200],
                              "later_excerpt": later.response_text[:200]},
                    source_kind="dynamic-runtime", tool_name=tool,
                ))
                break
            elif (drift := _drift_instruction(ctx, tool, first, later)) is not None:
                # v6-W2 -- the response drifted AND the drifted text speaks
                # to the agent. Escalate from the "state-dependent behavior"
                # note to prompt-injection; the drift itself (and any source
                # gate that explains it) stays attached as corroboration.
                gates = _source_gates(ctx, tool)
                out.append(mk(
                    ctx, detector_id="rugpull-runtime", category="prompt-injection",
                    evidence_location="multi-call-state", severity="high",
                    confidence="medium", detection_method="response-diff-instruction",
                    rationale=("An identical repeated call returned a DIFFERENT "
                               "response, and the text the drift introduced carries "
                               "agent-directed instruction(s) "
                               f"({sorted(drift['shift']['signals']) or sorted(drift['families']) or 'planning directive'})"
                               " -- state drift used to deliver an injection the "
                               "first response did not contain."
                               + (f" The tool's source gates behavior on {gates}, "
                                  "which explains the flip." if gates else "")),
                    evidence={"tool": tool, "drift": True,
                              "introduced_text": drift["delta"],
                              "shift_signals": drift["shift"]["signals"],
                              "families": drift["families"],
                              "planning_directives": drift["planning_directives"],
                              "source_gates": gates,
                              "first_excerpt": first.response_text[:200],
                              "later_excerpt": later.response_text[:200]},
                    source_kind="dynamic-runtime", tool_name=tool,
                    raw={"state_drift": True, "source_gate": bool(gates)},
                ))
                break
            elif new_secrets:
                out.append(mk(
                    ctx, detector_id="rugpull-runtime", category="data-exfiltration",
                    evidence_location="multi-call-state", severity="high",
                    confidence="high", detection_method="response-diff",
                    rationale=("An identical repeated call to the same tool with the "
                               "same arguments produced a later response containing a "
                               "new sensitive-labeled value absent from the first — "
                               "state generated by an intervening, unrelated call now "
                               "leaks through this tool's response (cross-call secret "
                               "leak of a server-generated, not caller-supplied, "
                               "secret)."),
                    evidence={"tool": tool, "new_values": sorted(new_secrets)[:5],
                              "first_excerpt": first.response_text[:200],
                              "later_excerpt": later.response_text[:200]},
                    source_kind="dynamic-runtime", tool_name=tool,
                ))
                break
            elif (declared_idempotent
                  and first.response_text.strip() != later.response_text.strip()):
                # rule 3.8 — keep numbers: an ordinary text diff that strips
                # volatile tokens (timestamps/uuids/*numbers*) would compare
                # a credits balance of 15 vs. 20 as equal and miss exactly
                # the violation idempotentHint=true promises cannot happen.
                out.append(mk(
                    ctx, detector_id="hint-violation", category="excessive-privilege",
                    evidence_location="multi-call-state", severity="high",
                    confidence="high", detection_method="idempotent-response-diff",
                    rationale=("Tool declares idempotentHint=true, but an identical "
                               "repeated call with the SAME arguments produced a "
                               "DIFFERENT response (compared with numbers kept, not "
                               "stripped) — repeating the call changes server-visible "
                               "state each time, contradicting the declared "
                               "idempotency."),
                    evidence={"tool": tool, "declared": {"idempotentHint": True},
                              "first_excerpt": first.response_text[:200],
                              "later_excerpt": later.response_text[:200]},
                    source_kind="dynamic-runtime", tool_name=tool,
                ))
                break
            elif _devolatile(first.response_text) != _devolatile(later.response_text):
                # structural divergence beyond volatile tokens — weak signal
                out.append(mk(
                    ctx, detector_id="rugpull-runtime", category="other",
                    evidence_location="multi-call-state", severity="low",
                    confidence="low", detection_method="response-diff",
                    rationale=("Identical repeated call returned structurally "
                               "different content (beyond timestamps/ids) — possible "
                               "state-dependent behavior; verify intent."),
                    evidence={"tool": tool,
                              "first_excerpt": first.response_text[:160],
                              "later_excerpt": later.response_text[:160]},
                    source_kind="dynamic-runtime", tool_name=tool,
                ))
                break
    return out


def _relist_finding(ctx, name, change, before_sig, after_sig, b=None, a=None) -> Finding:
    ev = {"change": change, "tool": name}
    if b is not None and a is not None:
        ev["description_before"] = (b.description or "")[:200]
        ev["description_after"] = (a.description or "")[:200]
    return mk(
        ctx, detector_id="rugpull-runtime", category="tool-poisoning",
        evidence_location="multi-call-state", severity="high", confidence="high",
        detection_method="tools-list-diff",
        rationale=("Declared tool metadata changed at runtime between two listings "
                   f"({change}) — a manifest that mutates after inspection is a "
                   "rug-pull / time-of-check-time-of-use mechanism."),
        evidence=ev, source_kind="dynamic-runtime", tool_name=name,
    )


register(Detector(
    id="rugpull-source", category="other", evidence_location="source",
    phase="listing", run=_run_source, requires={CAP_SOURCE},
    rationale=("Control flow that switches behavior based on call count, wall-clock "
               "time, or an external env toggle has the structural signature of a "
               "delayed behavior change; honest tools rarely branch on these."),
))

register(Detector(
    id="rugpull-runtime", category="tool-poisoning", evidence_location="multi-call-state",
    phase="multicall", run=_run_runtime, requires={CAP_DYNAMIC},
    rationale=("Re-listing and diffing declared metadata, and diffing responses of "
               "identical repeated calls, catches servers that pass inspection then "
               "change — invisible to any single-listing manifest scanner."),
))
