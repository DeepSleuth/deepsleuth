"""rule 5.3(b) / rule 5.6 — dangerous sinks reached by agent-influenced input.

Uses the intra-procedural taint engine (analysis.pyast): tool parameters are
tainted sources; taint flows through assignments / string building; sinks are
command execution, eval/exec, unsafe deserialization, file open/delete and network
calls. We report a finding only when a *tainted* value reaches the sink — a tool
that runs a fixed command or opens a constant path for its stated purpose is not
flagged. Category names the sink class (command-injection / path-traversal / ssrf /
command-injection for code-exec).
"""
from __future__ import annotations

import re
from typing import List

from ..context import ScanContext, ToolContract
from ..models import Finding
from .base import CAP_SOURCE, Detector, register
from ._util import mk

# sink kind -> (category, base severity, evidence detail)
SINK_MAP = {
    "command-exec": ("command-injection", "high"),
    "code-exec": ("command-injection", "high"),
    "deserialize": ("command-injection", "high"),
    "network": ("ssrf", "medium"),
    "file-write": ("path-traversal", "high"),
    "file-delete": ("path-traversal", "high"),
    "file-read": ("path-traversal", "medium"),
}

_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
# rule P3.4 — ``os.system``/``os.popen`` are unconditionally shell-interpreted
# (there is no non-shell mode to opt into), even though the AST-level
# ``shell`` flag on ``SinkRecord`` only tracks an explicit ``shell=True``
# keyword on a ``subprocess.*``-style call. Recognized here so the bare
# helper-passthrough case (``def _run(cmd): os.system(cmd)``) is counted as
# the shell sink it structurally is.
_ALWAYS_SHELL_CALLS = ("os.system", "os.popen")

# rule P3.7 / v3-1.1 — a tool whose OWN description openly declares the exact
# dangerous capability a sink reaches (running a command / fetching a URL
# the caller supplies) gets an ADDITIONAL, low-severity CAPABILITY note
# (detection_method="declared-capability") recording that the capability is
# declared. The declaration never discounts the taint finding itself: a
# description is the author's to write, so "I run caller-supplied commands"
# + interpolating them into a shell is still an injection at full grade
# (v3-1.1: the capability lane is ADDITIVE — it may change how the finding
# is categorised/annotated, never its severity or confidence).
_DECLARES_RUNS_COMMANDS_RE = re.compile(
    r"\b(run|runs|execute|executes|invoke|invokes)\b(?:\s+\w+){0,4}?\s+"
    r"\b(command|commands|shell|script|scripts)\b|"
    r"\barbitrary\s+(shell\s+)?command", re.IGNORECASE)
_DECLARES_FETCHES_URLS_RE = re.compile(
    r"\bfetch(es)?\b(?:\s+\w+){0,4}?\s+\b(url|urls|uri|page|webpage|website)\b|"
    r"\b(makes?|sends?)\b(?:\s+\w+){0,4}?\s+\b(http|https|request|requests)\b.{0,20}"
    r"\b(url|endpoint|caller|supplied|given|provided)\b|"
    r"\b(downloads?)\b(?:\s+\w+){0,4}?\s+\b(url|file|from\s+a\s+url)\b",
    re.IGNORECASE)


def _declares_sink_capability(desc: str, sink_kind: str) -> bool:
    if sink_kind in ("command-exec", "code-exec"):
        return bool(_DECLARES_RUNS_COMMANDS_RE.search(desc or ""))
    if sink_kind == "network":
        return bool(_DECLARES_FETCHES_URLS_RE.search(desc or ""))
    return False


def _run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    for c in ctx.all_contracts():
        if not c.source:
            continue
        facts = c.source.facts
        for sink in facts.sinks:
            if not sink.tainted:
                continue
            if sink.kind not in SINK_MAP:
                continue
            category, sev = SINK_MAP[sink.kind]
            # rule P3.4 — a sink reached only through one level of helper
            # inlining is a weaker, more heuristic signal than one directly
            # in the tool's own body — UNLESS the helper is a bare
            # passthrough wrapper that hands the tainted value straight into
            # a shell/eval sink with no transformation of its own
            # (``def _run(cmd): os.system(cmd)``): that shape adds no
            # defense at all, so it stays at full severity exactly like a
            # direct sink.
            always_shell = sink.call.endswith(_ALWAYS_SHELL_CALLS)
            is_shell_or_eval = sink.kind == "code-exec" or (
                sink.kind == "command-exec" and (sink.shell or always_shell))
            full_severity_helper = sink.via_helper and is_shell_or_eval and sink.via_helper_passthrough
            # shell=True (or an unconditionally-shell call like os.system)
            # with tainted arg is the sharpest command-injection shape.
            if sink.kind == "command-exec" and (sink.shell or always_shell) and (
                    not sink.via_helper or full_severity_helper):
                sev = "critical"
            # a sink reached only through inlining into a local helper is never
            # "direct" evidence, regardless of whether the tainted parameter
            # itself was passed straight through at the call site.
            direct = (bool(set(sink.tainted_params) & set(c.source.tool_def.params))
                      and not sink.via_helper)
            conf = "high" if direct else "medium"
            rationale = (f"Tool parameter flows unsanitized into a {sink.kind} sink "
                         f"({sink.call}) — agent-controlled input reaching this sink "
                         f"enables {category}.")
            # rule 2.6 (FP fix) — one level of call inlining is a weaker, more
            # heuristic signal than taint reaching a sink directly in the
            # tool's own body: the inlining itself is a one-level, approximate
            # static heuristic. Cap severity at medium so a helper-reached
            # sink is reported (never silently dropped) but never outranks —
            # or is graded identically to — a direct, hidden injection.
            # rule P3.4 — except the bare-passthrough shell/eval case above,
            # which stays uncapped.
            if sink.via_helper and not full_severity_helper and _SEV_RANK[sev] > _SEV_RANK["medium"]:
                sev = "medium"
            # rule P3.7 / v3-1.1 — an openly declared capability earns an
            # ADDITIONAL capability note; the taint finding below is still
            # emitted at its full grade (a declaration is the author's to
            # write and never discounts observed data flow).
            declared_capability = _declares_sink_capability(c.description or "", sink.kind)
            if declared_capability:
                out.append(mk(
                    ctx, detector_id="ast-taint", category="excessive-privilege",
                    evidence_location="source", severity="low", confidence="low",
                    detection_method="declared-capability",
                    rationale=(f"Tool's own description openly declares the "
                               f"capability this {sink.kind} sink reaches ({sink.call}) "
                               "— recorded as a declared-capability note alongside "
                               "the taint finding, which keeps its full grade: a "
                               "declared capability is still an injection when the "
                               "caller-supplied value reaches the sink unsanitized."),
                    evidence={"sink": sink.call, "sink_kind": sink.kind,
                              "line": sink.lineno, "code": sink.snippet,
                              "module": c.source.module_path},
                    source_kind="static-code", tool_name=c.name,
                    raw={"declared_capability": True},
                ))
            # rule 2.6 — a recognized sanitizer (basename/shlex.quote, or a
            # realpath/normpath/abspath normalization backed by a prefix/
            # allow-list guard elsewhere in the function) covers this
            # specific sink: the taint is real, but a verified defense
            # downgrades it instead of reporting a correctly-guarded path
            # identically to an unguarded one.
            if sink.sanitized:
                sev = "low"
                conf = "low"
                rationale += (" A sanitizer (path normalization backed by a prefix/"
                              "allow-list guard, or a stripping call such as "
                              "basename/shlex.quote) covers this value, so this is "
                              "reported at low confidence as a defense-in-depth note "
                              "rather than an exploitable path.")
            if sink.via_helper:
                rationale += (f" Reached through one level of inlining into the local "
                              f"helper function `{sink.via_helper}`, not directly in "
                              "the tool's own body — a weaker, more heuristic signal "
                              "than a direct sink, graded at most medium on its own.")
            if declared_capability:
                rationale += (" The tool's own description declares this capability; "
                              "the declaration is noted separately and does not "
                              "lower this grade (v3-1.1).")
            out.append(mk(
                ctx, detector_id="ast-taint", category=category,
                evidence_location="source", severity=sev, confidence=conf,
                detection_method="ast-taint",
                rationale=rationale,
                evidence={"sink": sink.call, "sink_kind": sink.kind,
                          "line": sink.lineno, "shell": sink.shell,
                          "tainted_params": sink.tainted_params,
                          "code": sink.snippet, "sanitized": sink.sanitized,
                          "via_helper": sink.via_helper or None,
                          "declared_capability": declared_capability,
                          "module": c.source.module_path},
                source_kind="static-code", tool_name=c.name,
                # v4-8 — ``raw.declared_capability`` tags the finding for
                # the the gate/startup policy (``allow_declared_capabilities``);
                # severity and confidence are unchanged.
                raw={"source_to_sink": True,
                     "declared_capability": bool(declared_capability)},
            ))
    return out


register(Detector(
    id="ast-taint",
    category="command-injection",
    evidence_location="source",
    phase="tool listing",
    run=_run,
    requires={CAP_SOURCE},
    rationale=(
        "Manifest-only scanners never read the implementation. Tracking tool "
        "parameters (tainted sources) to command/eval/file/network/deserialization "
        "sinks reveals injection classes that are structurally invisible in the "
        "declared manifest. Gated on taint reaching the sink to avoid flagging "
        "legitimate fixed-argument execution."
    ),
))
