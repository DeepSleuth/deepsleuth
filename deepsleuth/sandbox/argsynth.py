"""Deterministic argument synthesis + canary machinery (rule 4.3).

For each tool we build valid arguments from its ``inputSchema`` — respecting
types, ``required`` and ``enum`` — and plant recognizable, inert **canaries** in
free-form strings. Because we know exactly what we planted, later responses can be
scanned deterministically for leakage/over-sharing. Nothing here is random: the
same schema always yields the same arguments (hard constraint rule 3.3).

Also defines the decoy-file layout the sandbox seeds at sensitive paths, and a
helper to flatten an MCP tool-call result into scannable text.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

from ..analysis.pyast import is_secret_hint_name, _split_ident_tokens
from ..context import CANARIES

CANARY_URL_HOST = "canary.invalid"

# decoy files seeded into the sandbox (label -> (container path, content w/ marker))
def decoy_files() -> Dict[str, Tuple[str, str]]:
    out: Dict[str, Tuple[str, str]] = {}
    specs = [
        ("ssh_key", "/home/canary/.ssh/id_rsa",
         "-----BEGIN OPENSSH PRIVATE KEY-----\n{m}\n-----END OPENSSH PRIVATE KEY-----\n"),
        ("env", "/home/canary/.env", "SECRET_TOKEN={m}\nDB_PASSWORD={m}\n"),
        ("aws", "/home/canary/.aws/credentials",
         "[default]\naws_secret_access_key = {m}\n"),
        ("netrc", "/home/canary/.netrc", "machine example.com password {m}\n"),
        ("npmrc", "/home/canary/.npmrc", "//registry.npmjs.org/:_authToken={m}\n"),
    ]
    for label, path, tmpl in specs:
        marker = CANARIES.file_marker(label)
        out[label] = (path, tmpl.format(m=marker))
    return out


def decoy_markers() -> Dict[str, str]:
    """marker value -> label, for the cross-call state tracker."""
    return {CANARIES.file_marker(label): label for label in
            ("ssh_key", "env", "aws", "netrc", "npmrc")}


# --- argument synthesis -------------------------------------------------------

_PATH_HINT = ("path", "file", "dir", "filename", "filepath", "location", "target")
_URL_HINT = ("url", "uri", "endpoint", "host", "link", "webhook", "callback")
# rule P0.7: whole-token secret-name matching now lives in
# analysis.pyast.is_secret_hint_name (shared with gate_precall) — this tuple
# is no longer used for a bare substring check, kept only for backward
# reference to the old shape.
_SECRET_HINT = ("secret", "password", "token", "apikey", "api_key", "key",
                "credential", "auth")
# Identity-shaped parameters (an account/session/user handle) that different
# tools on the SAME server commonly share to refer to the *same* conceptual
# entity (e.g. ``register_api_key(user_id, ...)`` and
# ``get_activity(user_id)`` both take a "user_id" naming the same account).
# Cross-call multi-call-state mechanisms (rule 5.5: a secret registered against
# an identity surfacing through a different tool queried with that SAME
# identity; rule 5.9/BOLA: a session id minted by one tool and looked up by
# another) only ever manifest when the two calls actually correlate — i.e.
# use the SAME synthesized value for "the same identity" regardless of which
# tool is being called. Scoping the canary by (tool, param) as every OTHER
# parameter is scoped breaks that correlation by construction: two calls to
# two different tools that both accept "user_id" would silently receive two
# DIFFERENT synthesized values, so any server-side state keyed by that
# identity could never be found again by a later call. Scoping by parameter
# NAME alone (ignoring which tool) is what actually exercises this whole
# mechanism class.
_IDENTITY_RE = re.compile(
    r"^(user|account|session|customer|owner|client)[_-]?(id|name)?$|"
    r"^(username|user_name|email)$", re.IGNORECASE)


def _string_value(tool: str, key: str, spec: Dict[str, Any], idx: int) -> str:
    enum = spec.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0] if isinstance(enum[0], str) else str(enum[0])
    fmt = str(spec.get("format", "")).lower()
    lk = key.lower()
    if fmt in ("uri", "url") or any(h in lk for h in _URL_HINT):
        # canary URL so SSRF/exfil attempts hit a recognizable, dead host
        return f"http://{CANARY_URL_HOST}/{CANARIES.arg(tool, key, idx)}"
    if any(h in lk for h in _PATH_HINT):
        # point at a decoy secret file so a traversal/read is observable
        return "/home/canary/.env"
    if is_secret_hint_name(key):
        return CANARIES.secret("token", tool, key)
    if _IDENTITY_RE.match(key):
        # tool-independent: every tool that names this same identity param
        # gets the SAME synthesized value, so state a server keys by it
        # correlates across calls instead of silently missing every time.
        return CANARIES.arg("<identity>", key, 0)
    return CANARIES.arg(tool, key, idx)


def synthesize(tool_name: str, schema: Dict[str, Any], _depth: int = 0) -> Dict[str, Any]:
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties")
    if not isinstance(props, dict):
        return {}
    required = set(schema.get("required") or [])
    args: Dict[str, Any] = {}
    idx = 0
    for key, spec in props.items():
        if _depth > 3:
            break
        # include required + a bounded number of optionals to exercise behavior
        if key not in required and len(args) >= max(len(required), 4):
            continue
        args[key] = _value_for(tool_name, key, spec if isinstance(spec, dict) else {},
                               idx, _depth)
        idx += 1
    return args


def _value_for(tool: str, key: str, spec: Dict[str, Any], idx: int, depth: int) -> Any:
    t = spec.get("type")
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), "string")
    if "enum" in spec and isinstance(spec["enum"], list) and spec["enum"]:
        return spec["enum"][0]
    if t == "string" or t is None and "properties" not in spec:
        return _string_value(tool, key, spec, idx)
    if t in ("integer", "number"):
        mn = spec.get("minimum")
        return mn if isinstance(mn, (int, float)) else 1
    if t == "boolean":
        return False
    if t == "array":
        items = spec.get("items") or {"type": "string"}
        return [_value_for(tool, key, items if isinstance(items, dict) else {}, 0, depth + 1)]
    if t == "object" or "properties" in spec:
        return synthesize(tool, spec, depth + 1)
    return _string_value(tool, key, spec, idx)


# --- response flattening ------------------------------------------------------

def flatten_result(result_msg: Dict[str, Any]) -> Tuple[str, bool, Any]:
    """Return (scannable_text, is_error, raw_result)."""
    if not isinstance(result_msg, dict):
        return "", False, result_msg
    if result_msg.get("_timeout"):
        return "", True, result_msg
    err = result_msg.get("error")
    if err is not None:
        return json.dumps(err, default=str), True, result_msg
    result = result_msg.get("result", result_msg)
    parts: List[str] = []
    is_error = bool(isinstance(result, dict) and result.get("isError"))
    if isinstance(result, dict):
        content = result.get("content")
        if isinstance(content, list):
            for c in content:
                if isinstance(c, dict):
                    if isinstance(c.get("text"), str):
                        parts.append(c["text"])
                    elif c.get("type") == "resource" and isinstance(c.get("resource"), dict):
                        parts.append(json.dumps(c["resource"], default=str))
                    else:
                        parts.append(json.dumps(c, default=str))
        # rule 3.4 — ``resources/read``'s ``contents`` and ``prompts/get``'s
        # ``messages`` are shaped differently from ``tools/call``'s
        # ``content``; flattened the same way so the response rules can
        # scan a resource/prompt result exactly like a tool result.
        contents = result.get("contents")
        if isinstance(contents, list):
            for c in contents:
                if isinstance(c, dict) and isinstance(c.get("text"), str):
                    parts.append(c["text"])
                elif isinstance(c, dict):
                    parts.append(json.dumps(c, default=str))
        messages = result.get("messages")
        if isinstance(messages, list):
            for m in messages:
                if not isinstance(m, dict):
                    continue
                mc = m.get("content")
                if isinstance(mc, str):
                    parts.append(mc)
                elif isinstance(mc, dict) and isinstance(mc.get("text"), str):
                    parts.append(mc["text"])
                elif isinstance(mc, list):
                    for cc in mc:
                        if isinstance(cc, dict) and isinstance(cc.get("text"), str):
                            parts.append(cc["text"])
        if "structuredContent" in result:
            parts.append(json.dumps(result["structuredContent"], default=str))
        if not parts:
            parts.append(json.dumps(result, default=str))
    else:
        parts.append(json.dumps(result, default=str))
    return "\n".join(parts), is_error, result


# rule P3.1/v3-4.2 — call ORDER is derived from each tool's observed BEHAVIOR
# (``BehaviorFacts`` computed from its source), never from its name:
#   * MUTATORS (source mutates module state / writes or deletes files /
#     accumulates) run first, so the state they create is in place when the
#     readers run and a cross-call leak has something to surface;
#   * READERS (no mutation) run next;
#   * RESETTERS (``BehaviorFacts.resets_state``: assigns zero/empty/None to a
#     module global, ``.clear()``s one, or rewrites a state file) run LAST in
#     every phase, so a call-counter-gated rug pull in another tool is never
#     silently re-armed by an intervening reset between two of its own burst
#     calls.
# A tool with no source facts at all (live tool listing only) is treated as a
# reader; nothing about its name is consulted.
_BEHAVIOR_RANK = {"mutator": 0, "reader": 1, "reset": 2}


def _facts_for(name: str, source_facts: Any):
    if source_facts is None or not hasattr(source_facts, "get"):
        return None
    sf = source_facts.get(name)
    return getattr(sf, "facts", None) if sf is not None else None


def _behavior_class(name: str, source_facts: Any) -> str:
    f = _facts_for(name, source_facts)
    if f is None:
        return "reader"
    if getattr(f, "resets_state", False):
        return "reset"
    if (getattr(f, "mutates_module_state", False) or getattr(f, "writes_fs", False)
            or getattr(f, "deletes", False) or getattr(f, "accumulates_state", False)):
        return "mutator"
    return "reader"


def _ordered_tools(tools: List[Dict[str, Any]], source_facts: Any = None) -> List[Dict[str, Any]]:
    named = [t for t in tools if t.get("name")]
    return sorted(named, key=lambda t: (_BEHAVIOR_RANK[_behavior_class(t["name"], source_facts)],
                                        t["name"]))


def _extra_variant_calls(tools: List[Dict[str, Any]], source_facts: Any = None,
                         cap_per_tool: int = 3) -> List[Tuple[str, Dict[str, Any]]]:
    """rules 3.2/3.3 — a small, CAPPED set of extra calls per tool beyond the
    canary-only base plan, so branches a fixed canary can never reach get
    exercised too:

    * rule 3.2 harvested candidate values — a string literal the tool's own
      source compares a parameter against, or uses as a dict-lookup key
      (``ScanContext._source_facts[name].facts.candidate_values``, built by
      ``analysis.pyast._harvest_candidate_values``). Overrides just that one
      parameter's synthesized value with each harvested candidate in turn.
    * rule 3.3 every remaining schema ``enum`` value (the base ``synthesize()``
      pass already tries the first), and relative/``../`` path-traversal
      variants for path-hinted string parameters.

    Deterministic and capped: at most ``cap_per_tool`` extra calls per tool,
    so a large enum/candidate set cannot blow up the call plan."""
    out: List[Tuple[str, Dict[str, Any]]] = []
    for t in tools:
        name = t.get("name")
        if not name:
            continue
        schema = t.get("inputSchema") or t.get("input_schema") or {}
        props = schema.get("properties") if isinstance(schema, dict) else None
        if not isinstance(props, dict):
            continue
        base_args = synthesize(name, schema)
        variants: List[Dict[str, Any]] = []

        # rule 3.2 — harvested candidate values, one extra call per candidate
        facts = None
        if source_facts is not None:
            sf = source_facts.get(name)
            facts = getattr(sf, "facts", None) if sf is not None else None
        candidate_values = getattr(facts, "candidate_values", None) or {}
        for key, values in candidate_values.items():
            if key not in props:
                continue
            for v in values[:2]:  # cap per parameter too
                args = dict(base_args)
                args[key] = v
                variants.append(args)

        # rule 3.3 — every remaining enum value + relative/../ path variants
        for key, spec in props.items():
            if not isinstance(spec, dict):
                continue
            enum = spec.get("enum")
            if isinstance(enum, list) and len(enum) > 1:
                for v in enum[1:3]:  # first value already used by the base pass
                    args = dict(base_args)
                    args[key] = v
                    variants.append(args)
            lk = key.lower()
            fmt = str(spec.get("format", "")).lower()
            if spec.get("type") in (None, "string") and (
                    fmt in ("uri", "url") or any(h in lk for h in _PATH_HINT)):
                for pv in ("../../../home/canary/.env", "reports/../../home/canary/.env"):
                    args = dict(base_args)
                    args[key] = pv
                    variants.append(args)

        for args in variants[:cap_per_tool]:
            out.append((name, args))
    return out


def build_call_plan(tools: List[Dict[str, Any]], passes: int = 2, burst: int = 3,
                    source_facts: Any = None,
                    ) -> List[Tuple[str, Dict[str, Any]]]:
    """Deterministic call plan (rule P3.1/v3-4.2), ordered by BEHAVIOR
    (``_ordered_tools``: mutators, then readers, then resetters — from each
    tool's ``BehaviorFacts``, never its name):

    1. A BURST phase first: every tool is called ``burst`` times *in a row*
       (resetters last), so a call-counter-gated rug pull (``if _calls >=
       3: ...``) actually trips within one tool's own burst — the shallow
       2-pass round-robin alone calls each tool only once per pass,
       interleaved with every OTHER tool's calls, so a counter the gate at 3+
       calls, or one an intervening reset call re-arms between passes,
       could never fire.
    2. Then the round-robin passes (default 2), same ordering, which is what
       lets a canary planted in tool A's argument surface in tool B's
       response (cross-call leakage) and lets an identical repeated call
       across passes reveal response drift (rug-pull) —
       ``detectors.rugpull._run_runtime`` groups ALL calls (burst + passes)
       to the same tool with identical (fully deterministic, so pass-to-pass
       identical) arguments and diffs first-vs-later.
    3. v3-4.2 — the burst is REPEATED once after the round-robin passes, so
       a counter gate armed only by the interleaved calls still trips.

    0. v3-4.2 — before any of that, a one-call BASELINE pass over every
       READER (never a resetter): a value a mutator creates and a reader
       later surfaces (a reset code, a minted token) is only observable as
       first-vs-later drift of the reader's own identical call
       (``rugpull-runtime``'s labelled-secret diff) if the reader was seen
       once BEFORE the mutators ran. Mutators-first alone would erase that
       baseline, so it is taken explicitly, from behavior, not by the
       accident of alphabetical order.

    Resetters are ordered last in EVERY phase (each burst and each
    round-robin pass) and never take part in the baseline, so a reset never
    runs between two burst calls of another tool."""
    plan: List[Tuple[str, Dict[str, Any]]] = []
    ordered = _ordered_tools(tools, source_facts)

    def _call(t: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        name = t["name"]
        schema = t.get("inputSchema") or t.get("input_schema") or {}
        return name, synthesize(name, schema)

    # 0. baseline observation of every reader before any mutator runs
    for t in ordered:
        if _behavior_class(t["name"], source_facts) == "reader":
            plan.append(_call(t))
    for t in ordered:
        for _ in range(max(0, burst)):
            plan.append(_call(t))
    for _ in range(passes):
        for t in ordered:
            plan.append(_call(t))
    # v3-4.2 — repeat the burst once after the round-robin passes.
    for t in ordered:
        for _ in range(max(0, burst)):
            plan.append(_call(t))
    # rules 3.2/3.3 — a small capped tail of extra calls per tool trying
    # source-harvested candidate values, every remaining enum value, and
    # relative/../ path-traversal variants. Appended after the burst+pass
    # phases (which rugpull-runtime's response-diff already groups by exact
    # arguments) so it never disturbs their identical-repeat pairing.
    plan.extend(_extra_variant_calls(ordered, source_facts))
    # v6 — gate-aware depth: a tool whose merged source facts (own body or
    # any helper module hop) carry a call-counter threshold gets identical
    # calls scheduled PAST that threshold. Appended last, so the burst/pass
    # identical-repeat pairing rugpull-runtime groups on is untouched, and a
    # tool with no detected gate keeps exactly the plan above.
    plan.extend(_gate_depth_calls(ordered, source_facts, plan, _call))
    return plan


GATE_DEPTH_MARGIN = 3     # calls scheduled beyond the gate's threshold
GATE_DEPTH_CAP = 24       # max identical calls per gated tool


def _gate_threshold(name: str, source_facts: Any) -> int:
    """Largest reachable call-counter threshold (<= GATE_DEPTH_CAP - 1) in a
    tool's merged facts, or 0 when it has none."""
    f = _facts_for(name, source_facts)
    thrs = [t for t in (getattr(f, "counter_gate_thresholds", None) or [])
            if isinstance(t, int) and 1 <= t <= GATE_DEPTH_CAP - 1]
    return max(thrs) if thrs else 0


def _gate_depth_calls(ordered: List[Dict[str, Any]], source_facts: Any,
                      plan: List[Tuple[str, Dict[str, Any]]], make_call
                      ) -> List[Tuple[str, Dict[str, Any]]]:
    if source_facts is None:
        return []
    has_resetter = any(_behavior_class(t["name"], source_facts) == "reset" for t in ordered)
    out: List[Tuple[str, Dict[str, Any]]] = []
    for t in ordered:
        thr = _gate_threshold(t["name"], source_facts)
        if not thr:
            continue
        name, args = make_call(t)
        target = min(GATE_DEPTH_CAP, thr + GATE_DEPTH_MARGIN)
        have = sum(1 for n, a in plan if n == name and a == args)
        # a resetter earlier in the plan may have zeroed the counter after
        # the last burst, so the tail must clear the threshold on its own
        extra = target if has_resetter else max(0, target - have)
        out.extend((name, dict(args)) for _ in range(extra))
    return out
