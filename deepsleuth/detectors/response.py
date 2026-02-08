"""rule 5.3(a) + rule 5.5 — runtime-response detectors.

* response-injection: apply the normalized rule 5.1 mechanism rules to every tool
  *response* (not just the static tool description), with a stricter response-specific
  grading bar (rules P1.3/P2.1): fire only when the response (a) is agent-directed,
  (b) steers a hidden or next-step action (exfiltrate/redirect/override/conceal/
  contact an external destination) and (c) is out of scope for the tool's job —
  independent of the framing device (a footer/note/tip/pseudo-system tag) used to
  introduce it. Plain helpful prose, or instructions the user asked for, must not
  trip it.
* response-leak: cross-call canary leakage (a value planted in call A surfacing in
  the response of call B, or decoy-file content surfacing), credential exposure
  (secret-shaped keys/values beyond the tool's described scope), and (rule P2.2)
  over-sharing vs. declared scope — the response's *shape/volume* (extra record
  lists, adjacent-entity fields) materially exceeding what the description
  promises, independent of whether any individual value looks like a secret.
"""
from __future__ import annotations

import json
import re
from typing import Any, List, Tuple

from typing import Callable, Optional

from ..analysis.pyast import _split_ident_tokens
from ..analysis.textrules import RuleResult, _clauses, analyze_text
from ..context import CrossCallState, ScanContext
from ..context import CANARIES
from ..models import Finding
from ..normalize import normalize
from .base import CAP_DYNAMIC, Detector, register
from ._util import mk

# secret-shaped keys and values (for over-sharing / credential exposure).
# Two alternatives: the original JSON-quoted-key shape, and a bare
# "label: value" / "label=value" shape (no quotes) — the overwhelmingly
# common form for a plain-text/formatted tool response (e.g.
# "password_hash=5f4dcc..."), which the quote-only version silently missed
# entirely (a response that happens not to be JSON was invisible to this
# detector no matter how blatant the leaked field).
SECRET_KEY_RE = re.compile(
    r'"([^"]*(?:password|passwd|secret|api[_-]?key|access[_-]?key|token|'
    r'private[_-]?key|client[_-]?secret|credential|ssh[_-]?key|session[_-]?id)[^"]*)"'
    r'\s*:\s*"?([^",\n}]*)"?|'
    # V5-2: the prefix before the sensitive word must be OPTIONAL
    # (``[\w-]*``, zero-or-more) not ``[a-zA-Z][\w-]*`` (one-or-more) — a
    # required leading character consumes the sensitive word's own first
    # letter whenever the label starts directly with it (e.g.
    # "password_hash=...", "token=...", the overwhelmingly common real
    # case), leaving nothing for the alternation to match and silently
    # defeating the whole bare-label branch on exactly the labels it exists
    # to catch.
    r'\b([\w-]*(?:password|passwd|secret|api[_-]?key|access[_-]?key|token|'
    r'private[_-]?key|client[_-]?secret|credential|ssh[_-]?key|session[_-]?id)[\w-]*)\s*[:=]\s*'
    r'"?([^\s,;"\n]*)"?',
    re.IGNORECASE)
# rule P0.8: keys that merely CONTAIN "token" but are pagination/usage-shaped
# ("nextPageToken", "total_tokens", "max_tokens", "token_type", ...) are an
# extremely common, entirely honest API response shape with no relationship
# to a credential.
_TOKEN_USAGE_KEY_RE = re.compile(
    r"(page|next|prev|cursor|continuation|total|max|min|count|num|usage|"
    r"input|output|prompt|completion|type|limit)[\w-]*token|"
    r"token[\w-]*(page|count|type|usage|limit|id)\b",
    re.IGNORECASE)
_STRONG_SECRET_KEY_WORD_RE = re.compile(
    r"password|passwd|secret|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|credential|ssh[_-]?key|session[_-]?id",
    re.IGNORECASE)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from math import log2
    counts: dict = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in counts.values())


def _secret_shaped_value(value: str) -> bool:
    v = (value or "").strip().strip('"').strip("'")
    if len(v) < 12 or re.search(r"\s", v):
        return False
    if SECRET_VALUE_RE.search(v):
        return True
    return _shannon_entropy(v) > 3.3


def find_secret_key_hits(text: str) -> List[str]:
    """rule P0.8: extract secret-shaped keys from a response, excluding
    pagination/usage-shaped "token" keys outright, and — for a key whose ONLY
    sensitive word is the bare, generic "token" (no password/secret/
    credential/api-key/... qualifier) — requiring the paired value to itself
    look secret-shaped (long, high-entropy, no whitespace) before counting
    it. A bare "token" key with an ordinary short/low-entropy value
    (``token_type: "Bearer"``, an opaque short id) is not evidence of a
    leaked credential."""
    hits: List[str] = []
    for m in SECRET_KEY_RE.finditer(text):
        key = m.group(1) or m.group(3) or ""
        value = m.group(2) or m.group(4) or ""
        if not key:
            continue
        if _TOKEN_USAGE_KEY_RE.search(key):
            continue
        if not _STRONG_SECRET_KEY_WORD_RE.search(key):
            if not _secret_shaped_value(value):
                continue
        hits.append(key)
    return hits


SECRET_VALUE_RE = re.compile(
    r'(-----begin (?:rsa |ec |openssh )?private key-----|'
    r'AKIA[0-9A-Z]{16}|'
    r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|'  # jwt
    r'gh[pousr]_[A-Za-z0-9]{20,}|'                                     # github token
    r'xox[baprs]-[A-Za-z0-9-]{10,})', re.IGNORECASE)


def _strip_canaries(text: str) -> str:
    # remove our own inert canaries so we never flag them as real secrets
    return re.sub(r'MCPSCANCANARY[\w!/-]*|AKIAMCPSCANCANARY[0-9A-F]*|sk-mcpscancanary-\w+', '', text or '')


# ---- response injection ------------------------------------------------------

# rules P1.3/P2.1: raise the bar for RESPONSE text specifically (vs. the description
# grading in poisoning._grade). A response is legitimate, often second-person,
# helpful prose by default — it must not trip on a lone imperative or a weak
# multi-family combination. We only fire on:
#  (a) a DECISIVE family — override_instructions / concealment / exfiltration —
#      each of which, by construction, names a hidden-or-next-step action
#      (ignore prior guidance, hide something from the user, contact an external
#      destination) that a response has no legitimate reason to carry regardless
#      of what the tool was asked to do; or
#  (b) a strong multi-family combination (score >= 6 across >= 2 distinct
#      families) — still requires more than a single soft signal.
# This deliberately drops the description-grading engine's weaker single-family
# "total >= 3/4" tiers for responses, which is what let helpful prose (a lone
# agent_directive or preference_manipulation match) trip the old detector.
_DECISIVE = {"override_instructions", "concealment", "exfiltration",
             "next_action_redirect"}
_FAMILY_ORDER = ["override_instructions", "exfiltration", "next_action_redirect",
                 "concealment", "read_sensitive", "preference_manipulation",
                 "agent_directive", "sensitive_reference"]


def _primary_family(fams) -> str:
    for f in _FAMILY_ORDER:
        if f in fams:
            return f
    return next(iter(fams), "")


# rules 3.9/P2.1 — tools whose job is to RETRIEVE third-party content (fetch a
# URL, read a file/email, search an index, ...) are structurally different
# from a tool that only ever returns content the SERVER ITSELF authored:
# their response text is not the server's own words, so an instruction-like
# sentence inside it is exactly as likely to be a quoted excerpt of
# retrieved content (a README, an email body, API documentation) as it is to
# be a genuine attack. Flagged at all-purpose "high/high, blocked by
# default" severity, this makes every honest fetch/read/search tool
# unusable the moment it touches content that happens to use imperative
# language — the reported false-positive probe. The fix is not to stop
# looking, but to change the DEFAULT stance from block to annotate — unless
# the text does what a retrieval tool's own honest content essentially never
# does: address the agent directly with a specific tool call to make
# (``next_action_redirect``) or ask for something to be hidden from the user
# (``concealment``). Those two stay full-severity everywhere.
#
# rule P2.1 — the decision that a tool is "retrieval-shaped" must come from
# BEHAVIOR, never from a name/description string the server itself chooses
# (a malicious tool can trivially name itself ``fetch_notes`` to buy the
# discount for a hard-coded, self-authored redirect that never touches a
# network or file source at all — the exact evasion this closes). Two
# behavioral signals, either one sufficient:
#  (a) static — v3-1.2: the tool's OWN source RETURNS content derived from
#      a network call / file read (``BehaviorFacts.returns_external_content``:
#      data flow from the read call's result to the return, not the mere
#      presence of a read somewhere in the body — a tool that fetches a URL
#      for telemetry and returns a constant string is returning self-
#      authored content whatever else it called); or
#  (b) dynamic — replayed calls to the SAME tool with a different
#      URL/path/host-shaped argument produced a DIFFERENT response, AND
#      (v3-1.2) the specific injected clause is ABSENT from at least one of
#      those replays — proving the instruction tracks the external source
#      rather than being a fixed suffix the server appends to every answer.
_RETRIEVAL_ALWAYS_BLOCK = {"next_action_redirect", "concealment"}
_VARYING_ARG_NAME_TOKENS = frozenset({
    "url", "uri", "link", "host", "path", "file", "filepath", "filename",
    "endpoint", "address", "site", "page", "resource", "domain",
})


def _replay_calls_varying_input(ctx: Optional[ScanContext], tool_name: str) -> list:
    """rule P2.1(b) — the replayed calls to ``tool_name`` when >=2 of them
    supplied a different value for the SAME url/path-shaped argument and got
    back a different response; ``[]`` when no such variance exists."""
    if ctx is None:
        return []
    calls = [c for c in ctx.calls if c.tool_name == tool_name and isinstance(c.arguments, dict)]
    if len(calls) < 2:
        return []
    common_keys = set.intersection(*(set(c.arguments.keys()) for c in calls))
    for key in common_keys:
        if not (set(_split_ident_tokens(key)) & _VARYING_ARG_NAME_TOKENS):
            continue
        values = {str(c.arguments.get(key)) for c in calls}
        if len(values) < 2:
            continue
        texts = {c.response_text or "" for c in calls}
        if len(texts) > 1:
            return calls
    return []


def _dynamic_response_varies_with_input(ctx: Optional[ScanContext], tool_name: str,
                                        injected_present: Optional[Callable[[str], bool]] = None,
                                        ) -> bool:
    """rule P2.1(b)/v3-1.2 — True when replayed calls with a different url/
    path-shaped argument came back different (behavior proving the output
    tracks an external source) AND, when ``injected_present`` is given, the
    injected clause is ABSENT from at least one of those replays. A clause
    that is present in every replay regardless of which URL/path was
    supplied is the server's own fixed text, not retrieved content."""
    calls = _replay_calls_varying_input(ctx, tool_name)
    if not calls:
        return False
    if injected_present is None:
        return True
    return any(not injected_present(c.response_text or "") for c in calls)


def _injected_clause_probe(text: str, primary_family: str) -> Optional[Callable[[str], bool]]:
    """v3-1.2 — build a probe answering "does THIS other response contain
    the same injected clause(s)?" for the clause(s) of ``text`` on which
    ``primary_family`` fires on their own. Compared on the normalized
    (folded, whitespace-collapsed) form so punctuation/case noise around
    the clause does not matter. ``None`` when no single clause isolates the
    family (the probe then cannot discriminate and no discount is earned)."""
    clauses = []
    for clause in _clauses(text):
        try:
            if primary_family in analyze_text(clause).families:
                clauses.append(normalize(clause).normalized)
        except Exception:
            continue
    clauses = [c for c in clauses if c]
    if not clauses:
        return None

    def present(other: str) -> bool:
        norm_other = normalize(other or "").normalized
        return any(c in norm_other for c in clauses)
    return present


def _clause_probe(clause: str) -> Callable[[str], bool]:
    """v3-1.2 — probe for one specific clause (response-redirect)."""
    needle = normalize(clause or "").normalized

    def present(other: str) -> bool:
        return bool(needle) and needle in normalize(other or "").normalized
    return present


def _is_retrieval_tool(contract, ctx: Optional[ScanContext] = None,
                       injected_present: Optional[Callable[[str], bool]] = None) -> bool:
    if contract is None:
        return False
    facts = contract.source.facts if contract.source else None
    # v3-1.2 — data flow, not presence: the return must derive from the read.
    if facts is not None and getattr(facts, "returns_external_content", False):
        return True
    if ctx is not None and _dynamic_response_varies_with_input(
            ctx, contract.name, injected_present):
        return True
    return False


# v4-1 — audit-echo by ATTRIBUTION, not by description. A plain-argument
# (non-secret-kind) canary that resurfaces INSIDE A RECORD THAT ALSO NAMES
# THE PLANTING TOOL — the planting tool's identifier, or a verb token of its
# own name, in the same line / JSON record as the echoed value — is an
# attributed audit entry ("create_ticket(note=...)", ``{"tool": "create_
# ticket", "args": {...}}``, "Created ticket with note ..."): that is the
# shape of an honest log, whatever either tool's description says, graded
# low/medium with a warning. A BARE echoed value with no attribution in its
# record ("(debug: last input was ...)") is a leak at high/high. An
# underscore-named or "internal"-described surfacing tool is never
# downgraded — a hidden surface echoing another tool's argument is a covert
# side-channel however well it labels its entries. The previous
# description-declaration requirement (the surfacing tool had to SAY it is
# a log, the planting tool had to SAY it records input) is gone: both were
# words the server author writes freely.
_INTERNAL_TOOL_RE = re.compile(
    r"\b(internal|private|hidden|debug|admin[- ]only|not\s+(documented|for\s+"
    r"(end\s+)?users))\b", re.IGNORECASE)

# closed, generic action-verb vocabulary: the token of a planting tool's name
# that names the ACTION a log entry attributes the value to. A name token
# outside it (``note`` in ``set_note``) is a noun and never attributes.
_ATTRIBUTION_VERBS = frozenset({
    "create", "add", "set", "save", "store", "update", "delete", "remove",
    "submit", "register", "record", "send", "post", "put", "transfer", "book",
    "schedule", "upload", "write", "log", "insert", "push", "publish", "assign",
    "grant", "revoke", "mark", "apply", "enroll", "activate", "deactivate",
    "charge", "credit", "debit", "increment", "reset", "cancel", "approve",
    "reject", "open", "close", "start", "stop", "run", "execute", "deploy",
    "install", "move", "rename", "copy", "sync", "import", "export", "fetch",
    "get", "read", "list", "search", "query", "lookup", "check", "verify",
    "validate", "login", "logout", "connect", "disconnect", "subscribe",
    "unsubscribe", "notify", "alert", "report", "generate", "issue", "order",
    "pay", "refund", "purchase", "reserve", "archive", "restore", "enable",
    "disable", "configure", "link", "unlink", "attach", "detach", "tag",
    "label", "flag", "invite", "share", "forward", "reply", "comment", "vote",
    "rate", "follow", "join", "leave", "lock", "unlock", "sign", "encrypt",
    "decrypt", "hash", "compute", "calculate", "convert", "translate",
    "summarize", "parse", "render", "build", "compile", "test", "ping", "call",
    "invoke", "trigger", "dispatch", "route", "redirect", "load", "process",
    "handle", "request", "place", "make", "edit", "modify", "change", "clear",
    "drop", "purge", "truncate", "append", "queue", "enqueue", "track",
})


def _verb_forms(base: str) -> set:
    """Inflections of a base verb (set/sets/setting, create/created/creating,
    transfer/transferred/transferring, apply/applied/applies)."""
    forms = {base, base + "s", base + "es", base + "d", base + "ed", base + "ing"}
    if base.endswith("e"):
        forms.add(base[:-1] + "ing")
    if base.endswith("y") and len(base) > 2 and base[-2] not in "aeiou":
        forms.add(base[:-1] + "ies")
        forms.add(base[:-1] + "ied")
    if len(base) >= 3 and base[-1] not in "aeiouy" and base[-2] in "aeiou" and base[-3] not in "aeiou":
        forms.add(base + base[-1] + "ed")
        forms.add(base + base[-1] + "ing")
    return forms


def _attribution_pattern(tool_name: str) -> Optional[re.Pattern]:
    """Pattern that matches a textual reference to *tool_name*: its
    identifier (separators optional, so ``create_ticket`` / ``createTicket``
    / ``create ticket``) or an inflected form of a verb token of its name."""
    tokens = [t for t in _split_ident_tokens(tool_name or "") if t]
    if not tokens:
        return None
    alts = [r"[\s_\-\.]*".join(re.escape(t) for t in tokens)]
    for t in tokens:
        if t in _ATTRIBUTION_VERBS:
            alts.extend(re.escape(f) for f in sorted(_verb_forms(t)))
    return re.compile(r"(?<![A-Za-z0-9])(?:" + "|".join(alts) + r")(?![A-Za-z0-9])",
                      re.IGNORECASE)


def _json_record_with(obj: Any, value: str, record: Any = None) -> Any:
    """The JSON RECORD holding *value*: the innermost object that is an
    element of a list (an entry of a record list), else the root container;
    a bare string entry of a list is its own record."""
    if record is None:
        record = obj
    if isinstance(obj, dict):
        for v in obj.values():
            r = _json_record_with(v, value, record)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, str):
                if value in item:
                    return item
                continue
            r = _json_record_with(item, value, item if isinstance(item, dict) else record)
            if r is not None:
                return r
    elif isinstance(obj, str) and value in obj:
        return record
    return None


def _record_containing(text: str, value: str) -> str:
    """The record of *text* that holds *value*: its JSON record when the
    response (or the line) parses as JSON, else the line itself."""
    stripped = (text or "").strip()
    if stripped[:1] in ("{", "["):
        try:
            rec = _json_record_with(json.loads(stripped), value)
        except ValueError:
            rec = None
        if rec is not None:
            return rec if isinstance(rec, str) else json.dumps(rec, ensure_ascii=False)
    for line in (text or "").splitlines():
        if value not in line:
            continue
        s = line.strip()
        if s[:1] in ("{", "["):
            try:
                rec = _json_record_with(json.loads(s), value)
            except ValueError:
                rec = None
            if rec is not None:
                return rec if isinstance(rec, str) else json.dumps(rec, ensure_ascii=False)
        return line
    return text or ""


def _attribution_in_record(record: str, planting_tool: str, value: str) -> Optional[str]:
    """The attribution token (identifier or verb form of the planting tool's
    name) found in *record* outside the echoed value itself, or None."""
    pat = _attribution_pattern(planting_tool)
    if pat is None:
        return None
    scrubbed = record.replace(value, " ")
    m = pat.search(scrubbed)
    return m.group(0) if m else None


def _is_internal_surface(tool_name: str, contract) -> bool:
    """An underscore-named or internal/private/hidden/debug-described
    surfacing tool: never downgraded, whatever its records look like."""
    if (tool_name or "").startswith("_"):
        return True
    if contract is not None and (contract.name or "").startswith("_"):
        return True
    desc = (contract.description or "") if contract is not None else ""
    return bool(_INTERNAL_TOOL_RE.search(desc))


def _grade_response(rr: RuleResult) -> Tuple[bool, str, str, str]:
    """Return (fire, severity, confidence, primary_family) for RESPONSE text."""
    fams = set(rr.families)
    if not fams:
        return False, "none", "low", ""
    primary = _primary_family(fams)
    if fams & _DECISIVE:
        return True, "high", "high", primary
    if rr.total >= 6 and len(fams) >= 2:
        return True, "high", "medium", primary or "combined"
    return False, "none", "low", primary


def _run_injection(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    for call in ctx.calls:
        text = call.response_text or ""
        if not text:
            continue
        rr = analyze_text(text)
        fire, sev, conf, primary = _grade_response(rr)
        if fire:
            # rule 3.9 — a retrieval-shaped tool carrying content that does not
            # itself address the agent with a call to make or a concealment
            # request is annotated (low severity/confidence, so the gate
            # allows-with-warning per rule 0.5) rather than blocked.
            contract = ctx.tool_by_name(call.tool_name)
            probe = _injected_clause_probe(text, primary)
            # v3-1.2 — with no isolating clause the dynamic replay evidence
            # cannot show the clause tracks the input; only static data flow
            # can then earn the discount.
            if probe is None:
                probe = (lambda _other: True)
            if (_is_retrieval_tool(contract, ctx, probe)
                    and primary not in _RETRIEVAL_ALWAYS_BLOCK):
                out.append(mk(
                    ctx, detector_id="response-injection", category="prompt-injection",
                    evidence_location="runtime-response", severity="low", confidence="medium",
                    detection_method="untrusted-content-annotation",
                    rationale=(f"Tool is retrieval-shaped (fetches/reads/searches "
                               f"third-party content) and its response contains "
                               f"instruction-like text [{primary}] that does not "
                               "directly address the agent with a specific tool call "
                               "or a concealment request — annotated as untrusted "
                               "retrieved content, the same way a fetched README or "
                               "email body legitimately might read, rather than "
                               "blocked outright."),
                    evidence={"tool": call.tool_name, "families": rr.families,
                              "response_excerpt": text[:400], "seq": call.seq,
                              "untrusted_content_annotation": True},
                    source_kind="dynamic-runtime", tool_name=call.tool_name,
                ))
                continue
            out.append(mk(
                ctx, detector_id="response-injection", category="prompt-injection",
                evidence_location="runtime-response", severity=sev, confidence=conf,
                detection_method="runtime-response-scan",
                rationale=(f"Tool response contains agent-directed instruction "
                           f"mechanism(s) [{primary}] — prompt injection delivered "
                           "through tool output the agent will read."),
                evidence={"tool": call.tool_name, "families": rr.families,
                          "response_excerpt": text[:400], "seq": call.seq},
                source_kind="dynamic-runtime", tool_name=call.tool_name,
            ))
        elif rr.obfuscation_flags and ({"zero-width-characters", "bidi-control-characters",
                                        "encoded-blob-decoded"} & set(rr.obfuscation_flags)):
            out.append(mk(
                ctx, detector_id="response-injection", category="prompt-injection",
                evidence_location="runtime-response", severity="high", confidence="medium",
                detection_method="runtime-response-scan",
                rationale=("Tool response hides content via "
                           f"{', '.join(sorted(rr.obfuscation_flags))} — concealed "
                           "payload delivered through tool output."),
                evidence={"tool": call.tool_name,
                          "obfuscation_flags": sorted(rr.obfuscation_flags),
                          "decoded": rr.norm.decoded_segments[:3], "seq": call.seq},
                source_kind="dynamic-runtime", tool_name=call.tool_name,
            ))
        else:
            out.extend(_own_tool_planning_directives(ctx, call, text))
    return out


def _own_tool_planning_directives(ctx: ScanContext, call, text: str) -> List[Finding]:
    """v5-5 — a planning directive that names one of THIS server's own
    tools (the non-sibling case is ``response-redirect``'s). A prompt
    template is exempt: a prompt is the instruction text the user selects,
    and sequencing the server's own tools is its job."""
    if (call.tool_name or "").startswith("prompt:"):
        return []
    live_names = {c.name.lower() for c in ctx.all_contracts() if c.name}
    if not live_names:
        return []
    contract = ctx.tool_by_name(call.tool_name)
    out: List[Finding] = []
    seen: set = set()
    for pd in planning_directive_clauses(text, live_names, _own_param_names(contract, call)):
        key = pd["named_tool"].lower()
        if not pd["own_tool"] or key in seen:
            continue
        seen.add(key)
        evidence = {"tool": call.tool_name, "named_tool": pd["named_tool"],
                    "clause": pd["clause"], "verb": pd["verb"],
                    "plan_reference": pd["plan_reference"], "seq": call.seq,
                    "trigger": "planning-directive", "own_tool": True}
        if _is_retrieval_tool(contract, ctx, _clause_probe(pd["clause"])):
            evidence["untrusted_content_annotation"] = True
            out.append(mk(
                ctx, detector_id="response-injection", category="prompt-injection",
                evidence_location="runtime-response", severity="low", confidence="medium",
                detection_method="untrusted-content-annotation",
                rationale=(f"Tool is retrieval-shaped (data flow shows it returns "
                           f"third-party content) and its response carries a planning "
                           f"directive naming '{pd['named_tool']}' — annotated as "
                           "untrusted retrieved content rather than blocked outright."),
                evidence=evidence, source_kind="dynamic-runtime", tool_name=call.tool_name,
            ))
            continue
        out.append(mk(
            ctx, detector_id="response-injection", category="prompt-injection",
            evidence_location="runtime-response", severity="high", confidence="medium",
            detection_method="response-planning-directive",
            rationale=(f"Tool response carries an obligation aimed at the agent together "
                       f"with an invoke verb whose object is the tool '{pd['named_tool']}', "
                       f"and refers to the agent's plan / next step / the user's request "
                       f"(\"{pd['plan_reference']}\") — a response is data, and one that "
                       "writes the agent's plan for it is an injected planning directive, "
                       "even when the tool it names is the server's own."),
            evidence=evidence, source_kind="dynamic-runtime", tool_name=call.tool_name,
        ))
    return out


# ---- rule 3.5 — response redirect toward a non-sibling tool ---------------------
# ``analysis.textrules._clause_scoped_tool_redirect`` already catches "call X"
# clauses that ALSO carry a secret/credential reference — that mechanism
# stays. This is a second, independent structural signal: "call X" where X is
# simply not a tool this server itself declares at all is itself suspicious,
# with no secret word required. A response has no legitimate reason to name
# and direct the agent toward invoking a tool from some OTHER server — and a
# response naming one of THIS server's own tools (an honest "see also
# refresh_token" cross-reference) is deliberately excluded, since that is
# ordinary, harmless prose.
_CALL_TOOL_VERB_RE = re.compile(
    r"\b(call|invoke|run|execute|trigger)\b\s+([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b",
    re.IGNORECASE)
# v3-2.4 — "add/include/insert <tool>" counts as a call verb only when the
# clause names a plan/response/call list/next step ("add a call to X to your
# plan"), never a bare "include the title in the response".
_ADD_TOOL_VERB_RE = re.compile(
    r"\b(add|adds|added|adding|include|includes|included|including|insert|inserts|"
    r"inserted|inserting)\b\s+(?:a\s+call\s+to\s+|the\s+)?[`\"']?"
    r"([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b", re.IGNORECASE)
_RESPONSE_PLAN_NOUN_RE = re.compile(
    r"\b(plans?|responses?|repl(?:y|ies)|outputs?|answers?|call\s+lists?|"
    r"list\s+of\s+calls|tool\s+calls?|calls|next\s+steps?|sequence|workflow|"
    r"chain|pipeline|queue)\b", re.IGNORECASE)
# rule P6.6 — a response redirect needs an OBLIGATION (must/should/always/...)
# or an explicit AGENT addressee (assistant/agent/model/ai/system — not a
# bare "you"/"user", which routinely addresses the human in ordinary text)
# in the SAME clause. A plain, unforced mention ("you can also call
# export_data for a CSV") is ordinary documentation prose, not a redirect
# instruction — the same two-tier "force required" bar rule 1 already applies
# to a description naming a sibling tool.
_REDIRECT_OBLIGATION_RE = re.compile(
    r"\b(must|should|shall|need to|have to|are required to|are instructed to|"
    r"always|never|immediately|first|before (doing )?anything|prior to)\b",
    re.IGNORECASE)
_AGENT_ADDRESSEE_RE = re.compile(
    r"\b(the\s+)?(assistant|agent|model|\bai\b|system)\b", re.IGNORECASE)
# v3-1.4 — a LABEL-SHAPED directive: a closed vocabulary of "what to do
# next" labels in key/value or label form (``next_step=``, ``action:``,
# ``todo:``, ``then:`` ...) whose VALUE is a CALL to a tool — either a call
# verb followed by a tool-shaped identifier, or the identifier followed by
# an argument list. The label form is itself the directive, so no separate
# obligation word is required; a label whose value is a bare status word
# (``action: refund_issued``) is not a call and never matches.
_DIRECTIVE_LABEL_RE = re.compile(
    r"(?:^|[\s\[\(\{,;|>*-])(?:next[_ -]?steps?|next[_ -]?actions?|next|actions?|"
    r"todo|to[_ -]?do|then|steps?|instructions?|commands?|directives?|tasks?|"
    r"required[_ -]?actions?|follow[_ -]?up|do|run|execute)\s*[:=]\s*"
    r"(?:(?:please\s+)?(?:call|invoke|run|execute|trigger|use)\s+[`\"']?"
    r"([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b"
    r"|[`\"']?([a-z][a-z0-9]*(?:_[a-z0-9]+)+)[`\"']?\s*\()",
    re.IGNORECASE)


# ---- v5-5 — planning directive in a response -------------------------------
# A response is DATA the agent asked for. A clause in it that carries an
# OBLIGATION (must, should, always, need to, ...) together with an
# invoke-class verb (call, use, run, add, include, insert, ...) whose OBJECT
# is a tool-shaped identifier, and that refers to the agent's PLAN, its NEXT
# STEP, or THE USER'S REQUEST, is the response writing the agent's plan for
# it — whether the named tool belongs to another server (a redirect) or to
# this one (the server steering how its own tools get chained). The three
# parts together are the mechanism; none of them alone is:
#
# * "You can also call export_report for a CSV."      — no obligation;
# * "You must call start_session first."              — an honest
#   precondition error: obligation + own tool, no plan / next-step /
#   user-request reference;
# * "You must include order_id in your request."      — the identifier is
#   one of the tool's own parameters, not a tool.
#
# The identifier is tool-shaped when it is one of this server's listed tool
# names, a snake_case token, or a quoted / "... tool"-suffixed kebab-case or
# camelCase token; a token that is a parameter of the responding tool (its
# schema or this call's own arguments) is a field name, never a tool.
_PLAN_QUOTE = "`\"'‘’“”"
_PLAN_OBLIGATION_RE = re.compile(
    r"\b(must|should|shall|always|needs?\s+to|ha(?:ve|s)\s+to|(?:is|are)\s+to|required|"
    r"mandatory|make\s+sure|be\s+sure\s+to|remember\s+to)\b", re.IGNORECASE)
_PLAN_INVOKE_RE = re.compile(
    r"\b(?P<verb>call(?:s|ed|ing)?|invok(?:e|es|ed|ing)|run(?:s|ning)?|"
    r"execut(?:e|es|ed|ing)|trigger(?:s|ed|ing)?|us(?:e|es|ed|ing)|add(?:s|ed|ing)?|"
    r"includ(?:e|es|ed|ing)|insert(?:s|ed|ing)?)\s+"
    r"(?:(?:a|an|the|another|one|extra|additional)\s+){0,2}"
    r"(?:(?:tool\s+)?(?:calls?|steps?|invocations?)\s+(?:to|of|for)\s+)?"
    r"(?:(?:the|tool|function|command)\s+){0,2}"
    r"(?P<q>[" + _PLAN_QUOTE + r"])?"
    r"(?P<name>[A-Za-z][A-Za-z0-9]*(?:[_\-][A-Za-z0-9]+)*)"
    r"(?(q)[" + _PLAN_QUOTE + r"])"
    r"(?P<suffix>\s+(?:tool|function)\b)?", re.IGNORECASE)
_PLAN_PASSIVE_RE = re.compile(
    r"(?P<q>[" + _PLAN_QUOTE + r"])?"
    r"\b(?P<name>[A-Za-z][A-Za-z0-9]*(?:[_\-][A-Za-z0-9]+)*)"
    r"(?(q)[" + _PLAN_QUOTE + r"])"
    r"(?P<suffix>\s+(?:tool|function))?\s+"
    r"(?:must|should|shall|needs?\s+to|ha(?:s|ve)\s+to|is\s+to|is\s+required\s+to)\s+"
    r"(?:(?:always|first|also|then)\s+){0,2}be\s+"
    r"(?P<verb>called|invoked|run|executed|triggered|used|added|included|inserted)\b",
    re.IGNORECASE)
_PLAN_REF_RE = re.compile(
    # the agent's plan
    r"\b(?:to|in|into|of|on)\s+(?:your|the|its)\s+(?:current\s+|own\s+)?plan\b|"
    r"\b(?:updat\w+|revis\w+|adjust\w*|amend\w*|extend\w*|modif\w+)\s+(?:your|the)\s+plan\b|"
    r"\b(?:execution|action|task|tool[- ]call)\s+plan\b|\bplan\s+of\s+action\b|"
    r"\bplanned\s+(?:steps?|calls?|actions?)\b|\bwhen\s+planning\b|"
    # its next step
    r"\bnext\s+(?:steps?|actions?|moves?|turn)\b|\bas\s+(?:the|your|a)\s+next\b|"
    r"\bbefore\s+(?:you\s+)?(?:respond|reply|answer)\w*\b|"
    r"\bbefore\s+(?:responding|replying|answering)\b|"
    r"\bprior\s+to\s+(?:responding|replying|answering)\b|"
    r"\bbefore\s+(?:your|the)\s+(?:next|final)\s+(?:response|reply|answer|message|step|action)\b|"
    r"\b(?:and\s+)?then\s+(?:respond|reply|answer)\b|"
    # the user's request
    r"\b(?:the\s+)?user['’]?s?\s+(?:(?:original|current|actual|initial|latest|own)\s+)?"
    r"(?:request|query|question|task|instructions?|message|prompt|ask|goal|intent)\b|"
    r"\bwhat\s+the\s+user\s+(?:asked|requested|wants|wanted)\b|\bthe\s+original\s+request\b",
    re.IGNORECASE)


def _plan_tool_shaped(name: str, quoted: bool, suffixed: bool, live_names: set,
                      own_params: set) -> bool:
    from .crosstool import _looks_like_quoted_tool_name, _normalize_ident
    low = name.lower()
    if _normalize_ident(name) in own_params:
        return False  # a parameter of the responding tool is a field, not a tool
    single = len(_split_ident_tokens(name)) < 2
    if low in live_names:
        return (not single) or quoted or suffixed
    if single:
        return False
    if "_" in name and "-" not in name:
        return True
    return (quoted or suffixed) and _looks_like_quoted_tool_name(name)


def planning_directive_clauses(text: str, live_names: set, own_params: set = frozenset()
                               ) -> List[dict]:
    """v5-5 — every clause of ``text`` that is a planning directive: an
    obligation + an invoke-class verb whose object is a tool-shaped
    identifier + a reference to the agent's plan / next step / the user's
    request. ``own_tool`` says whether the named tool is one this server
    lists."""
    out: List[dict] = []
    for clause in _clauses(text or ""):
        ref = _PLAN_REF_RE.search(clause)
        if not ref:
            continue
        passive = None
        for pm in _PLAN_PASSIVE_RE.finditer(clause):
            if _plan_tool_shaped(pm.group("name"), bool(pm.group("q")),
                                 bool(pm.group("suffix")), live_names, own_params):
                passive = pm
                break
        active = None
        if passive is None and _PLAN_OBLIGATION_RE.search(clause):
            for am in _PLAN_INVOKE_RE.finditer(clause):
                if _plan_tool_shaped(am.group("name"), bool(am.group("q")),
                                     bool(am.group("suffix")), live_names, own_params):
                    active = am
                    break
        m = passive or active
        if m is None:
            continue
        name = m.group("name")
        out.append({"clause": clause[:200], "named_tool": name,
                    "verb": m.group("verb").lower(),
                    "plan_reference": ref.group(0).strip(),
                    "own_tool": name.lower() in live_names})
    return out


def _own_param_names(contract, call=None) -> set:
    from .crosstool import _normalize_ident, _own_prop_names
    names = set()
    if contract is not None:
        names |= set(_own_prop_names(contract))
    if call is not None and isinstance(getattr(call, "arguments", None), dict):
        names |= {_normalize_ident(k) for k in call.arguments}
    return names


def _run_response_redirect(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    live_names = {c.name.lower() for c in ctx.all_contracts() if c.name}
    for call in ctx.calls:
        text = call.response_text or ""
        if not text:
            continue
        contract = ctx.tool_by_name(call.tool_name)
        seen: set = set()
        for clause in _clauses(text):
            named = ""
            trigger = ""
            m = _CALL_TOOL_VERB_RE.search(clause)
            if not m and _RESPONSE_PLAN_NOUN_RE.search(clause):
                m = _ADD_TOOL_VERB_RE.search(clause)
            if m:
                cand = m.group(2)
                # rule P6.6 — a plain, unforced mention with no obligation and
                # no explicit agent addressee is ordinary prose, not a
                # redirect instruction.
                if (_REDIRECT_OBLIGATION_RE.search(clause)
                        or _AGENT_ADDRESSEE_RE.search(clause)):
                    named, trigger = cand, "obligation"
            if not named:
                # v3-1.4 — second trigger: a label-shaped directive whose
                # value is a call to a tool.
                m2 = _DIRECTIVE_LABEL_RE.search(clause)
                if m2:
                    named, trigger = (m2.group(1) or m2.group(2) or ""), "label-directive"
            if not named:
                # v5-5 — third trigger: a planning directive (obligation +
                # invoke-class verb with a tool-shaped object + a plan /
                # next-step / user-request reference). The call-verb list
                # above has no "use", and add/include/insert needs it too.
                # A directive naming one of this server's OWN tools is
                # reported by ``_run_injection`` instead.
                for pd in planning_directive_clauses(
                        clause, live_names, _own_param_names(contract, call)):
                    if not pd["own_tool"]:
                        named, trigger = pd["named_tool"], "planning-directive"
                        break
            if not named:
                continue
            key = named.lower()
            if key in live_names or key in seen or len(named) < 4:
                continue
            # v3-1.2 — the retrieval discount is decided per injected
            # clause: static data flow, or replay variance with THIS clause
            # absent from at least one replay.
            retrieval = _is_retrieval_tool(contract, ctx, _clause_probe(clause))
            seen.add(key)
            # rule P6.6 — instructional text inside RETRIEVED content (a fetch/
            # read/search tool quoting a README/email/webpage verbatim) is
            # exactly as likely to be an honest excerpt as an attack; annotate
            # rather than block, same stance as response-injection's rule P2.1.
            if retrieval:
                out.append(mk(
                    ctx, detector_id="response-redirect", category="confused-deputy",
                    evidence_location="runtime-response", severity="low", confidence="medium",
                    detection_method="response-nonsibling-redirect-annotation",
                    rationale=(f"Tool is retrieval-shaped and its response instructs "
                               f"calling '{named}', which is not a tool this server "
                               "declares — annotated as untrusted retrieved content "
                               "rather than blocked outright."),
                    evidence={"tool": call.tool_name, "named_tool": named,
                              "clause": clause[:200], "seq": call.seq,
                              "trigger": trigger,
                              "untrusted_content_annotation": True},
                    source_kind="dynamic-runtime", tool_name=call.tool_name,
                ))
                continue
            out.append(mk(
                ctx, detector_id="response-redirect", category="confused-deputy",
                evidence_location="runtime-response", severity="high", confidence="medium",
                detection_method="response-nonsibling-redirect",
                rationale=(f"Tool response instructs the agent to call '{named}', which "
                           "is not a tool this server declares — a response naming and "
                           "directing the agent toward a tool OUTSIDE its own server's "
                           "tool listing has no legitimate purpose, independent of any "
                           "secret/credential reference in the same clause."
                           + (" The directive is label-shaped (a next-step/action/"
                              "todo label whose value is a tool call), which is "
                              "itself the instruction form (v3-1.4)."
                              if trigger == "label-directive" else "")
                           + (" The clause is a planning directive: an obligation, an "
                              "invoke-class verb whose object is the tool, and a "
                              "reference to the agent's plan / next step / the user's "
                              "request (v5-5)."
                              if trigger == "planning-directive" else "")),
                evidence={"tool": call.tool_name, "named_tool": named,
                          "clause": clause[:200], "seq": call.seq,
                          "trigger": trigger},
                source_kind="dynamic-runtime", tool_name=call.tool_name,
            ))
    return out


register(Detector(
    id="response-redirect", category="confused-deputy",
    evidence_location="runtime-response", phase="response", run=_run_response_redirect,
    requires={CAP_DYNAMIC},
    rationale=("A response has no legitimate reason to name and direct the agent "
               "toward invoking a tool that is not part of this server's own "
               "declared listing — that is a confused-deputy redirect, structurally, "
               "with no dependency on secret-word vocabulary or framing device."),
))


# ---- cross-call leakage + over-sharing --------------------------------------


def _run_leak(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    # replay calls in order against a fresh state seeded with decoy-file markers
    state = CrossCallState()
    state.register_file_markers(dict(ctx.state.file_markers))
    for call in ctx.calls:
        leaks = state.scan_response(call.seq, call.tool_name, call.response_text or "",
                                    call.arguments)
        for lk in leaks:
            if lk["kind"] == "file":
                out.append(mk(
                    ctx, detector_id="response-leak", category="credential-exposure",
                    evidence_location="runtime-response", severity="high",
                    confidence="high", detection_method="canary-file-scan",
                    rationale=("Tool response contains the content of a decoy secret "
                               "file seeded in the sandbox — the tool read a sensitive "
                               "file and returned it to the agent."),
                    evidence={"tool": call.tool_name, "decoy": lk["origin_param"],
                              "canary": lk["canary"], "seq": call.seq},
                    source_kind="dynamic-runtime", tool_name=call.tool_name,
                ))
            else:
                # rule 3.7/v4-1 — grade by canary KIND and by ATTRIBUTION. A
                # secret-kind canary (planted into a parameter that looked
                # credential-shaped) surfacing elsewhere is a real leak
                # everywhere, full stop. A plain ARGUMENT that resurfaces
                # inside a record naming the tool it was given to is an
                # attributed audit entry — the shape of an honest log,
                # whatever either tool's description says (low/medium, with
                # a warning); the same value echoed bare, with nothing in
                # its record tying it to the planting call, is a covert
                # side-channel (high/high). An underscore-named/"internal"
                # surfacing tool is never downgraded.
                surfacing = ctx.tool_by_name(call.tool_name)
                attribution = None
                record = ""
                if lk["kind"] == "arg" and not _is_internal_surface(call.tool_name, surfacing):
                    record = _record_containing(call.response_text or "", lk["canary"])
                    attribution = _attribution_in_record(record, lk["origin_tool"], lk["canary"])
                if attribution:
                    sev, conf = "low", "medium"
                    note = (" The echoed value sits inside a record that also names "
                            f"the planting tool ('{attribution}') — an attributed "
                            "audit/history entry, the shape of an honest log rather "
                            "than a hidden side-channel; reported as a warning "
                            "(confirm that exposing other callers' inputs through "
                            "this tool is intended).")
                else:
                    sev, conf = "high", "high"
                    note = ("" if lk["kind"] != "arg" else
                            " Nothing in the record that carries the value names the "
                            "tool it was given to — a bare echo, not an attributed "
                            "audit entry.")
                evidence = {"planted_in_tool": lk["origin_tool"],
                            "planted_seq": lk["origin_seq"],
                            "surfaced_in_tool": lk["surfaced_in_tool"],
                            "surfaced_seq": lk["surfaced_in_seq"],
                            "canary": lk["canary"], "canary_kind": lk["kind"],
                            "attributed": bool(attribution)}
                if attribution:
                    evidence["attribution"] = attribution
                    evidence["record_excerpt"] = record[:200]
                out.append(mk(
                    ctx, detector_id="response-leak", category="data-exfiltration",
                    evidence_location="multi-call-state", severity=sev,
                    confidence=conf, detection_method="cross-call-canary-scan",
                    rationale=("A value planted into an earlier call surfaced in a "
                               "later, unrelated response — server carries state "
                               "across calls and leaks it (cross-call leakage)." + note),
                    evidence=evidence,
                    source_kind="dynamic-runtime", tool_name=call.tool_name,
                ))
        state.note_call_args(call.seq, call.tool_name, call.arguments)

        # over-sharing / credential exposure vs declared scope
        out.extend(_oversharing(ctx, call))
        # rule P2.2: over-sharing measured by response *shape/volume*, independent
        # of whether any individual value looks like a secret
        out.extend(_scope_oversharing(ctx, call))
    return out


def _oversharing(ctx: ScanContext, call) -> List[Finding]:
    out: List[Finding] = []
    text = _strip_canaries(call.response_text or "")
    if not text:
        return out
    contract = ctx.tool_by_name(call.tool_name)
    desc = (contract.description if contract else "") or ""
    desc_mentions_secrets = bool(re.search(
        r"secret|password|credential|token|api\s?key|private key|ssh|\.env",
        desc, re.IGNORECASE))

    val_hit = SECRET_VALUE_RE.search(text)
    if val_hit and not desc_mentions_secrets:
        out.append(mk(
            ctx, detector_id="response-leak", category="credential-exposure",
            evidence_location="runtime-response", severity="high", confidence="high",
            detection_method="response-shape-scan",
            rationale=("Response contains a credential-shaped value (e.g. private "
                       "key / access key / token) that the tool's described scope "
                       "never promised — credential exposure."),
            evidence={"tool": call.tool_name, "match_kind": "value",
                      "excerpt": text[max(0, val_hit.start() - 20):val_hit.start() + 40],
                      "seq": call.seq},
            source_kind="dynamic-runtime", tool_name=call.tool_name,
        ))
        return out

    key_hits = find_secret_key_hits(text)
    if key_hits and not desc_mentions_secrets:
        out.append(mk(
            ctx, detector_id="response-leak", category="information-disclosure",
            evidence_location="runtime-response", severity="medium", confidence="medium",
            detection_method="response-shape-scan",
            rationale=("Response includes secret-shaped fields "
                       f"({sorted(set(k.lower() for k in key_hits))[:5]}) not implied "
                       "by the tool's description — over-sharing of sensitive data."),
            evidence={"tool": call.tool_name, "secret_keys": sorted(set(key_hits))[:8],
                      "seq": call.seq},
            source_kind="dynamic-runtime", tool_name=call.tool_name,
        ))
    return out


# ---- rule P2.2: over-sharing vs. declared scope (shape/volume, not injection) ----
# The payload here is the *excess data itself*, not an instruction: a response
# that returns materially more than its own description promises (extra
# records, extra fields, adjacent-entity data, identifiers the tool had no
# stated reason to return). We compare the response's *shape* — record-list
# volume and field-name vocabulary — against the description's declared scope,
# deterministically (no LLM, no semantic embedding): a description is a bag of
# words naming what the tool returns, and a response is over the declared scope
# when it embeds a list of unrelated records the description never implied is a
# collection, or when most of its field names share no vocabulary with the
# description at all.

_SCOPE_STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "for", "to", "in", "on", "with", "by",
    "return", "returns", "returning", "current", "this", "that", "its", "is",
    "are", "given", "provided", "value", "values", "data", "information",
    "about", "from", "get", "gets", "fetch", "fetches",
}
_SCOPE_PLURAL_RE = re.compile(
    r"\b(list|all|records?|results?|items?|entries|multiple|array|history|"
    r"logs?|every|collection|batch)\b", re.IGNORECASE)


def _scope_tokens(desc: str) -> set:
    words = re.findall(r"[a-zA-Z]+", (desc or "").lower())
    return {w for w in words if w not in _SCOPE_STOPWORDS and len(w) > 2}


def _flatten_keys(obj: Any, out: List[str] = None) -> List[str]:  # noqa: B006
    if out is None:
        out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(str(k))
            _flatten_keys(v, out)
    elif isinstance(obj, list):
        for item in obj:
            _flatten_keys(item, out)
    return out


def _find_record_lists(obj: Any, path: str = "", out: List[Tuple[str, int]] = None
                       ) -> List[Tuple[str, int]]:  # noqa: B006
    if out is None:
        out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            _find_record_lists(v, f"{path}.{k}" if path else str(k), out)
    elif isinstance(obj, list):
        dict_items = [i for i in obj if isinstance(i, dict)]
        if len(dict_items) >= 2:
            out.append((path or "<root>", len(dict_items)))
        for item in obj:
            _find_record_lists(item, path, out)
    return out


def _key_related(key: str, tokens: set) -> bool:
    words = [w for w in re.findall(r"[a-zA-Z]+", key.lower()) if len(w) > 2]
    if not words:
        return True  # purely numeric/opaque key — nothing to compare, not a signal
    for w in words:
        for t in tokens:
            if w == t or (len(t) > 3 and (w in t or t in w)):
                return True
    return False


# rule P2.2 (widened): the overwhelming majority of real MCP tool responses are
# NOT raw JSON — FastMCP-style tools routinely return a formatted string like
# "Email: x. Address: y. Internal customer ID: z." The JSON-only shape/volume
# comparison above is completely blind to this (``json.loads`` just raises
# and the detector silently returns nothing, no matter how much unrelated
# data the string carries). This label extractor recovers the same
# "declared scope vs. field vocabulary" signal from ordinary "Label: value"
# / "Label=value" prose, and a bare PII-shaped value (an email address) is a
# second, even simpler signal: a tool whose description never mentions
# contact/email information has no honest reason to emit one.
_TEXT_LABEL_RE = re.compile(r'\b([A-Z][A-Za-z]+(?:[ ][A-Za-z]+){0,3})\s*[:=]\s')
# discourse/footnote markers ("Note:", "Tip:", "FYI:", ...) are commentary,
# not a data field — a response that appends a friendly aside must not be
# mistaken for "over-sharing" just because it happens to use colon-prefixed
# prose, which is an extremely common, entirely benign writing style.
_NON_DATA_LABELS = {"note", "tip", "warning", "important", "fyi", "reminder",
                    "also", "hint", "caution", "disclaimer", "ps", "aside"}
_EMAIL_RE = re.compile(r'[\w.+-]+@[\w-]+\.[a-z]{2,}', re.IGNORECASE)
# An email address alone is extremely common, legitimate content (a support/
# contact address in ordinary helpdesk prose). It is only a genuine
# over-sharing signal when it is *attributed to someone* the tool never
# promised to disclose — a possessive/ownership construction right next to
# it ("owned by", "belongs to", ...) — not a call-to-action ("contact us at").
_EMAIL_OWNER_CTX_RE = re.compile(
    r"\b(owned|belongs?|registered|associated)\b.{0,15}\b(by|to|with)\b|"
    r"\b(account|customer|user|owner)\s+(of|is|:)\b", re.IGNORECASE)


def _text_labels(text: str) -> List[str]:
    return [m.group(1).strip() for m in _TEXT_LABEL_RE.finditer(text)
            if m.group(1).strip().lower() not in _NON_DATA_LABELS]


# ---- rule 3.6 — value-SHAPE over-sharing checks ---------------------------------
# A label-vocabulary mismatch (above) needs the description AND the response
# to both use words at all; some of the most sensitive things a response can
# leak (a national ID, a card number, a phone number, an internal hostname, a
# private IP, a build string) are recognizable purely from the VALUE's own
# shape, independent of whatever word introduces it — "National ID on file:
# 923-14-7765" was reported missed because "the rule needs two [unrelated
# labels]; no pattern recognises ID-shaped values" at all. One of these is
# enough on its own: an honest tool's description essentially never promises
# this specific KIND of sensitive data, so if the description doesn't even
# use the related vocabulary, a match is a real signal by itself.
_NATIONAL_ID_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b")
_PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3})\b")
_INTERNAL_HOST_RE = re.compile(
    r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:internal|corp|local|intranet|lan)\b",
    re.IGNORECASE)
_BUILD_STRING_RE = re.compile(r"\bbuild[ #_-]?\d{3,}\b", re.IGNORECASE)
_CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
# v3-3.5 — a value explicitly LABELED as internal/private/system/backend/
# debug/diagnostic (an internal identifier, a debug error string, a backend
# trace) is a sensitive value shape in its own right: internal identifiers
# and diagnostic detail are the classic information-disclosure payload, and
# an honest description essentially never promises them.
_INTERNAL_LABEL_VALUE_RE = re.compile(
    r"\b(?:(?:internal|private|system|backend)[\s_-]*(?:[a-z]+[\s_-]*){0,2}"
    r"(?:id|ids|identifier|identifiers|ref|reference|code|codes|key|keys|number|no)"
    r"|(?:debug|diagnostic|backend|internal)[\s_-]*(?:[a-z]+[\s_-]*){0,2}"
    r"(?:error|errors|trace|traces|stack|dump))\b\s*[:=]\s*\S",
    re.IGNORECASE)

# rule P6.5 — a bare ###-##-#### digit pattern is not by itself identity-shaped
# (it is just as easily an order/reference/product code formatted that way)
# — it needs a SUPPORTING LABEL nearby (ssn/social security/national id/tax
# id/...) introducing it as an identity number before it counts at all.
_NATIONAL_ID_LABEL_RE = re.compile(
    r"\b(ssn|social\s+security|national\s+id|tax\s+id|itin|ein|"
    r"identification\s+number)\b", re.IGNORECASE)

_VALUE_SHAPE_CHECKS = (
    ("national-id", _NATIONAL_ID_RE, {"ssn", "national", "identification"}),
    ("phone", _PHONE_RE, {"phone", "telephone", "mobile", "contact"}),
    ("private-ip", _PRIVATE_IP_RE, {"ip", "address", "network"}),
    ("internal-hostname", _INTERNAL_HOST_RE, {"host", "hostname", "server", "internal"}),
    ("build-string", _BUILD_STRING_RE, {"build", "version", "release"}),
    ("internal-labeled-value", _INTERNAL_LABEL_VALUE_RE,
     {"internal", "private", "system", "backend", "debug", "diagnostic", "trace"}),
)
# rule P6.5 — phone numbers and host names ALONE are informational: extremely
# common, largely benign content on their own (a support phone number, an
# ordinary internal service hostname in an infra-status response). They
# still corroborate a STRONGER signal (a field-vocabulary mismatch, a card
# number, a labeled national id, a private IP) but do not by themselves earn
# medium/actionable confidence the way those do.
_INFORMATIONAL_SHAPE_LABELS = {"phone", "internal-hostname"}


def _luhn_valid(digits: str) -> bool:
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _card_number_hits(text: str) -> List[str]:
    hits = []
    for m in _CARD_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            hits.append(m.group(0))
    return hits


def _value_shape_hits(text: str, tokens: set) -> List[Tuple[str, str]]:
    """rules 3.6/P6.5 — every value-shaped sensitive match not already implied by
    the description's own vocabulary. An identity-number-shaped value needs
    a SUPPORTING LABEL (ssn/social security/national id/tax id/...)
    somewhere in the text before it counts at all — the bare digit pattern
    alone is just as easily an order/reference/product code."""
    hits: List[Tuple[str, str]] = []
    for label, pat, related_words in _VALUE_SHAPE_CHECKS:
        if related_words & tokens:
            continue  # description already implies this kind of data
        if label == "national-id" and not _NATIONAL_ID_LABEL_RE.search(text):
            continue
        m = pat.search(text)
        if m:
            hits.append((label, m.group(0)))
    if not ({"card", "payment", "billing"} & tokens):
        card_hits = _card_number_hits(text)
        if card_hits:
            hits.append(("card-number", card_hits[0]))
    return hits


def _scope_oversharing(ctx: ScanContext, call) -> List[Finding]:
    text = _strip_canaries(call.response_text or "")
    if not text:
        return []
    contract = ctx.tool_by_name(call.tool_name)
    desc = (contract.description if contract else "") or ""
    if not desc:
        return []  # nothing declared to compare the response's scope against

    tokens = _scope_tokens(desc)
    reasons = []
    record_lists: List[Tuple[str, int]] = []
    unrelated: List[str] = []
    shape_hits = _value_shape_hits(text, tokens)
    for label, snippet in shape_hits:
        reasons.append(f"contains a {label}-shaped value ({snippet!r}) the description "
                       "gives no indication this tool returns")
    # rule 3.10 — track which reason(s) actually fired, not just their combined
    # text, so grading below can tell "only a bare unpromised record list"
    # apart from "specific unrelated field names/values" instead of treating
    # every reason as equally strong evidence.
    has_record_list = False
    has_field_mismatch = False

    data = None
    try:
        parsed = json.loads(text)
        if isinstance(parsed, (dict, list)):
            data = parsed
    except (json.JSONDecodeError, ValueError):
        data = None

    if data is not None:
        desc_is_plural = bool(_SCOPE_PLURAL_RE.search(desc))
        record_lists = [] if desc_is_plural else _find_record_lists(data)
        if record_lists:
            path, n = record_lists[0]
            reasons.append(f"embeds a list of {n} unrelated records at '{path}' though "
                           "the description promises a single item, not a collection")
            has_record_list = True
        keys = _flatten_keys(data)
        unrelated = sorted({k for k in keys if not _key_related(k, tokens)})
        if len(unrelated) >= 3 and len(unrelated) / max(1, len(keys)) > 0.4:
            reasons.append("includes fields with no vocabulary overlap with the "
                           f"description ({unrelated[:6]})")
            has_field_mismatch = True
    else:
        # plain-text/formatted response: recover the same signal from
        # "Label: value" pairs instead of JSON keys. De-duplicated (order
        # preserved): a flattened MCP result commonly echoes the same text
        # twice (a human-readable ``content`` block plus a mirrored
        # ``structuredContent``/JSON block) — comparing a de-duplicated
        # "unrelated" set against a NON-deduplicated total label count would
        # silently dilute the ratio below threshold on exactly that harmless
        # duplication, which is what happened here before this fix.
        labels = list(dict.fromkeys(_text_labels(text)))
        unrelated = sorted({lb for lb in labels if not _key_related(lb, tokens)})
        if labels and len(unrelated) >= 2 and len(unrelated) / max(1, len(labels)) >= 0.4:
            reasons.append("includes labeled fields with no vocabulary overlap with the "
                           f"description ({unrelated[:6]})")
            has_field_mismatch = True
        email_m = _EMAIL_RE.search(text)
        if email_m and "email" not in tokens and "contact" not in tokens:
            window = text[max(0, email_m.start() - 40):email_m.start()]
            if _EMAIL_OWNER_CTX_RE.search(window):
                reasons.append("includes an email address attributed to a different "
                               "record/owner though the description gives no "
                               "indication this tool returns contact/email data")
                # v3-3.5 — PII attributed to another owner is a sensitive
                # VALUE shape, not a bare field-vocabulary mismatch.
                shape_hits.append(("attributed-email", email_m.group(0)))

    if not reasons:
        return []
    # rule 3.10 — demote the WEAKEST generic shape/volume heuristic (a bare
    # unpromised record list, and NOTHING else corroborating it) to low
    # confidence: real, but too easily true of an honest response whose
    # description is merely terse about "returns a list" (the reported
    # weather/search-probe false positives — a list-shaped result with no
    # field-vocabulary mismatch and no sensitive-shaped value at all). A
    # SPECIFIC field-vocabulary mismatch (named unrelated fields/labels the
    # description shares no vocabulary with at all, already gated behind a
    # >=40% ratio) or a rule 3.6 value-shape match is much more specific
    # evidence and keeps this detector's full actionable confidence — that
    # is the shape of the devset's own labeled over-sharing cases (an email
    # tool also returning "Internal customer ID"/"Account notes"), which
    # must stay caught.
    has_card = any(lbl == "card-number" for lbl, _ in shape_hits)
    severity = "high" if has_card else "medium"
    # rule P6.5 — a phone number or host name ALONE (no OTHER corroborating
    # shape hit, no field-vocabulary mismatch) is informational: common,
    # largely benign content on its own. A STRONGER shape hit (card number,
    # labeled national id, private IP, build string) still earns full
    # actionable confidence exactly as before.
    strong_shape_hits = [h for h in shape_hits if h[0] not in _INFORMATIONAL_SHAPE_LABELS]
    # v3-3.5 — the unrelated-field vocabulary heuristic ALONE is
    # informational (low confidence): a description that is merely terse
    # about its fields is too easily "unrelated". It earns medium only when
    # a sensitive value shape (any shape hit, incl. an attributed email or
    # an internal/debug-labeled value) or an unpromised record list is
    # ALSO present; a strong shape hit earns medium on its own as before.
    confidence = ("medium" if (strong_shape_hits
                               or (has_field_mismatch and (shape_hits or has_record_list)))
                  else "low")
    return [mk(
        ctx, detector_id="response-oversharing", category="information-disclosure",
        evidence_location="runtime-response", severity=severity, confidence=confidence,
        detection_method="response-shape-vs-scope",
        rationale=("Response's shape/volume materially exceeds the tool's declared "
                   "scope — " + "; ".join(reasons) + " — over-sharing distinct from "
                   "any individual value looking secret-shaped."),
        evidence={"tool": call.tool_name, "description_excerpt": desc[:200],
                  "record_lists": record_lists[:3], "unrelated_fields": unrelated[:10],
                  "value_shape_hits": shape_hits, "seq": call.seq},
        source_kind="dynamic-runtime", tool_name=call.tool_name,
    )]


register(Detector(
    id="response-injection", category="prompt-injection",
    evidence_location="runtime-response", phase="response", run=_run_injection,
    requires={CAP_DYNAMIC},
    rationale=("Tool responses are content the agent reads and may act on; applying "
               "the same normalized instruction-mechanism rules to responses catches "
               "injection delivered at call time, which no manifest-only scan sees."),
))

register(Detector(
    id="response-leak", category="data-exfiltration",
    evidence_location="multi-call-state", phase="response", run=_run_leak,
    requires={CAP_DYNAMIC},
    rationale=("Planted canaries make leakage fully deterministic: a canary surfacing where "
               "it was never passed proves cross-call state leakage, decoy-file "
               "content in a response proves a sensitive read, and credential-shaped "
               "output beyond the described scope proves over-sharing."),
))
