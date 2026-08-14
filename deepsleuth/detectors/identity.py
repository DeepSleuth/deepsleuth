"""rule 5.7 — server-identity spoofing / tool shadowing.

Handshake serverInfo and tool names/descriptions are self-asserted. We flag:
* descriptions/names that assert this tool *is* or *replaces/overrides/shadows*
  a *different, named* entity — an identity-assertion verb whose OBJECT is a
  tool-shaped or server-shaped entity (v5-7: a sibling or quoted
  tool-identifier-shaped name, a naming token followed by tool / server /
  function / command / API / integration, or "the real/official/... X") — not a
  value, a mode, a string literal, text or a setting (parameter documentation),
  and not mere topical or lexical similarity between a server's own sibling
  tools (P1.2: two tools naturally sharing vocabulary about their own prior
  behavior, e.g. "replaces the old inline edit command", is benign and must
  not fire),
* duplicate tool names within one tool listing (a shadow of a sibling),
* impersonation lexicon in the declared identity (official/verified/system/…)
  inconsistent with the package/config identity (normalized so formatting-only
  differences, e.g. "System Monitor" vs. "system-monitor", do not misfire).
"""
from __future__ import annotations

import json
import os
import re
from typing import List, Optional

from ..context import ScanContext, contract_descriptions
from ..models import Finding
from .base import CAP_MANIFEST, Detector, register
from ._util import mk

# V3-2: a match is disqualified when the surrounding text marks the "other"
# reference as self-referential — a coordinator/orchestrator tool honestly
# describing itself as delegating to "the other tools in this (same) server/
# package/suite" is not a collision, it is an accurate description of its own
# multi-tool design. Only a reference to a genuinely distinct, foreign entity
# (no such self-referential qualifier nearby) counts.
SELF_REF = re.compile(
    r"\b(in|on|within|of|from)\s+(this|the\s+same)\s+"
    r"(server|tool|package|suite|toolkit|project|api|service|repo|repository|"
    r"codebase|application|app)\b|"
    r"\bits\s+own\b|\bitself\b|\bin-server\b|\bsame[- ]server\b",
    re.IGNORECASE)
# rule P0.9: "admin" and "core" are dropped — both are extremely common, entirely
# generic pieces of an honest server/package name ("core-utils-mcp",
# "admin-dashboard-server") and were the single largest source of the 20-of-60
# visibility-bench handshake-identity false positives.
IMPERSONATION = re.compile(
    r"\b(official|verified|trusted|authorized|genuine|canonical|system|internal|"
    r"root|builtin|first[- ]?party)\b", re.IGNORECASE)


def _norm_ident(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


# v3-2.6 — the tool's OWN schema property names and enum values: a quoted
# token that is one of them is the tool talking about its own parameters,
# never a different entity (consumed by the v5-7 object test below).
def _own_schema_tokens(c) -> set:
    toks: set = set()
    props = (c.input_schema or {}).get("properties") or {}
    if not isinstance(props, dict):
        return toks
    for pname, pspec in props.items():
        toks.add(_norm_ident(pname))
        if isinstance(pspec, dict):
            enums = pspec.get("enum")
            items = pspec.get("items") if isinstance(pspec.get("items"), dict) else {}
            for e in (enums if isinstance(enums, list) else []) + (
                    items.get("enum") if isinstance(items.get("enum"), list) else []):
                if isinstance(e, (str, int, float)):
                    toks.add(_norm_ident(str(e)))
    return {t for t in toks if t}


# ---------------------------------------------------------------------------
# v5-7 — shadowing needs a TOOL-SHAPED or SERVER-SHAPED OBJECT. A shadow
# verb followed by ANY quoted token, or by "the original <anything>", used
# to be an identity assertion; "replaces the original text with ...",
# "replaces every "TODO" marker", "overrides the `Content-Type` header" are
# parameter documentation — their object is a value, a mode, a string
# literal, text, or a setting. The verb's OBJECT (the noun phrase right
# after it; the subject for a passive; the antecedent for a pronoun object)
# must be an ENTITY:
#
# 1. a sibling tool of this listing, or a quoted tool-identifier-shaped
#    token that is not one of the tool's own parameters / enum values and is
#    not labelled as a parameter ("the `max_items` setting");
# 2. a token followed by "tool", "server", "function", "command", "API" or
#    "integration" as the HEAD of the phrase ("the filesystem server", "the
#    `git` tool", "another tool") — unless the token is a determiner or a
#    generic adjective, or the phrase is marked as the tool's own
#    predecessor ("the old inline edit command", "the legacy tool");
# 3. "the official / real / original / genuine ... X" where X is not a
#    value-class noun ("the original text", "the real path").
_SHADOW_VERB_RE = re.compile(
    r"\b(?:(?P<plain>replac\w+|overrid\w+|overrode|supersed\w+|shadow\w*|impersonat\w*|"
    r"take[s]?\s+the\s+place\s+of|take[s]?\s+precedence\s+over)|"
    r"(?P<claim>masquerad\w*(?:\s+as)?|pretend\w*\s+to\s+be|claim\w*\s+to\s+be)|"
    r"(?P<act>act\w*\s+as(?=\s+(?:the|a|an)\b)))", re.IGNORECASE)
_SHADOW_PARTICIPLE_RE = re.compile(
    r"^(?:replaced|overridden|superseded|shadowed|impersonated)$", re.IGNORECASE)
_SHADOW_PASSIVE_AUX_RE = re.compile(
    r"\b(?:is|are|was|were|be|been|being|gets?|got)\s+(?:(?:now|hereby|fully|entirely|"
    r"effectively|completely|always)\s+)?$", re.IGNORECASE)
_SHADOW_NOUN_PREP_RE = re.compile(r"^\s*(?:for|of)\s+", re.IGNORECASE)
_SHADOW_SELF_AGENT_RE = re.compile(r"^\s*by\s+(?:this|it)\b", re.IGNORECASE)
_SHADOW_SENT_BREAK_RE = re.compile(r"[.!?\n]")
_SHADOW_OBJ_END_RE = re.compile(
    r"[.!?;:\n,()]|\s[-–—]\s|\b(?:with|by|in|into|for|from|when|whenever|if|on|at|to|as|and|"
    r"or|but|so|that|which|while|unless|because|during|before|after|via|using|then|"
    r"is|are|was|were|will|can|should|must)\b", re.IGNORECASE)
_SHADOW_PRONOUN_OBJ_RE = re.compile(
    r"^\s*(?:it|them|that|those|these|that\s+one|the\s+latter|the\s+former)\b", re.IGNORECASE)
_SHADOW_QUOTED_RE = re.compile(r"[`\"'‘’“”]([^`\"'‘’“”]{2,60})[`\"'‘’“”]")
_SHADOW_ENTITY_NOUN = r"(?:tool|server|function|command|api|integration)"
_SHADOW_HEAD_RE = re.compile(
    r"(?P<token>[`\"'‘’“”]?[A-Za-z][A-Za-z0-9_.\-]*[`\"'‘’“”]?)\s+(?P<noun>"
    + _SHADOW_ENTITY_NOUN + r")s?(?:['’]s)?\s*$", re.IGNORECASE)
# the same token + entity-noun pair anywhere in a phrase (subject of a
# passive / antecedent of a pronoun object: the noun is followed by the
# rest of that clause, not by the end of the phrase)
_SHADOW_HEAD_ANY_RE = re.compile(
    r"(?P<token>[`\"'‘’“”]?[A-Za-z][A-Za-z0-9_.\-]*[`\"'‘’“”]?)\s+(?P<noun>"
    + _SHADOW_ENTITY_NOUN + r")s?\b", re.IGNORECASE)
# a passive whose agent is something OTHER than the described tool
# ("`a` is replaced by `b`") documents a substitution, not a shadowing
_SHADOW_FOREIGN_AGENT_RE = re.compile(
    r"^\s*by\s+(?!this\b|it\b|the\s+(?:new|current|present)\b|here\b)", re.IGNORECASE)
_SHADOW_OTHER_RE = re.compile(
    r"\b(?:another|(?:any\s+|all\s+|the\s+)?other)\s+(?:[a-z\-]+\s+){0,2}?(?:tool|server|"
    r"function|command|api|service|integration|version)s?\b", re.IGNORECASE)
_SHADOW_AUTHORITY_RE = re.compile(
    r"\bthe\s+(?:real|official|correct|genuine|authentic|original|authoritative|"
    r"legitimate)\s+(?P<x>[`\"'‘’“”]?[A-Za-z][\w.\-]*)", re.IGNORECASE)
# determiners and generic adjectives: "the X tool" names nothing with these
_SHADOW_GENERIC_TOKENS = frozenset({
    "the", "a", "an", "this", "that", "these", "those", "its", "their", "your", "our",
    "my", "any", "each", "every", "some", "same", "new", "own", "given", "specified",
    "selected", "current", "default", "main", "following", "above", "entire", "whole",
    "such", "certain", "particular", "specific", "respective", "relevant", "internal",
    "underlying", "standard", "regular", "normal", "basic", "generic", "simple",
    "native", "built-in", "builtin", "inline", "base", "core", "primary", "single",
    "whole", "local", "custom", "first", "last", "next", "target", "source", "named",
    "called", "listed", "registered", "available", "configured", "wrapped", "of",
})
# the tool's OWN predecessor: self-versioning, not a foreign entity
_SHADOW_VERSIONING_RE = re.compile(
    r"\b(?:old|older|previous|legacy|former|deprecated|earlier|prior|existing|outdated|"
    r"obsolete|v\d+(?:\.\d+)*)\b", re.IGNORECASE)
# value-class nouns: the object of ordinary parameter documentation
_SHADOW_VALUE_WORDS = frozenset({
    "parameter", "parameters", "argument", "arguments", "option", "options", "mode",
    "modes", "setting", "settings", "default", "defaults", "value", "values", "field",
    "fields", "flag", "flags", "config", "configuration", "text", "string", "strings",
    "content", "contents", "input", "inputs", "output", "outputs", "data", "file",
    "files", "path", "paths", "name", "names", "message", "messages", "line", "lines",
    "order", "format", "state", "behavior", "behaviour", "result", "results",
    "response", "request", "query", "number", "numbers", "date", "time", "id", "ids",
    "key", "keys", "entry", "entries", "record", "records", "item", "items", "list",
    "document", "documents", "image", "images", "selection", "version", "versions",
    "implementation", "method", "algorithm", "logic", "approach", "one", "ones",
    "source", "target", "destination", "location", "url", "link", "title", "label",
    "description", "body", "header", "headers", "row", "rows", "column", "columns",
    "table", "schema", "template", "layout", "style", "color", "size", "type",
    "language", "encoding", "prompt", "note", "notes", "array", "object", "element",
    "elements", "character", "characters", "word", "words", "paragraph", "section",
    "code", "snippet", "block", "cell", "sheet", "page", "node", "branch", "commit",
    "tag", "variable", "variables", "property", "properties", "attribute",
    "attributes", "marker", "markers", "placeholder", "placeholders", "token",
    "tokens", "pattern", "patterns", "prefix", "suffix", "timeout", "limit", "range",
})
_SHADOW_WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_'\-]*")


def _strip_quotes(tok: str) -> str:
    return (tok or "").strip("`\"'‘’“”")


def _entity_in_phrase(phrase: str, own_tokens: set, sibling_patterns, allow_generic_head: bool,
                      head_anywhere: bool = False) -> Optional[dict]:
    """The entity the noun phrase names, or None when it is a value, a
    mode, a string literal, text or a setting."""
    from .crosstool import _looks_like_quoted_tool_name
    # 1) a sibling of this listing / a quoted tool-identifier-shaped token
    for nm, pat in sibling_patterns:
        if pat.search(phrase):
            return {"kind": "sibling", "entity": nm}
    for q in _SHADOW_QUOTED_RE.finditer(phrase):
        tok = q.group(1).strip()
        if _norm_ident(tok) in own_tokens:
            continue  # the tool's own parameter or enum value
        after = _SHADOW_WORD_RE.match(phrase[q.end():].lstrip())
        before = _SHADOW_WORD_RE.findall(phrase[:q.start()])
        if after and after.group(0).lower() in _SHADOW_VALUE_WORDS:
            continue  # "the `max_items` setting"
        if before and before[-1].lower() in _SHADOW_VALUE_WORDS:
            continue  # "the option `max_items`"
        if _looks_like_quoted_tool_name(tok):
            return {"kind": "quoted-tool-identifier", "entity": tok}
    # 3) "the official / real / original X"
    am = _SHADOW_AUTHORITY_RE.search(phrase)
    if am:
        x = _strip_quotes(am.group("x")).lower()
        if x and x not in _SHADOW_VALUE_WORDS and _norm_ident(x) not in own_tokens:
            return {"kind": "authority-claim", "entity": am.group(0).strip()}
    # 2) "another / other tool", or a naming token + an entity noun as the head
    om = _SHADOW_OTHER_RE.search(phrase)
    if om:
        return {"kind": "other-entity", "entity": om.group(0).strip()}
    if allow_generic_head and not _SHADOW_VERSIONING_RE.search(phrase):
        heads = (list(_SHADOW_HEAD_ANY_RE.finditer(phrase)) if head_anywhere
                 else [m for m in [_SHADOW_HEAD_RE.search(phrase.rstrip(" \t"))] if m])
        for hm in heads:
            token = _strip_quotes(hm.group("token")).lower()
            lead = {w.lower() for w in _SHADOW_WORD_RE.findall(phrase[:hm.start("noun")])}
            if (token and token not in _SHADOW_GENERIC_TOKENS
                    and token not in _SHADOW_VALUE_WORDS
                    and _norm_ident(token) not in own_tokens
                    and not (lead & {"default", "defaults"})):
                return {"kind": "named-" + hm.group("noun").lower(),
                        "entity": (hm.group("token") + " " + hm.group("noun")).strip()}
    return None


def _shadow_assertion(text: str, own_tokens: set, sibling_patterns) -> Optional[dict]:
    """v5-7 — the first shadow-verb whose OBJECT is an entity, as
    ``{"match", "verb", "kind", "entity"}``; None when every shadow verb in
    the text governs a value / mode / literal / setting or is
    self-referential."""
    for vm in _SHADOW_VERB_RE.finditer(text):
        # sentence bounds
        sb = [m.end() for m in _SHADOW_SENT_BREAK_RE.finditer(text, 0, vm.start())]
        s_start = sb[-1] if sb else 0
        se = _SHADOW_SENT_BREAK_RE.search(text, vm.end())
        s_end = se.start() if se else len(text)
        window = text[max(0, vm.start() - 30):min(len(text), vm.end() + 90)]
        if SELF_REF.search(window):
            continue  # self-referential — not a collision with a foreign entity
        is_act = vm.group("act") is not None
        rest = text[vm.end():s_end]
        # the noun form takes its object after "for" / "of" ("a drop-in
        # replacement for the filesystem server")
        obj_text = _SHADOW_NOUN_PREP_RE.sub("", rest, count=1)
        cut = _SHADOW_OBJ_END_RE.search(obj_text)
        phrase = obj_text[:cut.start()] if cut else obj_text
        found = None
        verb_word = vm.group(0).split()[0]
        # passive: an auxiliary before the participle, or the participle
        # with the described tool as its agent ("now replaced by this one")
        passive = bool(_SHADOW_PARTICIPLE_RE.match(verb_word) and (
            _SHADOW_PASSIVE_AUX_RE.search(text[s_start:vm.start()])
            or _SHADOW_SELF_AGENT_RE.match(rest)))
        if passive or _SHADOW_PRONOUN_OBJ_RE.match(rest):
            # the entity is the passive subject / the pronoun's antecedent:
            # the part of the sentence before the verb. A passive whose
            # agent is something other than the described tool is a
            # substitution being documented, not a shadowing claim.
            if passive and _SHADOW_FOREIGN_AGENT_RE.match(rest):
                continue
            found = _entity_in_phrase(text[s_start:vm.start()], own_tokens, sibling_patterns,
                                      allow_generic_head=True, head_anywhere=True)
        elif phrase.strip():
            found = _entity_in_phrase(phrase, own_tokens, sibling_patterns,
                                      allow_generic_head=not is_act)
        if found:
            found.update({"match": text[vm.start():min(s_end, vm.end() + 80)].strip(),
                          "verb": vm.group(0)})
            return found
    return None


def _extract_package_name(ctx: ScanContext) -> Optional[str]:
    """rule P0.9: compare the handshake-declared name against the package's OWN
    declared name (package.json / pyproject.toml / setup.py) — the identity
    the maintainer actually gave the package — rather than an arbitrary alias
    key a user's mcp.json config happens to use for this server entry.
    Config aliases routinely differ from the real package name for entirely
    innocent reasons ("fs" for the Filesystem server, "work-slack", ...),
    which is what made the alias-based comparison fire on 20 of 60
    visibility-bench cases."""
    manifests = getattr(ctx, "package_manifests", None) or {}
    for path, text in sorted(manifests.items()):
        base = os.path.basename(path)
        try:
            if base == "package.json":
                data = json.loads(text)
                name = data.get("name") if isinstance(data, dict) else None
                if isinstance(name, str) and name.strip():
                    return name.strip()
            elif base == "pyproject.toml":
                m = re.search(r'(?m)^\s*name\s*=\s*["\']([^"\']+)["\']', text)
                if m:
                    return m.group(1)
            elif base == "setup.py":
                m = re.search(r'\bname\s*=\s*["\']([^"\']+)["\']', text)
                if m:
                    return m.group(1)
        except Exception:
            continue
    return None


def _listing_kind(ctx: ScanContext) -> str:
    return "dynamic-runtime" if "dynamic" in ctx.layers else "static-manifest"


def _run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    kind = _listing_kind(ctx)

    # duplicate tool names within the listing
    seen = {}
    for c in ctx.tools:
        seen.setdefault(c.name, 0)
        seen[c.name] += 1
    for name, n in sorted(seen.items()):
        if n > 1:
            out.append(mk(
                ctx, detector_id="tool-shadowing", category="tool-shadowing",
                evidence_location="name", severity="medium", confidence="medium",
                detection_method="name-collision",
                rationale=(f"Tool name '{name}' is declared {n} times in one listing "
                           "— a duplicate/shadowing name that can override a sibling."),
                evidence={"name": name, "count": n},
                source_kind=kind, tool_name=name,
            ))

    # shadow/replace assertions in name or description
    from .crosstool import _name_pattern, _sibling_names
    for c in ctx.all_contracts():
        # v3-4.3 — every duplicate definition's description is scanned too
        blob = "\n".join([c.name or ""] + contract_descriptions(c))
        own_tokens = _own_schema_tokens(c)
        # v5-7 — the verb's OBJECT must be a tool-shaped or server-shaped
        # entity (a sibling / quoted tool identifier, a naming token + tool /
        # server / function / command / API / integration, or "the official /
        # real / original X"); a value, a mode, a string literal, text or a
        # setting is parameter documentation.
        sibling_patterns = [(nm, _name_pattern(nm)) for nm in _sibling_names(ctx, c.name)]
        hit = _shadow_assertion(blob, own_tokens, sibling_patterns)
        if hit:
            out.append(mk(
                ctx, detector_id="tool-shadowing", category="tool-shadowing",
                evidence_location="description", severity="high", confidence="medium",
                detection_method="identity-assertion",
                rationale=("Tool metadata asserts it replaces/overrides/shadows "
                           "another tool or server — a shadowing/impersonation "
                           "mechanism that redirects the agent away from the real "
                           f"entity. The verb's object is an entity ({hit['kind']}: "
                           f"'{hit['entity']}'), not a value or a setting."),
                evidence={"tool": c.name, "match": hit["match"][:120],
                          "verb": hit["verb"], "entity_kind": hit["kind"],
                          "entity": hit["entity"],
                          "description_excerpt": c.description[:200]},
                source_kind=kind, tool_name=c.name,
            ))

    # declared server identity vs config/package identity
    if ctx.server_info and isinstance(ctx.server_info, dict):
        declared = str(ctx.server_info.get("name") or "")
        configured = (_extract_package_name(ctx) or ctx.target.server_name
                     or ctx.target.target_id or "")
        nd, nc = _norm_ident(declared), _norm_ident(configured)
        # only a real mismatch: configured identity known, and neither name is a
        # substring of the other once formatting is stripped (so "System Monitor"
        # vs "system-monitor" — the same identity, differently spelled — does not
        # misfire; only a genuinely different declared name does).
        same_identity = bool(nc) and (not nd or nd in nc or nc in nd)
        if declared and configured and IMPERSONATION.search(declared) and not same_identity:
            out.append(mk(
                ctx, detector_id="server-identity", category="tool-shadowing",
                evidence_location="server-identity", severity="medium",
                confidence="low", detection_method="handshake-identity-check",
                rationale=("Handshake serverInfo advertises an authority-claiming "
                           f"identity ('{declared}') that does not match the "
                           f"configured/package identity ('{configured}') — possible "
                           "identity spoofing."),
                evidence={"serverInfo_name": declared, "configured": configured},
                source_kind="dynamic-runtime", tool_name=None,
            ))

    out.extend(_config_identity_mismatch(ctx))
    return out


# v6-W4 -- configured-vs-served identity. A launch that came from a config
# entry (``mcp.json``: ``"mcpServers": {"<key>": {...}}``) carries the key the
# USER gave the server; the handshake's ``serverInfo.name`` is what the
# running code claims to be. The existing check above only looks at an
# authority-claiming spelling ("official", "system", ...); a server that
# simply answers as a DIFFERENT product than the one configured (a
# drop-in that was swapped under the entry, a typosquatted package launched
# by an innocent-looking key) slips past it. The check is deliberately a soft
# signal -- low severity, never actionable alone -- because aliases are
# ordinary ("fs" for the Filesystem server): medium confidence on a plain
# mismatch, low when the package's OWN manifest name matches the handshake
# (an honest alias for a correctly-named package).
_GENERIC_ID_TOKENS = frozenset({"mcp", "server", "servers", "the", "a", "my", "tool", "tools",
                                "service", "official", "npm", "py", "python", "node"})


def _id_tokens(s: str) -> set:
    return {t for t in re.split(r"[^a-z0-9]+", (s or "").lower())
            if t and t not in _GENERIC_ID_TOKENS}


def _same_server_identity(a: str, b: str) -> bool:
    na, nb = _norm_ident(a), _norm_ident(b)
    if not na or not nb:
        return True          # one side unknown: not a mismatch
    if na == nb or na in nb or nb in na:
        return True
    ta, tb = _id_tokens(a), _id_tokens(b)
    return bool(ta and tb and (ta & tb))


def _config_identity_mismatch(ctx: ScanContext) -> List[Finding]:
    key = getattr(ctx.target, "config_entry", None)
    if not key or not isinstance(ctx.server_info, dict):
        return []
    declared = str(ctx.server_info.get("name") or "").strip()
    if not declared or _same_server_identity(key, declared):
        return []
    pkg = _extract_package_name(ctx)
    alias_of_package = bool(pkg and _same_server_identity(pkg, declared))
    return [mk(
        ctx, detector_id="server-identity", category="tool-shadowing",
        evidence_location="server-identity", severity="low",
        confidence="low" if alias_of_package else "medium",
        detection_method="config-identity-mismatch",
        rationale=(f"The server was launched from config entry '{key}' but its handshake "
                   f"serverInfo.name is '{declared}' -- the running code identifies as "
                   "a different server than the one configured."
                   + (f" The package's own manifest name ('{pkg}') matches the handshake, "
                      "so this is most likely an ordinary alias key." if alias_of_package
                      else " Verify the entry still launches what you configured.")),
        evidence={"configured_key": key, "serverInfo_name": declared,
                  "package_name": pkg or "", "alias_of_package": alias_of_package,
                  "colliding_key": f"config-key:{key}"},
        source_kind="dynamic-runtime", tool_name=None,
        raw={"config_identity": True},
    )]


register(Detector(
    id="server-identity", category="tool-shadowing", evidence_location="server-identity",
    phase="listing", run=_run, requires={CAP_MANIFEST},
    rationale=("Declared identity and namespaces are self-asserted and can imitate a "
               "trusted server or shadow another tool; detecting identity-assertion "
               "plus reference-to-another-entity catches impersonation without keying "
               "on any specific victim name."),
))
