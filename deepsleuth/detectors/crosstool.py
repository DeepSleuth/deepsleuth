"""rule P1 — structure rules for descriptions/schemas that reach OUTSIDE the tool's
own contract (1.1, 1.2, 1.6 of the improvement guide).

The scanner's own design principle is that a description describes its own
tool. Three ways a description contradicts that contract, purely structurally
— no hardcoded tool/server names or payload strings, only the server's own
live sibling-tool list (already on ``ctx`` — rule 1.8; both frontends populate
``ctx.tools`` before any detector runs, so a poisoned tool is always scanned
*among* its siblings, never alone) and closed, generic vocabularies of
obligation/invoke/tamper words:

1.1 Cross-tool call rule — a sentence names a SIBLING tool (from this same
    listing) plus an obligation/sequence word (must, always, before, after,
    when, first, ...) plus an invoke verb (call, use, run, execute, ...). A
    tool's own description has no legitimate reason to direct the agent
    toward invoking a *different*, specifically-named tool — that is the
    sibling's own job to describe about itself.

1.2 Parameter-tampering rule — the same sentence-with-a-sibling-name test,
    but with a tamper verb (modify, change, set, replace, append, redirect,
    ...) plus an argument-word or a quoted literal. One tool's contract has
    no authority over another tool's arguments.

1.6 Out-of-scope parameter — a schema parameter whose name or description
    asks the CALLER (the agent) for information about its own context: the
    invoking model's name/identity, its system prompt, its conversation
    history, or its own tool list. That is backwards — a tool takes domain
    inputs, not caller-identity harvesting fields. Raised to high when the
    bound source shows the parameter is never referenced in the function body
    at all (``BehaviorFacts.unused_params``, rule P1.6/pyast.py).
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import Dict, List, Optional

from ..analysis.pyast import _split_ident_tokens
from ..analysis.textrules import SENSITIVE as _SENSITIVE_RAW
from ..analysis.textrules import _clauses, output_substitution_hits
from ..context import (ScanContext, ToolContract, contract_descriptions,
                       listing_entry_strings, listing_path_under_schema,
                       step_down_confidence)
from ..models import Finding
from .base import CAP_MANIFEST, Detector, register
from ._util import mk

_TEXTRULES_SENSITIVE_RX = re.compile(_SENSITIVE_RAW, re.IGNORECASE)

# ---------------------------------------------------------------------------
# sibling-name discovery (rules 1.1/1.8) — purely structural: read from the live
# listing already on ctx, never a hardcoded name. Short/common names are
# skipped so an ordinary word ("get", "list", "run") occurring in someone
# else's honest prose is never misread as "naming a sibling tool".

_COMMON_WORDS = frozenset({
    "get", "set", "run", "call", "use", "the", "and", "for", "with", "this",
    "that", "list", "data", "file", "path", "name", "type", "value", "item",
    "user", "note", "tool", "step", "then", "when", "must", "true", "false",
    "none", "self", "args", "info", "text", "json", "http", "url", "key",
    "read", "write", "search", "query", "fetch", "load", "save", "check",
    "test", "main", "index", "reply",
})


def _sibling_names(ctx: ScanContext, self_name: str) -> List[str]:
    seen = set()
    out: List[str] = []
    for c in ctx.all_contracts():
        nm = (c.name or "").strip()
        if not nm or nm == self_name or nm.lower() == (self_name or "").lower():
            continue
        if len(nm) < 4 or nm.lower() in _COMMON_WORDS:
            continue
        if nm.lower() in seen:
            continue
        seen.add(nm.lower())
        out.append(nm)
    return out


_QUOTE_CHARS = "\"'`‘’“”"


def _is_single_word_name(name: str) -> bool:
    """v3-2.2 — structural test: a sibling name that is ONE bare token (no
    ``_``/``-``/``.`` separator, no camelCase boundary) reads as an ordinary
    dictionary word in prose ("summarize", "search", "translate"), so a bare
    occurrence of it is not evidence the sentence names the TOOL."""
    return len(_split_ident_tokens(name)) < 2


@lru_cache(maxsize=16384)
def _name_pattern(name: str) -> re.Pattern:
    """rule 1.4 — whole-IDENTIFIER match of a sibling tool name inside prose: the
    literal identifier only, hyphen treated as part of the name (not a word
    boundary). The prior version also opened ``_``/``-`` separators into
    spaces so prose referring to ``get_user_info`` as "get user info" still
    matched — dropped on purpose (rule 1.4): an ordinary English phrase that
    merely happens to share the same words in the same order as a sibling's
    identifier ("get user info" used generically, unrelated to the tool) is
    not evidence the sentence is actually about that sibling. The spaced
    prose form is only ever matched when the name occurs QUOTED (handled
    separately by the quoted-name mode, which requires an explicit
    identifier shape on the quoted token itself).

    v3-2.2 — a SINGLE-WORD sibling name (no separator, no camelCase) only
    matches when it is quoted/backticked or adjacent to the word "tool"
    (``the `search` tool``, ``tool named search``): a bare dictionary word
    used as a verb/noun in ordinary prose is not a reference to the tool."""
    esc = re.escape(name)
    if _is_single_word_name(name):
        q = "[" + _QUOTE_CHARS + "]"
        return re.compile(
            r"(?:" + q + r"\s*" + esc + r"\s*" + q + r")"
            r"|(?:\b" + esc + r"\s+tool\b)"
            r"|(?:\btool\s+(?:called\s+|named\s+)?" + q + r"?" + esc + r"\b)",
            re.IGNORECASE)
    return re.compile(r"\b" + esc + r"\b", re.IGNORECASE)


def _clauses_naming_siblings(text: str, sibling_names: List[str]):
    """Yield (clause, sibling_name) for every clause in ``text`` that names a
    sibling tool."""
    if not text or not sibling_names:
        return
    patterns = [(nm, _name_pattern(nm)) for nm in sibling_names]
    for clause in _clauses(text):
        for nm, pat in patterns:
            if pat.search(clause):
                yield clause, nm


# ---------------------------------------------------------------------------
# rule 1.1 cross-tool call rule

# rule 1.1 — the broad "any obligation or sequence word" set. On its own (with an
# invoke verb) this is only enough for the INFORMATIONAL "workflow reference"
# tier (rule 1.1) — a sentence naming a sibling tool with a plain sequence word
# ("before"/"after"/"when"/"then"/"first") is honest workflow advice far more
# often than an attack (measured: requiring only this dropped ~4 of every 5
# real-server flags relative to a strong-word-gated version). Escalating to
# the actionable tier additionally requires _STRONG_OBLIGATION_RX, a threat
# of failure, a sensitive target, or (rule 1.2) the "conditions on a different
# tool" direction.
_OBLIGATION_RX = re.compile(
    r"\b(must|always|never|mandatory|required?|need(?:s)?\s+to|have\s+to|should|"
    r"before|after|first|prior\s+to|once|when(?:ever)?|then)\b", re.IGNORECASE)
# rule 1.5 — inflected verb forms (calling/using/invoking/running), actionable
# tier only: the base-form-only list under-matched an extremely common real
# phrasing ("when calling export_report...", "before invoking send_alert...").
_INVOKE_RX = re.compile(
    r"\b(call(?:s|ing|ed)?|invok(?:e|es|ed|ing)|run(?:s|ning)?|"
    r"execut(?:e|es|ed|ing)|us(?:e|es|ed|ing)|trigger(?:s|ed|ing)?)\b",
    re.IGNORECASE)

# rule 1.1 — actionable-tier gate: a STRONG obligation word only (must/always/
# never/mandatory/required) — the narrow B-grade from the improvement guide's
# own measurement table, which alone keeps ~75% of the benchmark's real
# hijack recall while cutting real-server false flags by about 5x relative to
# the broad any-sequence-word grading above.
_STRONG_OBLIGATION_RX = re.compile(
    r"\b(must|always|never|mandatory|required?)\b", re.IGNORECASE)
# a threat that skipping the named step causes failure/breakage — a forceful
# signal structurally distinct from a strong obligation word, but just as
# decisive: honest workflow advice essentially never frames itself as "or
# this call will fail/break/error".
_THREAT_RX = re.compile(
    r"\b(otherwise|unless (you|this|it))\b[^.!?\n]{0,30}\b(fail\w*|error\w*|"
    r"break\w*|crash\w*|reject\w*|not\s+work|malfunction\w*|corrupt\w*)\b|"
    r"\b(will|would|may|might)\b[^.!?\n]{0,20}\b(fail\w*|break\w*|error\w*|"
    r"crash\w*|reject\w*|malfunction\w*|not\s+work)\b",
    re.IGNORECASE)
# rule 1.2 — direction: a clause CONDITIONS on the sibling ("when/while/once you
# use/call/invoke X, ...") and prescribes an action — graded higher (counts
# toward the actionable tier on its own) than the mirror shape where the
# sibling is merely the target of a precondition on THIS tool's own use
# ("before using this tool, call X" — a prerequisite of the tool itself,
# still actionable when paired with a strong word/threat/sensitive target,
# but the direction itself is not independently decisive).
# v3-2.1 — direction test: the conditioning word must be DIRECTLY followed
# by "you"/"the agent" or an invoke verb (at most two intervening words
# after "you"), with "at once", "all at once" and "once more" excluded —
# those are adverbial idioms, not a condition on the other tool's use.
_CONDITIONS_ON_OTHER_RX = re.compile(
    r"(?<!\bat\s)(?<!\ball\sat\s)\b(when(?:ever)?|while|once)\b(?!\s+more\b)\s+"
    r"(?:(?:you|the\s+agent|the\s+assistant|the\s+model)\s+(?:\w+\s+){0,2})?"
    r"(call(?:s|ing|ed)?|invok(?:e|es|ed|ing)|us(?:e|es|ed|ing)|run(?:s|ning)?|"
    r"execut(?:e|es|ed|ing)|trigger(?:s|ed|ing)?)\b",
    re.IGNORECASE)
# v3-2.3 — a threat of failure escalates a sibling reference only when it
# sits in the SAME dash/semicolon-delimited sub-clause as the reference: a
# sentence like "call X for a copy - note: large exports may fail" carries
# its threat in a separate aside, not as coercion attached to the call.
_SUBCLAUSE_SPLIT = re.compile(r"\s+[-–—]+\s+|[–—]+|;")
# v3-2.4 — "add"/"include"/"insert" count as invoke verbs ONLY when their
# object is a tool-shaped identifier AND the clause names a plan/response/
# call list/next step — the shape of "add a call to X to your plan", never
# "add a title field to the response".
_ADD_VERB_RX = re.compile(
    r"\b(add(?:s|ed|ing)?|includ(?:e|es|ed|ing)|insert(?:s|ed|ing)?)\b", re.IGNORECASE)
_PLAN_NOUN_RX = re.compile(
    r"\b(plans?|responses?|repl(?:y|ies)|outputs?|answers?|call\s+lists?|"
    r"list\s+of\s+calls|tool\s+calls?|calls|next\s+steps?|sequence|workflow|"
    r"chain|pipeline|queue)\b", re.IGNORECASE)


def _threat_near_sibling(clause: str, pat: re.Pattern) -> bool:
    for sub in _SUBCLAUSE_SPLIT.split(clause):
        if pat.search(sub) and _THREAT_RX.search(sub):
            return True
    return False


def _invoke_in_clause(clause: str, pat: re.Pattern, name: str) -> bool:
    """v3-2.4 — an ordinary invoke verb anywhere in the clause, OR an add/
    include/insert verb whose object (within a short window) is the
    tool-shaped sibling name while the clause names a plan/response/call
    list/next step."""
    if _INVOKE_RX.search(clause):
        return True
    if _is_single_word_name(name) or not _PLAN_NOUN_RX.search(clause):
        return False
    for m in _ADD_VERB_RX.finditer(clause):
        if pat.search(clause[m.end():m.end() + 40]):
            return True
    return False

# rule 1.1 — a sensitive target inside the clause (a secret-shaped reference, or
# the sibling's OWN name carrying a sensitive-action token) is itself a
# forceful-enough signal to actionable-grade a redirect, independent of
# obligation wording — "call delete_all_records" is worth flagging even
# phrased as a mild suggestion.
_SENSITIVE_TARGET_TOKENS = frozenset({
    "delete", "deletes", "deleting", "remove", "removes", "removing", "drop",
    "wipe", "wipes", "purge", "purges", "admin", "payment", "payments",
    "transfer", "transfers", "wire", "credential", "credentials", "password",
    "passwords", "secret", "secrets", "key", "keys", "auth", "root", "sudo",
    "grant", "revoke", "permission", "permissions", "refund", "refunds",
    "withdraw", "withdrawal",
})

# rule 1.2 parameter-tampering rule. rule 1.5 adds the missing tamper verbs (add/
# insert/inject/remove/prepend, inflected).
_TAMPER_RX = re.compile(
    r"\b(modif(?:y|ies|ied|ying)|chang(?:e|es|ed|ing)|set|replac(?:e|es|ed|ing)|"
    r"append(?:s|ed|ing)?|redirect(?:s|ed|ing)?|overwrit(?:e|es|ing|ten)|"
    r"alter(?:s|ed|ing)?|add(?:s|ed|ing)?|insert(?:s|ed|ing)?|"
    r"inject(?:s|ed|ing)?|remov(?:e|es|ed|ing)?|prepend(?:s|ed|ing)?)\b",
    re.IGNORECASE)
_ARG_WORD_RX = re.compile(
    r"\b(argument|arguments|parameter|parameters|value|values|field|fields|input|inputs)\b",
    re.IGNORECASE)
_QUOTED_RX = re.compile(r"[\"'`‘’“”][^\"'`‘’“”]{1,60}[\"'`‘’“”]")


def _listing_kind(ctx: ScanContext) -> str:
    return "dynamic-runtime" if "dynamic" in ctx.layers else "static-manifest"


# rule P1.1 false-positive carve-out — the improvement guide names a specific
# honest idiom that is structurally IDENTICAL to a hijack redirect: a
# session-based server's other tools honestly saying "you must call
# start_session before using any other tool in this server". The generic
# target of "before" here is "any other tool" (a blanket precondition on the
# whole server), never a *specific* different tool or "this tool" — that is
# what distinguishes a genuine one-time session/init bootstrap requirement
# from a redirect that steers the agent away from THIS tool's own proper use
# toward a specific different action. Narrow on purpose: it only silences the
# "any/all other tool(s)" generic-target shape, not "before using this tool"
# or a specific second target.
_SAFE_PRECONDITION_RX = re.compile(
    r"\bbefore\b[^.!?\n]{0,20}\b(using|calling|invoking)\b[^.!?\n]{0,10}"
    r"\b(any|all)\s+other\s+tools?\b", re.IGNORECASE)


def _has_sensitive_target(clause: str, name: str) -> bool:
    """rule 1.1 — the clause references a secret-shaped store/value, OR the
    named tool itself carries a sensitive-action token (delete/admin/
    payment/credential/...) in its own identifier."""
    if _TEXTRULES_SENSITIVE_RX.search(clause):
        return True
    return bool(set(_split_ident_tokens(name)) & _SENSITIVE_TARGET_TOKENS)


def _direction_conditions_on_other(clause: str, pat: re.Pattern) -> bool:
    """rule 1.2 — True when the clause is shaped "when/while/once you
    call/use/invoke/run <NAME>, <do something>": the sibling/named tool is
    the CONDITION and an action is prescribed off the back of it. Distinct
    from (and graded higher than) the mirror shape where the named tool is
    merely the object of a precondition on using THIS tool
    ("before using this tool, call X")."""
    m = _CONDITIONS_ON_OTHER_RX.search(clause)
    if not m:
        return False
    return bool(pat.search(clause[m.start():m.end() + 40]))


def _actionable_reason(clause: str, name: str, pat: re.Pattern,
                       other_props: frozenset = frozenset(),
                       own_props: frozenset = frozenset(),
                       strong_governs: Optional[bool] = None) -> str:
    """Return the reason string if this clause clears the ACTIONABLE bar
    (rule 1.1: a strong obligation word, a threat of failure, a sensitive
    target, a tamper verb with a literal value aimed at the other tool, or
    the "conditions on a different tool" direction), else "".

    v3-2.7 — the tamper-verb-with-literal reason is "aimed at the other
    tool" only when the literal names a property of the SIBLING's schema;
    a literal that is one of THIS tool's own parameters describes its own
    modes. With no schema for the named tool (quoted-name mode) the literal
    still counts unless it is an own parameter.

    v5-3 — ``strong_governs`` is the caller's verdict on whether a strong
    obligation word is an obligation on a CALL of the named tool
    (``_strong_word_governs``: the object test or the direct chain); the
    cross-tool call rule always passes it.
    ``None`` keeps the "any strong word in the clause" test for the
    parameter-tampering callers, whose verb is a tamper verb."""
    if strong_governs is None:
        strong_governs = bool(_STRONG_OBLIGATION_RX.search(clause))
    if strong_governs:
        return "strong-obligation-word"
    if _threat_near_sibling(clause, pat):
        return "threat-of-failure"
    if _has_sensitive_target(clause, name):
        return "sensitive-target"
    if _TAMPER_RX.search(clause) and _QUOTED_RX.search(clause):
        named = _argument_names_in_clause(clause) - {_normalize_ident(name)}
        own_only = bool(own_props) and bool(named & own_props) and not (named & other_props)
        if not own_only and (not other_props or (named & other_props)):
            return "tamper-verb-with-literal-value"
    if _direction_conditions_on_other(clause, pat):
        return "conditions-on-other-tool"
    return ""


# v4-7 — in a FORCEFUL clause (a strong obligation word) the sibling may
# be the direct object of ANY verb, not only one from the closed invoke
# list: "you must always prefer X", "agents must consult the X tool first",
# "never skip X". Structural test, no tagger: the word directly before the
# sibling (allowing one article/determiner and the word "tool" in between)
# is the candidate verb; it is accepted only when it is not a closed-class
# word (determiner, preposition, conjunction, pronoun, adverb, auxiliary,
# naming participle such as "called"/"named") AND it stands in verb
# position itself — clause-initial, or right after a modal / strong word /
# "to" / "and" / subject pronoun (skipping a closed adverb set) — so an
# adjective between the article and the name ("the legacy X format") never
# passes. Actionable tier only; the informational tier keeps the closed
# invoke list.
_NOT_A_VERB = frozenset({
    "the", "a", "an", "this", "that", "these", "those", "its", "your", "their",
    "our", "my", "his", "her", "each", "every", "any", "all", "some", "no",
    "both", "either", "neither", "such", "same", "other", "another",
    "of", "to", "from", "by", "with", "in", "on", "at", "for", "into", "onto",
    "via", "through", "after", "before", "during", "until", "than", "as",
    "like", "unlike", "about", "over", "under", "between", "within", "without",
    "against", "toward", "towards", "per", "across", "along", "except",
    "including", "excluding", "regarding", "concerning", "versus", "vs",
    "and", "or", "but", "nor", "so", "yet", "if", "unless", "when", "whenever",
    "while", "once", "then", "because", "although", "though", "whether",
    "you", "it", "they", "we", "he", "she", "i", "me", "him", "them", "us",
    "who", "which", "what", "whom", "whose",
    "also", "only", "just", "always", "never", "first", "last", "next", "now",
    "already", "still", "even", "not", "too", "very", "really", "simply",
    "directly", "immediately", "instead", "rather", "otherwise", "however",
    "therefore", "thus", "here", "there", "again", "ever", "later", "earlier",
    "must", "should", "shall", "will", "would", "can", "could", "may", "might",
    "be", "been", "being", "is", "are", "was", "were", "am", "do", "does",
    "did", "has", "have", "had", "having",
    "called", "named", "labelled", "labeled", "titled", "dubbed", "termed",
    "see", "etc", "tool", "tools", "mandatory", "required", "require",
})
_OBJECT_LEADERS = frozenset({"the", "a", "an", "this", "that", "its", "your",
                             "our", "their", "tool"})
_VERB_POSITION_BEFORE = frozenset({
    "must", "always", "never", "should", "shall", "will", "would", "can",
    "could", "may", "might", "to", "and", "then", "or", "you", "agent",
    "agents", "assistant", "model", "it", "they", "please", "do", "not",
    "required", "mandatory", "also",
})
_VERB_POSITION_SKIP = frozenset({
    "first", "then", "also", "immediately", "directly", "explicitly", "only",
    "just", "simply", "manually", "now", "still", "again", "strictly",
    "unconditionally", "always", "never",
})
_WORD_RX = re.compile(r"[A-Za-z][A-Za-z'\-]*")
_CLAUSE_PUNCT_RX = re.compile(r"[,.;:()\[\]!?]")


def _sibling_verb_objects(clause: str, pat: re.Pattern):
    """Yield (verb, verb_start, verb_end) for every mention of the sibling
    that is the direct object of a verb standing in verb position."""
    for m in pat.finditer(clause):
        words = [(w.start(), w.end(), w.group(0).lower())
                 for w in _WORD_RX.finditer(clause[:m.start()])]
        i = len(words) - 1
        skipped = 0
        while i >= 0 and words[i][2] in _OBJECT_LEADERS and skipped < 2:
            i -= 1
            skipped += 1
        if i < 0:
            continue
        v_start, v_end, verb = words[i]
        if len(verb) < 3 or verb in _NOT_A_VERB:
            continue
        if _CLAUSE_PUNCT_RX.search(clause[v_end:m.start()]):
            continue
        # verb position: clause-initial, or after a modal/strong word/"to"/
        # "and"/subject pronoun, skipping a closed adverb set
        j = i - 1
        while j >= 0 and words[j][2] in _VERB_POSITION_SKIP:
            j -= 1
        if j >= 0 and _CLAUSE_PUNCT_RX.search(clause[words[j][1]:v_start]):
            j = -1
        if j < 0 or words[j][2] in _VERB_POSITION_BEFORE:
            yield verb, v_start, v_end


def _sibling_as_verb_object(clause: str, pat: re.Pattern) -> Optional[str]:
    for verb, _v_start, _v_end in _sibling_verb_objects(clause, pat):
        return verb
    return None


# ---------------------------------------------------------------------------
# v5-3 — the strong obligation word must GOVERN the invoke verb whose
# object is the sibling. A strong word anywhere in the clause used to
# escalate any sibling reference with an invoke verb in it; "the value must
# match the format used by X" and "always returns what X produced when it
# was last run" carry a strong word that governs a DIFFERENT verb (match,
# returns) and merely mention X. Two routes decide it (``_strong_word_
# governs``): the OBJECT TEST of the next block — is the sibling the object
# of a call the strong word is an obligation on, wherever the strong word
# stands — and the DIRECT CHAIN of this block, the original ordering test,
# kept for the sibling that follows a strong-word-governed invoke verb as a
# complement rather than as its object ("must use this tool INSTEAD OF X",
# "must be used BEFORE X"). The direct chain, structurally (no tagger):
#
# * ACTIVE — the strong word, then its GOVERNED SLOT, then the sibling. The
#   governed slot is the first word after the strong word that is not
#   transparent (a closed set of adverbs / "to" / "be" / "not" / an agent
#   subject, any "-ly" adverb); it must be the invoke verb (or, on the
#   v4-7 route, the very verb whose direct object is the sibling). An
#   ADJUNCT in between — a subordinator (before, after, when, ...) up to
#   the next comma: "must, before answering, call X" — and, after
#   "required"/"mandatory", a short LABEL up to a colon/dash ("Mandatory
#   step: call X") are stepped over; any other word in the slot is the verb
#   or noun the strong word really governs, and the reference stays
#   informational. Between the governed verb and the sibling there must be
#   no finite auxiliary/modal (a new finite clause), and the sibling must
#   not be a PROVENANCE object ("the id returned BY X", "the output OF X",
#   "the value used IN X") or a comparison ("unlike X").
# * PASSIVE — the sibling, then the strong word, then "be" + an invoke
#   participle ("X must always be called first").
# * PREDICATE — the sibling, then "is required" / "is mandatory"
#   ("calling X first is mandatory").
_GOV_TOKEN_RX = re.compile(r"[A-Za-z][A-Za-z'\-]*|[,;:()\[\]–—]|\s-\s")
_GOV_SKIP_PUNCT = frozenset({",", ":", "-", "–", "—", "(", ")", "[", "]"})
_GOV_TRANSPARENT = frozenset({
    "to", "be", "not", "that", "you", "we", "they", "the", "agent", "agents",
    "assistant", "assistants", "model", "models", "llm", "ai", "caller", "client",
    "please", "have", "has", "first", "then", "also", "always", "never", "only",
    "just", "now", "still", "again", "ever", "instead", "either", "both",
})
_GOV_SUBORDINATORS = frozenset({
    "before", "after", "when", "whenever", "while", "once", "prior", "upon", "if",
    "during", "until", "unless", "without", "whether", "for", "in", "on", "at",
    "as", "with",
})
_GOV_FINITE = frozenset({
    "is", "are", "was", "were", "am", "has", "had", "have", "does", "do", "did",
    "will", "would", "can", "could", "may", "might", "should", "shall", "must",
})
_GOV_PROVENANCE = frozenset({"by", "from", "of", "in", "inside", "within",
                             "unlike", "like", "as"})
# "instead of X" / "in place of X" / "ahead of X" are not provenance
_GOV_OF_HEADS = frozenset({"instead", "place", "lieu", "favor", "favour", "ahead", "top"})
_GOV_LABEL_STRONG = frozenset({"required", "require", "mandatory"})
_GOV_LABEL_END = frozenset({":", "-", "–", "—"})
_GOV_PASSIVE_RX = re.compile(
    r"^[\s\"'`‘’“”]{0,3}(?:tool\s+)?(?:(?:should|shall|will|is|are|needs?|has|have|to)\s+)"
    r"{0,2}(?:must|always|never)\s+(?:(?:always|never|first|also|then|only|not|be)\s+)"
    r"{0,3}(?:called|invoked|run|executed|used|triggered)\b", re.IGNORECASE)
_GOV_PREDICATE_RX = re.compile(
    r"^[\s\"'`‘’“”]{0,3}(?:tool\s+)?(?:(?:first|beforehand|afterwards?)\s+)?(?:is|are)\s+"
    r"(?:(?:always|strictly|absolutely|also)\s+)?(?:required|mandatory)\b", re.IGNORECASE)


def _governed_verb(clause: str, s_end: int, is_target, label_ok: bool):
    """The (start, end) of the target verb standing in the governed slot of
    the strong word that ends at ``s_end``, or None."""
    toks = [(m.start(), m.end(), m.group(0).strip().lower())
            for m in _GOV_TOKEN_RX.finditer(clause, s_end)]
    i = 0
    adjuncts = 0
    while i < len(toks):
        start, end, w = toks[i]
        if not w[:1].isalpha():
            if w in _GOV_SKIP_PUNCT:
                i += 1
                continue
            return None
        if is_target(w):
            return start, end
        if w in _GOV_TRANSPARENT or (len(w) > 4 and w.endswith("ly")):
            i += 1
            continue
        if w in _GOV_SUBORDINATORS:
            # an adjunct runs to the next comma; the governed verb follows it
            j = next((k for k in range(i + 1, len(toks)) if toks[k][2] == ","), None)
            if j is None or adjuncts >= 2:
                return None
            adjuncts += 1
            i = j + 1
            continue
        if label_ok:
            j = next((k for k in range(i, min(len(toks), i + 4))
                      if toks[k][2] in _GOV_LABEL_END), None)
            if j is not None:
                label_ok = False
                i = j + 1
                continue
        return None
    return None


def _provenance_object(clause: str, m_start: int) -> bool:
    """The sibling mention is the object of a provenance/comparison
    preposition ("returned BY X", "the output OF X", "unlike X")."""
    words = [w.group(0).lower() for w in _WORD_RX.finditer(clause[:m_start])]
    i = len(words) - 1
    skipped = 0
    while i >= 0 and words[i] in _OBJECT_LEADERS and skipped < 2:
        i -= 1
        skipped += 1
    if i < 0 or words[i] not in _GOV_PROVENANCE:
        return False
    if words[i] == "of" and i >= 1 and words[i - 1] in _GOV_OF_HEADS:
        return False
    return True


def _strong_word_chain(clause: str, pat: re.Pattern, name: str = "",
                       verb_object_only: bool = False) -> bool:
    """v5-3 DIRECT CHAIN — True when a strong obligation word of the clause
    governs the invoke verb and the sibling follows it (see the block
    comment above). One of the two routes of ``_strong_word_governs``."""
    mentions = [(m.start(), m.end()) for m in pat.finditer(clause)]
    if not mentions:
        return False
    # passive / predicate: the sibling is the subject
    for m_start, m_end in mentions:
        if _provenance_object(clause, m_start):
            continue
        rest = clause[m_end:]
        if _GOV_PASSIVE_RX.match(rest) or _GOV_PREDICATE_RX.match(rest):
            return True
    add_ok = (bool(name) and not _is_single_word_name(name)
              and bool(_PLAN_NOUN_RX.search(clause)))
    verb_objects = {v_start: verb for verb, v_start, _e in _sibling_verb_objects(clause, pat)}

    def target(w: str) -> bool:
        if not verb_object_only and (
                _INVOKE_RX.fullmatch(w) or (add_ok and _ADD_VERB_RX.fullmatch(w))):
            return True
        return w in verb_objects.values()

    for sm in _STRONG_OBLIGATION_RX.finditer(clause):
        gv = _governed_verb(clause, sm.end(), target,
                            sm.group(0).lower() in _GOV_LABEL_STRONG)
        if gv is None:
            continue
        v_start, v_end = gv
        word = clause[v_start:v_end].lower()
        is_invoke = (not verb_object_only) and bool(
            _INVOKE_RX.fullmatch(word) or (add_ok and _ADD_VERB_RX.fullmatch(word)))
        if not is_invoke and verb_objects.get(v_start) != word:
            continue  # the same verb word, but not the one whose object is the sibling
        for m_start, _m_end in mentions:
            if m_start < v_end:
                continue
            between = [w.group(0).lower() for w in _WORD_RX.finditer(clause[v_end:m_start])]
            if set(between) & _GOV_FINITE:
                continue
            if _provenance_object(clause, m_start):
                continue
            return True
    return False


# ---------------------------------------------------------------------------
# v5-3 refinement — OBJECT TEST. The direct chain above ("strong word, then
# the invoke verb, then the sibling") is an ORDERING test, and too narrow: it
# demotes a forceful redirect whose strong word governs another verb on the
# way to the call ("you must first verify the account by calling X", "always
# make sure to run X") or follows the call ("calling X before answering is
# mandatory", "run X first - this step is mandatory"). The object test asks
# what the sibling IS in the clause, not where the strong word stands:
#
# * CALL SITE — the sibling is the DIRECT OBJECT of an invoke verb: the verb
#   stands immediately before the name, with only an article / determiner /
#   the word "tool" or "function" / a quote character in between (a sibling
#   coordinated with such an object, "call A and X", and the nominal form
#   "make a call to X" count too); or the sibling is the SUBJECT of an
#   obligation passive ("X must be called", "X is to be run first"; a plain
#   passive only under an "ensure" head: "make sure X is called"). A
#   sibling that is only inside a prepositional, participial or relative
#   phrase ("the value used IN X", "the id returned BY X", "what X
#   produced") has no call site and stays informational.
# * The call must be PRESCRIBED, not somebody else's, nor the circumstance
#   or the provenance of something else: an invoke verb that heads a
#   condition / purpose / comparison adjunct ("WHEN using X", "the
#   arguments FOR calling X", "TO use X, ...", "the token needed TO call
#   X"), a "by / after calling X" that hangs off a noun-modifying
#   participle ("the one obtained BY calling X"), and a call with a
#   third-party subject ("so the server can call X") are not calls the
#   sentence orders. A call after "before / until / unless" is a
#   prerequisite only under a negated agent obligation ("never answer
#   before calling X" — not "the id is required before calling X").
# * SAME FINITE CLAUSE — a subordinator, relativizer or coordinator that
#   opens a clause with its own subject ("before you call X", "when the
#   token is required", "the one you used to call X", "..., which must
#   ...", "... and you can call X") and a parenthesis put what they open
#   out of the strong word's reach, up to the next punctuation mark. The
#   one clause the strong word reaches into is a prerequisite clause of
#   its own clause ("... only after you have called X").
# * WHAT THE STRONG WORD SAYS — "must" reaches a call anywhere after it;
#   across punctuation only when its subject is the agent ("you must, ...,
#   call X" — not "the id must be valid, use X to find one"). "always" /
#   "never" do the same unless they describe behaviour (a third-person
#   verb, "always returns ..."; a state, "the id is always ...") or the
#   absence of an obligation ("never need to ..."). After the call, "must"
#   needs the call or an anaphor of it as its subject ("calling X must
#   happen first"), or the agent with a back-reference ("call X - you must
#   not skip this"); "always"/"never" must trail the call ("call X first,
#   always") or sit in an obligation predicate about it ("calling X is
#   always the first step"). "required" / "mandatory" are adjectives and
#   need a link to the call: a complement after them ("required to ...",
#   "mandatory that ...", a "Mandatory step:" label) with an agent /
#   expletive subject, or a predicate whose subject is the call ("calling
#   X before answering is mandatory", "run X first - this step is
#   required"); negated ("is not required") they state no obligation.
#
# Structure and closed generic vocabularies only; no tagger.
_OBJ_TOKEN_RX = re.compile(
    r"[A-Za-z][A-Za-z0-9_'\-]*|[,;:()\[\]–—]|(?<=\s)-(?=\s)|\.(?=\s)")
_OBJ_LEADERS = _OBJECT_LEADERS | frozenset({"function", "both", "either"})
_OBJ_NAMING = frozenset({"named", "called"})
_OBJ_NAMING_HEADS = frozenset({
    "tool", "tools", "function", "functions", "server", "endpoint", "command",
    "action", "operation", "method", "api", "utility", "integration", "plugin",
    "service", "resource", "prompt", "skill", "helper", "wrapper", "one", "something",
})
_OBJ_TOOLISH_RX = re.compile(r"[a-z][a-z0-9]*(?:[_\-][a-z0-9]+)+")
_OBJ_CALL_NOUNS = frozenset({"call", "calls"})
_OBJ_NOMINAL_LEADERS = frozenset({"a", "an", "the", "another", "one", "extra",
                                  "additional", "separate", "single", "first"})
_OBJ_LIGHT_VERBS = frozenset({
    "make", "makes", "making", "made", "issue", "issues", "issuing", "issued",
    "place", "places", "placing", "placed", "perform", "performs", "performing",
    "performed", "schedule", "schedules", "scheduling", "queue", "queues", "queuing",
})
_OBJ_PASSIVE_RX = re.compile(
    r"[\s\"'`‘’“”]{0,3}(?:(?:tool|function)\s+)?"
    r"(?:must|should|shall|needs?\s+to|ha(?:s|ve)\s+to|ought\s+to|is|are)\s+"
    r"(?:(?:always|never|first|also|then|only|not|now|still|required|supposed|expected)\s+)"
    r"{0,3}(?:to\s+)?be\s+(?:(?:always|never|first|also|then|only|not)\s+){0,2}"
    r"(?:called|invoked|run|executed|used|triggered)\b", re.IGNORECASE)
# a plain passive ("X is called first") orders the call only as the
# complement of an "ensure" head: "make sure X is called", "it is mandatory
# that X is run first"
_OBJ_PLAIN_PASSIVE_RX = re.compile(
    r"[\s\"'`‘’“”]{0,3}(?:(?:tool|function)\s+)?"
    r"(?:is|are|gets?|be|ha(?:s|ve)\s+been)\s+"
    r"(?:(?:always|never|first|also|then|only|not)\s+){0,2}"
    r"(?:called|invoked|run|executed|used|triggered)\b", re.IGNORECASE)
_OBJ_ENSURE_HEADS = frozenset({
    "ensure", "ensures", "ensuring", "sure", "certain", "guarantee", "guarantees",
    "mandatory", "required", "essential", "imperative", "critical", "crucial",
    "vital", "important", "necessary",
})
_OBJ_ADVERBS = frozenset({
    "first", "then", "also", "always", "never", "only", "just", "now", "still",
    "again", "ever", "not", "please", "beforehand", "afterwards", "afterward",
    "instead", "either", "both", "too",
})
_OBJ_NOT_ADVERBS = frozenset({"reply", "apply", "reapply", "supply", "comply", "imply",
                              "multiply", "family", "assembly", "anomaly"})
_OBJ_AGENTS = frozenset({
    "you", "we", "they", "agent", "agents", "assistant", "assistants", "model",
    "models", "llm", "ai", "caller", "client",
})
_OBJ_BE = frozenset({"is", "are", "be", "was", "were", "been", "being", "am"})
_OBJ_BE_FINITE = frozenset({"is", "are", "was", "were"})
_OBJ_AUX = _OBJ_BE | frozenset({
    "has", "have", "had", "do", "does", "did", "will", "would", "can", "could",
    "may", "might", "should", "shall",
})
_OBJ_LIGHT_MODALS = frozenset({"can", "could", "may", "might", "will", "would"})
_OBJ_PERFECT_AUX = frozenset({"have", "has", "had", "do", "does", "did"})
_OBJ_ARTICLES = frozenset({"a", "an", "the"})
_OBJ_SOFT_PUNCT = frozenset({",", ":", "-", "–", "—"})
# what "must" may have as its subject when it follows the call ...
_OBJ_ANAPHORS = frozenset({"this", "that", "it", "step", "call", "so"})
# ... and the narrower set for a predicate ("this is mandatory"): "it" after
# a call is as often the thing the call returned
_OBJ_PREDICATE_ANAPHORS = _OBJ_ANAPHORS - {"it"}
# conjunctions: what follows is a clause unless it is an "-ing" adjunct ...
_OBJ_CONJUNCTIONS = frozenset({
    "when", "whenever", "while", "whilst", "once", "unless", "if", "because",
    "although", "though", "whereas",
})
# ... and words that are prepositions too ("before any other action"): a
# clause only when a subject pronoun / agent follows ("before you call X")
_OBJ_PREP_CONJUNCTIONS = frozenset({"before", "after", "until", "till", "since"})
_OBJ_SUBORDINATORS = _OBJ_CONJUNCTIONS | _OBJ_PREP_CONJUNCTIONS
_OBJ_SUBJECT_PRONOUNS = frozenset({"you", "we", "they", "it", "he", "she", "i", "there"})
# a clause one of these opens states a PREREQUISITE of the clause it hangs
# off: unconditionally ("... only after you have called X"), or under a
# negated obligation ("never answer until you have called X")
_OBJ_PREREQUISITE_OPENERS = frozenset({"after"})
_OBJ_PREREQUISITE_HEADS = frozenset({"before", "until", "till", "unless"})
_OBJ_RELATIVIZERS = frozenset({"which", "who", "whom", "whose", "where", "wherever",
                               "what", "whatever", "whichever"})
_OBJ_COMPLEMENT_HEADS = frozenset({
    "sure", "ensure", "ensures", "ensuring", "ensured", "certain", "remember",
    "remembers", "guarantee", "guarantees", "verify", "check", "confirm",
    "mandatory", "required", "require", "requires", "essential", "critical",
    "crucial", "important", "imperative", "vital", "necessary", "is", "means", "so",
})
_OBJ_COORDINATORS = frozenset({"and", "or", "but", "then", "so", "nor", "yet"})
_OBJ_PARTICLES = frozenset({"to", "by", "with", "for", "in", "on", "at", "from", "of",
                            "and", "or", "here", "there", "back", "up", "out"})
# an invoke verb headed by one of these is the circumstance, the purpose or
# the comparison of something else — not a call the sentence prescribes
_OBJ_CONDITION_HEADS = frozenset({
    "when", "whenever", "while", "whilst", "if", "once", "upon", "on", "in",
    "during", "for", "as", "like", "unlike", "than", "about", "whether", "from",
    "of", "regarding", "concerning",
})
# "<head> to <invoke> X": the infinitive is a purpose / enablement adjunct
# ("access to use X", "in order to call X", "the token needed to call X")
_OBJ_ENABLEMENT = frozenset({
    "prior", "order", "as", "addition", "due", "according", "similar", "equivalent",
    "related", "compared", "opposed", "alternative", "regard", "respect",
    "access", "permission", "permissions", "right", "rights", "privilege",
    "privileges", "role", "roles", "scope", "scopes", "token", "tokens", "key",
    "keys", "credential", "credentials", "authorization", "authorisation",
    "authority", "ability", "able", "unable", "authorized", "authorised",
    "enabled", "configured", "valid", "ready", "used", "needed", "way", "ways",
    "how", "option", "possible", "safe", "free",
})
# after one of these the call is a means or a prerequisite — unless the
# phrase hangs off a participle that modifies a noun ("the id RETURNED after
# calling X", "the one OBTAINED by calling X"): then it is provenance
_OBJ_PARTICIPLE_GATED_HEADS = frozenset({"by", "via", "through", "after"})
# a sibling right after one of these is inside a phrase, not a subject
_OBJ_PREPOSITIONS = frozenset({
    "by", "from", "of", "in", "inside", "within", "into", "onto", "unlike", "like",
    "as", "with", "without", "to", "for", "on", "at", "via", "through", "than",
    "about", "against", "per", "over", "under", "between", "before", "after",
})
_OBJ_IRREGULAR_PARTICIPLES = frozenset({
    "given", "taken", "gotten", "got", "written", "chosen", "seen", "drawn",
    "shown", "known", "made", "built", "sent", "kept", "found", "held", "read",
    "set", "done",
})
_OBJ_PASSIVE_AUX = _OBJ_BE | frozenset({"get", "gets", "getting"})
_OBJ_ADJUNCT_PREPS = frozenset({"before", "after", "at", "on", "in", "prior", "during",
                                "with", "upon", "every", "each", "for"})
_OBJ_MAX_ADJUNCT_WORDS = 6
# "this tool always REQUIRES calling X first" states a requirement, unlike
# "always returns ..."
_OBJ_REQUIREMENT_VERBS = frozenset({"requires", "needs", "expects", "demands", "insists"})
# "never NEED to call X", "not REQUIRED": the absence of an obligation
_OBJ_NON_OBLIGATION = frozenset({"need", "needs", "needed", "have", "has", "required",
                                 "necessary", "mandatory"})
# a predicate about the call that states an obligation: "calling X is
# always the FIRST step", "... is never OPTIONAL" (not "is always faster")
_OBJ_ALWAYS_PREDICATES = frozenset({"first", "required", "mandatory", "necessary",
                                    "needed", "step", "prerequisite", "precondition"})
_OBJ_NEVER_PREDICATES = frozenset({"optional", "skipped", "omitted"})
# "call X first - you must never skip THIS": the agent's obligation after
# the call is about the call only when it points back at it
_OBJ_BACK_REFERENCES = frozenset({"this", "that", "it", "so", "step"})
# "the mandatory first STEP is to call X"
_OBJ_STEP_NOUNS = frozenset({"step", "steps", "action", "call", "prerequisite",
                             "precondition", "requirement", "procedure", "rule"})
_OBJ_MAX_LABEL_WORDS = 3


def _obj_is_adverb(w: str) -> bool:
    return w in _OBJ_ADVERBS or (
        len(w) > 4 and w.endswith("ly") and w not in _OBJ_NOT_ADVERBS)


def _obj_third_person(w: str) -> bool:
    """A third-person singular verb form ("returns", "has")."""
    return w in ("is", "has", "does") or (
        len(w) >= 4 and w.endswith("s") and not w.endswith(("ss", "us", "is")))


def _obj_looks_participle(w: str) -> bool:
    return w in _OBJ_IRREGULAR_PARTICIPLES or (
        len(w) >= 5 and w.endswith("ed") and not w.endswith("eed") and w != "embed")


def _obj_tokens(clause: str, pat: re.Pattern):
    """(start, end, lowercase text, kind) tokens of the clause — kind "w" a
    word, "p" a punctuation mark, "m" one whole mention of the sibling."""
    spans = [(m.start(), m.end()) for m in pat.finditer(clause)]
    toks = [(s, e, "", "m") for s, e in spans]
    for m in _OBJ_TOKEN_RX.finditer(clause):
        s, e = m.start(), m.end()
        if any(s < m_end and e > m_start for m_start, m_end in spans):
            continue
        w = m.group(0).lower()
        if w[:1].isalpha():
            w = w.rstrip("'-")
        toks.append((s, e, w, "w" if w[:1].isalpha() else "p"))
    toks.sort()
    return toks


def _obj_prev_word(toks, i: int, skip_subject: bool = False) -> Optional[int]:
    """Index of the nearest word before ``i`` in the same phrase, stepping
    over adverbs (and, when asked, an agent subject with a light modal);
    None at a phrase start (punctuation, a mention, the clause start)."""
    j = i - 1
    while j >= 0:
        _s, _e, w, kind = toks[j]
        if kind != "w":
            return None
        if _obj_is_adverb(w) or (skip_subject and (
                w in _OBJ_AGENTS or w in _OBJ_LIGHT_MODALS or w in _OBJ_PERFECT_AUX
                or w == "the")):
            j -= 1
            continue
        return j
    return None


def _obj_anchor(toks, i: int, soft_punct: bool, floor: int = -1):
    """What stands before index ``i`` once adverbs, auxiliaries and articles
    (and, with ``soft_punct``, commas / dashes / colons) are stepped over:
    ``(kind, index)`` with kind "site" (the walk reached ``floor``),
    "mention", "agent", "anaphor", "thing" or "none"."""
    j = i - 1
    while j > floor:
        _s, _e, w, kind = toks[j]
        if kind == "m":
            return "mention", j
        if kind == "p":
            if soft_punct and w in _OBJ_SOFT_PUNCT:
                j -= 1
                continue
            return "none", j
        if w in _OBJ_AGENTS:
            return "agent", j
        if w in _OBJ_ANAPHORS:
            return "anaphor", j
        if (_obj_is_adverb(w) or w in _OBJ_AUX or w in _OBJ_ARTICLES
                or (w in ("tool", "function") and j - 1 == floor)):
            j -= 1
            continue
        return "thing", j
    return ("site" if floor >= 0 else "none"), j


def _obj_tool_token(tok) -> bool:
    """A mention of the sibling, or another tool-identifier-shaped word."""
    return tok[3] == "m" or (tok[3] == "w" and bool(_OBJ_TOOLISH_RX.fullmatch(tok[2])))


def _obj_call_sites(clause: str, toks, add_ok: bool):
    """Every call site of the sibling as (verb index, first index, last
    index, kind): kind "active" / "gerund" for a direct object (first =
    the verb, last = the mention), "passive" for the subject of an
    obligation passive (first = the mention, last = the participle)."""
    sites = []
    for mi, tok in enumerate(toks):
        if tok[3] != "m":
            continue
        # the word the mention hangs off, past its article / determiner
        j = mi - 1
        lead = 0
        while j >= 0 and toks[j][3] == "w" and toks[j][2] in _OBJ_LEADERS and lead < 3:
            j -= 1
            lead += 1
        head = toks[j][2] if j >= 0 and toks[j][3] == "w" else ""
        pm = _OBJ_PASSIVE_RX.match(clause, tok[1])
        if pm is None:
            if head == "that" and j >= 1 and toks[j - 1][3] == "w":
                head = toks[j - 1][2]
            if head in _OBJ_ENSURE_HEADS:
                pm = _OBJ_PLAIN_PASSIVE_RX.match(clause, tok[1])
        # "the id returned by X must be used": X is inside a phrase, the
        # passive's subject is the id
        if pm is not None and head not in _OBJ_PREPOSITIONS:
            last = max(k for k, t in enumerate(toks) if t[0] < pm.end())
            sites.append((mi, mi, last, "passive"))
        j = mi - 1
        if (j >= 1 and toks[j][3] == "w" and toks[j][2] in _OBJ_NAMING
                and toks[j - 1][2] in ("tool", "function")):
            j -= 1  # "the tool named X"
        hops = 0
        while True:
            lead = 0
            while j >= 0 and toks[j][3] == "w" and toks[j][2] in _OBJ_LEADERS and lead < 3:
                j -= 1
                lead += 1
            # a sibling coordinated with a direct object: "call A and X"
            if j >= 1 and hops < 3 and toks[j][3] == "w" and toks[j][2] in ("and", "or"):
                k = j - 1
                if toks[k][3] == "p" and toks[k][2] == ",":
                    k -= 1
                if k >= 0 and _obj_tool_token(toks[k]):
                    j = k - 1
                    hops += 1
                    while (j >= 1 and toks[j][3] == "p" and toks[j][2] == ","
                           and _obj_tool_token(toks[j - 1])):
                        j -= 2
                    continue
            break
        if j < 0 or toks[j][3] != "w":
            continue
        w = toks[j][2]
        if _INVOKE_RX.fullmatch(w) or (add_ok and _ADD_VERB_RX.fullmatch(w)):
            if (w in _OBJ_NAMING and j >= 1 and toks[j - 1][3] == "w"
                    and toks[j - 1][2] in _OBJ_NAMING_HEADS):
                continue  # "a tool called X" names the tool, it does not call it
            sites.append((j, j, mi, "gerund" if w.endswith("ing") else "active"))
        elif w == "to" and j >= 1 and toks[j - 1][3] == "w" and toks[j - 1][2] in _OBJ_CALL_NOUNS:
            # nominal form: "make a call to X", "add a call to X"
            k = j - 2
            while k >= 0 and toks[k][3] == "w" and toks[k][2] in _OBJ_NOMINAL_LEADERS:
                k -= 1
            if k >= 0 and toks[k][3] == "w" and (
                    toks[k][2] in _OBJ_LIGHT_VERBS or _ADD_VERB_RX.fullmatch(toks[k][2])):
                sites.append((k, k, mi, "gerund" if toks[k][2].endswith("ing") else "active"))
    return sites


def _obj_site_role(toks, vi: int) -> str:
    """"prescribed" — the call is one the sentence orders; "negated" — the
    call is a prerequisite only under a negated obligation ("never answer
    BEFORE calling X"); "" — the call is somebody else's, or the
    circumstance, purpose, comparison or provenance of something else."""
    verb = toks[vi][2]
    j = vi - 1
    modal = agent = False
    h = None
    while j >= 0 and toks[j][3] == "w":
        w = toks[j][2]
        if _obj_is_adverb(w) or w in _OBJ_PERFECT_AUX:
            j -= 1
        elif w in _OBJ_LIGHT_MODALS and not agent:
            modal = True
            j -= 1
        elif w in _OBJ_AGENTS and not agent:
            agent = True
            j -= 1
            if j >= 0 and toks[j][2] == "the":
                j -= 1
        else:
            h = j
            break
    # "so the server can call X", "the system calls X": not the agent's call
    third_person = verb.endswith("s") and not verb.endswith("ss")
    if (modal or third_person) and not agent:
        return ""
    if h is None:
        return "prescribed"
    w = toks[h][2]
    if w in ("and", "or") and verb.endswith("ing"):
        # "before opening the report or calling X" shares the first
        # conjunct's role
        k = h - 1
        while k >= 0 and toks[k][3] == "w":
            if toks[k][2].endswith("ing") and len(toks[k][2]) > 4:
                return _obj_site_role(toks, k)
            k -= 1
        return "prescribed"
    if w in _OBJ_PREREQUISITE_HEADS:
        return "negated"
    if w in _OBJ_CONDITION_HEADS:
        return ""
    if w == "to":
        k = _obj_prev_word(toks, h)
        if k is None:
            # fronted purpose clause: "To use X, you must first ..."
            fronted = all(t[3] != "w" or _obj_is_adverb(t[2]) for t in toks[:h])
            return "" if fronted else "prescribed"
        if toks[k][2] == "prior":
            return "negated"
        return "" if toks[k][2] in _OBJ_ENABLEMENT else "prescribed"
    if w in _OBJ_PARTICIPLE_GATED_HEADS:
        # "must BE VERIFIED by calling X" is the main verb, not provenance
        k = _obj_prev_word(toks, h)
        if k is not None and _obj_looks_participle(toks[k][2]):
            k2 = _obj_prev_word(toks, k)
            if k2 is None or toks[k2][2] not in _OBJ_PASSIVE_AUX:
                return ""
    return "prescribed"


def _obj_opens_subclause(toks, i: int) -> bool:
    """The word at ``i`` opens a finite clause of its own."""
    w = toks[i][2]
    prev = toks[i - 1] if i > 0 else None
    j = i + 1
    while j < len(toks) and toks[j][3] == "w" and _obj_is_adverb(toks[j][2]):
        j += 1
    nxt = toks[j] if j < len(toks) else None
    if nxt is None or nxt[3] == "p":
        return False
    if w in _OBJ_PREP_CONJUNCTIONS:
        if nxt[3] != "w":
            return False
        if nxt[2] in _OBJ_SUBJECT_PRONOUNS:
            return True
        return (nxt[2] == "the" and j + 1 < len(toks)
                and toks[j + 1][2] in _OBJ_AGENTS | {"user"})
    if w in _OBJ_CONJUNCTIONS:
        if w == "once" and ((prev is not None and prev[2] == "at") or nxt[2] == "more"):
            return False
        if (w == "because" and nxt[2] in _OBJ_PREDICATE_ANAPHORS and j + 1 < len(toks)
                and toks[j + 1][2] in _OBJ_BE | _OBJ_STEP_NOUNS):
            return False  # "..., because this is mandatory" is about the call
        # "when using X" is a non-finite adjunct of the same clause
        return not (nxt[3] == "w" and nxt[2].endswith("ing"))
    if w in _OBJ_RELATIVIZERS:
        return True
    if w == "so" and nxt[2] == "that":
        return True  # purpose clause: "... so that calling X succeeds"
    if w in _OBJ_COORDINATORS:
        # "... and you can call X": a new clause with its own subject
        return nxt[3] == "w" and nxt[2] in _OBJ_SUBJECT_PRONOUNS
    if prev is None or prev[3] != "w":
        return False
    if w == "that":
        if prev[2] in _OBJ_COMPLEMENT_HEADS:
            return False  # "make sure that ...", "it is mandatory that ..."
        return nxt[3] == "w" and (nxt[2] in _GOV_FINITE or nxt[2] in _OBJ_AGENTS
                                  or nxt[2] in ("it", "the", "a", "an", "each", "every"))
    if w in ("you", "we", "they"):
        # zero relative: "the one you used to call X"
        if (prev[2] in _OBJ_COORDINATORS or prev[2] in _OBJ_SUBORDINATORS
                or prev[2] in _OBJ_RELATIVIZERS or prev[2] in _OBJ_COMPLEMENT_HEADS
                or prev[2] in _GOV_FINITE or prev[2] in ("that", "please")
                or _STRONG_OBLIGATION_RX.fullmatch(prev[2]) or _obj_is_adverb(prev[2])):
            return False
        nx = toks[i + 1]
        return nx[3] == "w" and nx[2] not in _OBJ_PARTICLES
    return False


def _obj_segments(toks):
    """A finite-clause id per token — 0 for the main clause; a sub-clause
    or a parenthesis gets its own id, up to the next punctuation mark — and
    {id: (opening word, id of the clause it hangs off)}."""
    seg = [0] * len(toks)
    opened = {}
    base = cur = 0
    nxt_id = 1
    stack = []
    for i, (_s, _e, w, kind) in enumerate(toks):
        if kind == "p":
            if w in ("(", "["):
                stack.append((base, cur))
                opened[nxt_id] = (w, cur)
                base = cur = nxt_id
                nxt_id += 1
            elif w in (")", "]"):
                if stack:
                    base, cur = stack.pop()
            else:
                cur = base
        elif kind == "w" and _obj_opens_subclause(toks, i):
            opened[nxt_id] = (w, cur)
            cur = nxt_id
            nxt_id += 1
        seg[i] = cur
    return seg, opened


def _obj_negated_agent_obligation(toks, si: int) -> bool:
    """"never <act>" / "must not <act>" addressed to the agent (or with no
    subject): the obligation under which a "before / until / unless" call
    is a prerequisite. A negated STATE ("must not be empty") is not one."""
    j = si + 1
    negated = toks[si][2] == "never"
    while j < len(toks) and toks[j][3] == "w" and _obj_is_adverb(toks[j][2]):
        negated = negated or toks[j][2] in ("not", "never")
        j += 1
    if not negated or j >= len(toks) or toks[j][3] != "w":
        return False
    if toks[j][2] in _OBJ_BE or toks[j][2] in ("have", "has"):
        return False
    return _obj_anchor(toks, si, soft_punct=False)[0] in ("agent", "none")


def _obj_descriptive_adverb(toks, si: int) -> bool:
    """"always"/"never" describing behaviour or a state, not an obligation:
    "always returns ...", "the id is always ..."."""
    j = si + 1
    while j < len(toks) and toks[j][3] == "w" and _obj_is_adverb(toks[j][2]):
        j += 1
    nxt = toks[j] if j < len(toks) and toks[j][3] == "w" else None
    p = _obj_prev_word(toks, si)
    if nxt is not None and nxt[2] == "to":
        return False  # "the first step is always to call X"
    if (nxt is not None and _obj_third_person(nxt[2]) and not _INVOKE_RX.fullmatch(nxt[2])
            and nxt[2] not in _OBJ_REQUIREMENT_VERBS):
        return not (p is not None and toks[p][2] in _OBJ_AGENTS)
    if p is not None and toks[p][2] in _OBJ_BE_FINITE:
        return _obj_anchor(toks, p, soft_punct=False)[0] == "thing"
    return False


def _obj_after_call_link(toks, i: int, site, anaphors: frozenset, agents: bool) -> bool:
    """The predicate that starts at ``i`` is about the call that precedes
    it: its subject is the call itself, an anaphor of it, the agent (when
    allowed), or the call followed by a short adjunct ("calling X before
    answering is mandatory")."""
    _vi, first, last, kind = site
    a_kind, j = _obj_anchor(toks, i, soft_punct=True, floor=last)
    if a_kind == "site":
        return True
    if a_kind == "anaphor":
        return toks[j][2] in anaphors
    if a_kind == "agent":
        return agents
    if a_kind != "thing" or kind != "gerund":
        return False
    if first > 0 and toks[first - 1][3] == "w":
        return False  # the gerund is not the subject of its clause
    between = toks[last + 1:j + 1]
    return (0 < len(between) <= _OBJ_MAX_ADJUNCT_WORDS
            and all(t[3] == "w" for t in between)
            and between[0][2] in _OBJ_ADJUNCT_PREPS
            and not any(t[2] in _OBJ_COORDINATORS for t in between))


def _obj_negated_before(toks, si: int) -> bool:
    """"not" / "never" in the adverb run right before the word at si."""
    j = si - 1
    while j >= 0 and toks[j][3] == "w" and _obj_is_adverb(toks[j][2]):
        if toks[j][2] in ("not", "never"):
            return True
        j -= 1
    return False


def _obj_forward_link(toks, si: int, first: int) -> bool:
    """"required" / "mandatory" before the call: a complement ("required to
    ...", "mandatory that ...") with an agent or expletive subject, or a
    label ("Mandatory step: ...", "the mandatory first step is ...")."""
    if _obj_negated_before(toks, si):
        return False  # "not required to ..."
    j = si + 1
    while j < first and toks[j][3] == "w" and (
            _obj_is_adverb(toks[j][2]) or toks[j][2] in _OBJ_AGENTS
            or toks[j][2] in ("for", "the")):
        j += 1
    if j < first and toks[j][3] == "w" and toks[j][2] in ("to", "that"):
        return _obj_anchor(toks, si, soft_punct=False)[0] in ("agent", "anaphor", "none")
    words = 0
    for k in range(si + 1, first):
        label_end = (toks[k][2] in _GOV_LABEL_END if toks[k][3] == "p" else
                     toks[k][2] in ("is", "are") and toks[k - 1][2] in _OBJ_STEP_NOUNS)
        if label_end:
            a_kind, a_j = _obj_anchor(toks, si, soft_punct=False)
            return a_kind == "none" or (
                a_kind == "anaphor" and toks[a_j][2] in _OBJ_PREDICATE_ANAPHORS)
        if toks[k][3] == "p":
            return False
        words += 1
        if words > _OBJ_MAX_LABEL_WORDS:
            return False
    return False


def _obj_predicate_link(toks, si: int, site) -> bool:
    """"required" / "mandatory" after the call: "<the call> is (a) mandatory
    ...", "... - this step is required"."""
    if _obj_negated_before(toks, si):
        return False  # "calling X is not required"
    j = si - 1
    while j >= 0 and toks[j][3] == "w" and (
            _obj_is_adverb(toks[j][2]) or toks[j][2] in _OBJ_ARTICLES):
        j -= 1
    if j < 0 or toks[j][3] != "w" or toks[j][2] not in ("is", "are", "be"):
        return False
    return _obj_after_call_link(toks, j, site, _OBJ_PREDICATE_ANAPHORS, agents=False)


def _obj_strong_in_scope(toks, si: int, site) -> bool:
    """The strong word at si is an obligation on the call at site."""
    _vi, first, last, kind = site
    w = toks[si][2]
    if kind == "passive" and first < si <= last:
        return True  # "X must be called", "X is always to be run first"
    if first <= si <= last:
        return False
    before = si < first
    if w in _GOV_LABEL_STRONG:
        return _obj_forward_link(toks, si, first) if before else _obj_predicate_link(toks, si, site)
    adverb = w in ("always", "never")
    j = si + 1
    while j < len(toks) and toks[j][3] == "w" and _obj_is_adverb(toks[j][2]):
        j += 1
    governed = toks[j][2] if j < len(toks) and toks[j][3] == "w" else ""
    if adverb:
        if _obj_descriptive_adverb(toks, si):
            return False
        if w == "never" and governed in _OBJ_NON_OBLIGATION:
            return False  # "you never need to call X"
        if w == "always" and _obj_negated_before(toks, si):
            return False  # "not always ..."
    if before:
        if any(toks[k][3] == "p" for k in range(si + 1, first)):
            # across punctuation only the agent's own obligation carries
            # over: "you must, ..., call X", "always verify ..., then call
            # X" — not "the id must be valid, use X to find one"
            a_kind = _obj_anchor(toks, si, soft_punct=False)[0]
            return a_kind == "agent" or (adverb and a_kind == "none")
        return True
    if adverb:
        if si + 1 >= len(toks) or toks[si + 1][3] == "p":
            return True  # trailing: "call X first, always"
        p = _obj_prev_word(toks, si)
        if p is None or toks[p][2] not in _OBJ_BE_FINITE:
            return False
        predicates = _OBJ_ALWAYS_PREDICATES if w == "always" else _OBJ_NEVER_PREDICATES
        if not any(t[3] == "w" and t[2] in predicates for t in toks[si + 1:si + 4]):
            return False  # "this is always faster" states no obligation
        return _obj_after_call_link(toks, p, site, _OBJ_PREDICATE_ANAPHORS, agents=False)
    if _obj_anchor(toks, si, soft_punct=True, floor=last)[0] == "agent":
        # "call X first - you must never skip THIS"
        k = si + 1
        while k < len(toks) and toks[k][3] == "w":
            if toks[k][2] in _OBJ_BACK_REFERENCES:
                return True
            k += 1
        return False
    return _obj_after_call_link(toks, si, site, _OBJ_ANAPHORS, agents=False)


def _strong_word_object_test(clause: str, pat: re.Pattern, name: str = "") -> bool:
    """v5-3 refinement — a strong obligation word shares a finite clause
    with a prescribed call of the sibling and is an obligation on it (see
    the block comment above)."""
    toks = _obj_tokens(clause, pat)
    add_ok = (bool(name) and not _is_single_word_name(name)
              and bool(_PLAN_NOUN_RX.search(clause)))
    sites = []
    for site in _obj_call_sites(clause, toks, add_ok):
        role = "prescribed" if site[3] == "passive" else _obj_site_role(toks, site[0])
        if role:
            sites.append((site, role))
    if not sites:
        return False
    seg, opened = _obj_segments(toks)
    for si, (_s, _e, w, kind) in enumerate(toks):
        if kind != "w" or not _STRONG_OBLIGATION_RX.fullmatch(w):
            continue
        for site, role in sites:
            _vi, first, last, _kind = site
            if seg[first] != seg[last]:
                continue
            needs_negation = role == "negated"
            if seg[si] != seg[first]:
                # the call sits in a prerequisite clause of the strong
                # word's own clause: "... only after you have called X"
                opener, parent = opened.get(seg[first], ("", -1))
                if si > first or parent != seg[si]:
                    continue
                if opener in _OBJ_PREREQUISITE_HEADS:
                    needs_negation = True
                elif opener not in _OBJ_PREREQUISITE_OPENERS:
                    continue
            if needs_negation and not _obj_negated_agent_obligation(toks, si):
                continue
            if _obj_strong_in_scope(toks, si, site):
                return True
    return False


def _strong_word_governs(clause: str, pat: re.Pattern, name: str = "",
                         verb_object_only: bool = False) -> bool:
    """v5-3 — True when a strong obligation word of the clause is an
    obligation on a call of the sibling: the OBJECT TEST (the sibling is the
    direct object of an invoke verb or the subject of a passive invoke, in
    the strong word's own finite clause), or the retained DIRECT CHAIN
    (strong word, then the invoke verb, then the sibling as any
    non-provenance complement: "must use this tool instead of X"). The
    v4-7 any-verb route (``verb_object_only``) keeps the direct chain
    only — its verb list is open, so the wider reach is not extended to it."""
    if not verb_object_only and _strong_word_object_test(clause, pat, name):
        return True
    return _strong_word_chain(clause, pat, name, verb_object_only)


# ---------------------------------------------------------------------------
# v5-2 — THIRD-PARTY PAIR. A clause that names TWO distinct tools, neither
# of which is the tool being described, and relates them to EACH OTHER
# ("before using A, call B", "call B after A", "B must be run before A") is
# an instruction about other tools' flow — no description has a legitimate
# reason to sequence two tools that are not its own, so the clause is
# actionable even with a weak modal or a bare sequence word. Structure, not
# vocabulary:
#
# * ANCHORED mention — a tool reference directly governed by a sequence /
#   condition word (before, after, prior to, when, once, while, until, if,
#   every time, ...): at most four words in between, no clause punctuation,
#   no self pronoun ("before using THIS tool" anchors the described tool,
#   not a sibling). A reference coordinated with an anchored one
#   ("before using A or B") is anchored too.
# * PRESCRIBED mention — a DIFFERENT tool reference, not anchored, that is
#   the object of an invoke verb (the word directly before it, allowing a
#   determiner / the word "tool" / "a call to"), or the subject of a
#   passive invoke ("B must be called").
#
# Two siblings in the same role ("use A or B first", "before using this
# tool, call A and B") relate to the described tool, not to each other, and
# keep the two-tier grading. Tool references are co-listed siblings or
# quoted tool-identifier-shaped tokens that are not the tool's own
# parameters (the latter grade one confidence step lower, like the
# quoted-name mode).
_PAIR_ANCHOR_RX = re.compile(
    r"\b(before|after|prior\s+to|when(?:ever)?|while|once|until|upon|if|"
    r"every\s+time|each\s+time|any\s+time|as\s+soon\s+as|following)\b",
    re.IGNORECASE)
_PAIR_BREAK_RX = re.compile(r"[,;:()\[\]]")
_PAIR_SELF_WORDS = frozenset({"this", "it", "itself", "these", "those"})
_PAIR_MAX_ANCHOR_WORDS = 4
_PAIR_COORD_RX = re.compile(
    r"^(?:[\s,/&" + "\"'`‘’“”" + r"]|\b(?:and|or|the|tools?)\b)*$", re.IGNORECASE)
_PAIR_PASSIVE_RX = re.compile(
    r"^[\s\"'`‘’“”]{0,3}(?:tool\s+)?(?:must|should|shall|needs?\s+to|ha(?:s|ve)\s+to|"
    r"is\s+to|are\s+to|is\s+required\s+to|will|can|may)\s+"
    r"(?:(?:always|first|also|then|only|never|not)\s+){0,2}be\s+"
    r"(?:called|invoked|run|executed|used|triggered)\b", re.IGNORECASE)
_PAIR_CALL_NOUN = frozenset({"call", "calls"})


def _tool_mentions(clause: str, siblings: List[str], own_props: frozenset,
                   self_name: str = ""):
    """Every tool reference in the clause as (start, end, name, mode): a
    co-listed sibling (``mode="sibling"``) or a quoted, tool-identifier-shaped
    token that is neither a sibling, nor the described tool's own name, nor
    one of its own parameters (``mode="quoted-name"``)."""
    out = []
    sib_norm = {_normalize_ident(self_name)} if self_name else set()
    for nm in siblings:
        sib_norm.add(_normalize_ident(nm))
        for m in _name_pattern(nm).finditer(clause):
            out.append((m.start(), m.end(), nm, "sibling"))
    for m in _QUOTED_CAPTURE_RX.finditer(clause):
        cand = m.group(1).strip()
        norm = _normalize_ident(cand)
        if norm in sib_norm or norm in own_props:
            continue
        if not _looks_like_quoted_tool_name(cand):
            continue
        out.append((m.start(1), m.end(1), cand, "quoted-name"))
    return sorted(set(out))


def _mention_governed_by_invoke(clause: str, start: int, end: int) -> bool:
    """The tool reference is the object of an invoke verb (the word directly
    before it, allowing a determiner / "tool" / "a call to"), or the subject
    of a passive invoke right after it."""
    words = [w.group(0).lower() for w in _WORD_RX.finditer(clause[:start])]
    i = len(words) - 1
    skipped = 0
    while i >= 0 and words[i] in _OBJECT_LEADERS and skipped < 2:
        i -= 1
        skipped += 1
    if i >= 0:
        if _INVOKE_RX.fullmatch(words[i]) or _ADD_VERB_RX.fullmatch(words[i]):
            return True
        if words[i] == "to" and i >= 1 and words[i - 1] in _PAIR_CALL_NOUN:
            return True
    return bool(_PAIR_PASSIVE_RX.match(clause[end:]))


def _third_party_pairs(clause: str, siblings: List[str], own_props: frozenset,
                       self_name: str = ""):
    """(anchor mention, prescribed mention) pairs of v5-2 in one clause."""
    mentions = _tool_mentions(clause, siblings, own_props, self_name)
    if len({_normalize_ident(m[2]) for m in mentions}) < 2:
        return []
    anchors = [a.end() for a in _PAIR_ANCHOR_RX.finditer(clause)]
    anchored = set()
    for idx, (start, _end, _nm, _mode) in enumerate(mentions):
        for a_end in anchors:
            if a_end > start:
                continue
            between = clause[a_end:start]
            if _PAIR_BREAK_RX.search(between):
                continue
            if any(o_start >= a_end and o_end <= start
                   for o_start, o_end, _n, _m in mentions):
                continue  # another tool reference sits in between
            words = [w.group(0).lower() for w in _WORD_RX.finditer(between)]
            if len(words) > _PAIR_MAX_ANCHOR_WORDS or set(words) & _PAIR_SELF_WORDS:
                continue
            anchored.add(idx)
            break
    # a reference coordinated with an anchored one shares its role
    changed = True
    while changed:
        changed = False
        for idx in range(1, len(mentions)):
            if idx in anchored or (idx - 1) not in anchored:
                continue
            if _PAIR_COORD_RX.match(clause[mentions[idx - 1][1]:mentions[idx][0]]):
                anchored.add(idx)
                changed = True
    pairs = []
    for bi, (b_start, b_end, b_nm, b_mode) in enumerate(mentions):
        if bi in anchored or not _mention_governed_by_invoke(clause, b_start, b_end):
            continue
        for ai in sorted(anchored):
            a_nm, a_mode = mentions[ai][2], mentions[ai][3]
            if _normalize_ident(a_nm) == _normalize_ident(b_nm):
                continue
            pairs.append(((a_nm, a_mode), (b_nm, b_mode)))
    return pairs


def _check_third_party_pair(text: str, siblings: List[str],
                            own_props: Optional[frozenset] = None,
                            self_name: str = "") -> List[Dict[str, str]]:
    out = []
    own_props = own_props or frozenset()
    for clause in _clauses(text or ""):
        if not _PAIR_ANCHOR_RX.search(clause):
            continue  # no sequence/condition word that could anchor a reference
        if _SAFE_PRECONDITION_RX.search(clause) or not _OBLIGATION_RX.search(clause):
            continue
        pairs = _third_party_pairs(clause, siblings, own_props, self_name)
        if not pairs:
            continue
        # a pair of two co-listed siblings is the strongest evidence
        pairs.sort(key=lambda p: (p[0][1] != "sibling") + (p[1][1] != "sibling"))
        (a_nm, a_mode), (b_nm, b_mode) = pairs[0]
        both_listed = a_mode == "sibling" and b_mode == "sibling"
        out.append({"clause": clause[:200], "sibling": b_nm, "anchor": a_nm,
                    "mode": "sibling" if both_listed else "quoted-name",
                    "tier": "actionable", "reason": "third-party-pair"})
    return out


def _check_cross_tool_call(text: str, siblings: List[str],
                           sibling_props: Optional[Dict[str, frozenset]] = None,
                           own_props: Optional[frozenset] = None) -> List[Dict[str, str]]:
    out = []
    sibling_props = sibling_props or {}
    own_props = own_props or frozenset()
    for clause, nm in _clauses_naming_siblings(text, siblings):
        if _SAFE_PRECONDITION_RX.search(clause):
            continue
        pat = _name_pattern(nm)
        if not _OBLIGATION_RX.search(clause):
            continue
        invoke = _invoke_in_clause(clause, pat, nm)
        verb_object = None
        strong = bool(_STRONG_OBLIGATION_RX.search(clause))
        if not invoke and strong:
            verb_object = _sibling_as_verb_object(clause, pat)
        if invoke or verb_object:
            # v5-3 — a strong word escalates only when the sibling is the
            # object of a call it is an obligation on (object test), or it
            # directly governs the invoke verb the sibling follows.
            governs = strong and _strong_word_governs(
                clause, pat, nm, verb_object_only=not invoke)
            reason = _actionable_reason(clause, nm, pat,
                                        sibling_props.get(nm.lower(), frozenset()), own_props,
                                        strong_governs=governs)
            if verb_object and not reason:
                continue  # v4-7: the verb-object route is actionable-tier only
            entry = {"clause": clause[:200], "sibling": nm, "mode": "sibling",
                     "tier": "actionable" if reason else "informational",
                     "reason": reason}
            if verb_object:
                entry["verb_object"] = verb_object
            out.append(entry)
    return out


# v3-2.7 — the argument a tampering sentence names: every quoted token
# (normalized), plus a bare word standing directly next to an argument word
# ("its recipient argument", "the parameter recipient").
_ARG_NEIGHBOR_RX = re.compile(
    r"\b([A-Za-z][A-Za-z0-9_\-]*)\s+(?:argument|arguments|parameter|parameters|"
    r"field|fields|input|inputs|value|values)\b|"
    r"\b(?:argument|parameter|field|input|param)\s+[\"'`‘’“”]?([A-Za-z][A-Za-z0-9_\-]*)",
    re.IGNORECASE)


def _argument_names_in_clause(clause: str) -> frozenset:
    names = set()
    for m in _QUOTED_CAPTURE_RX.finditer(clause):
        names.add(_normalize_ident(m.group(1)))
    for m in _ARG_NEIGHBOR_RX.finditer(clause):
        tok = m.group(1) or m.group(2) or ""
        if tok:
            names.add(_normalize_ident(tok))
    return frozenset(n for n in names if n)


def _tamper_actionable_reason(clause: str, name: str, pat: re.Pattern,
                              other_props: frozenset, own_props: frozenset) -> str:
    """v3-2.7 — parameter tampering is actionable only when the argument
    named belongs to the OTHER tool (a property present in the sibling's
    schema) or the sentence carries a strong obligation word. A sentence
    that names only the tool's OWN parameters (describing their modes) is
    informational even though it mentions a sibling."""
    if _STRONG_OBLIGATION_RX.search(clause):
        return "strong-obligation-word"
    named = _argument_names_in_clause(clause)
    if other_props and (named & other_props):
        return "sibling-parameter-named"
    if own_props and (named & own_props) and not (named & other_props):
        return ""  # modes of this tool's own parameters
    if _threat_near_sibling(clause, pat):
        return "threat-of-failure"
    if _has_sensitive_target(clause, name):
        return "sensitive-target"
    return ""


def _check_param_tampering(text: str, siblings: List[str],
                           sibling_props: Optional[Dict[str, frozenset]] = None,
                           own_props: Optional[frozenset] = None) -> List[Dict[str, str]]:
    out = []
    sibling_props = sibling_props or {}
    own_props = own_props or frozenset()
    for clause, nm in _clauses_naming_siblings(text, siblings):
        if _TAMPER_RX.search(clause) and (_ARG_WORD_RX.search(clause) or _QUOTED_RX.search(clause)):
            # v3-2.7 — actionable only when the named argument belongs to
            # the sibling (a property of ITS schema) or a strong obligation
            # word is present; own-parameter modes are informational.
            reason = _tamper_actionable_reason(
                clause, nm, _name_pattern(nm),
                sibling_props.get(nm.lower(), frozenset()), own_props)
            out.append({"clause": clause[:200], "sibling": nm, "mode": "sibling",
                        "tier": "actionable" if reason else "informational",
                        "reason": reason})
    return out


# ---------------------------------------------------------------------------
# QUOTED-TOOL-NAME mode (eval-driven addition) — the sibling-based checks above
# only fire when the named tool is a CO-LISTED SIBLING (present in this
# same server's ``ctx.all_contracts()``). A very common real-world
# description-poisoning shape instead names the VICTIM tool by a literal
# quoted/backticked identifier in the prose, where that tool is NOT in the
# current listing at all (a different server, a tool the agent has elsewhere,
# or simply not visible to this scan). Those attacks slipped through the
# sibling-only checks entirely. This mode drops the sibling-membership
# requirement and instead requires the quoted token to be STRUCTURALLY
# SHAPED LIKE A TOOL IDENTIFIER (snake_case / kebab-case / camelCase /
# dotted — never a bare English word, whatever its case), combined with the
# exact same structural obligation/invoke or tamper/argument-word context
# already required above. That keeps precision high: an honest description
# that quotes an ordinary word, or names a real sibling in "see also" prose
# with no obligation/invoke language, never fires.

_COMMON_ENGLISH_TOKENS = _COMMON_WORDS | frozenset({
    "content", "length", "range", "header", "headers", "status", "state",
    "real", "well", "known", "built", "date", "end", "open", "source",
    "third", "party", "long", "short", "non", "pre", "post", "sub", "multi",
    "single", "double", "case", "day", "hand", "hands", "off", "demand",
    "shelf", "stand", "alone", "art", "one", "mail", "ray", "follow", "opt",
    "worker", "never", "mind", "world", "wide", "web", "plain", "rich",
    "pair", "first", "last", "next", "prev", "previous", "current",
    "default", "custom", "auto", "manual", "other", "any", "all", "each",
    "every", "null", "yes", "no", "min", "max", "avg", "sum", "total",
    "super", "meta", "proto", "base", "root", "top", "bottom", "left",
    "center", "middle", "inner", "outer", "local", "global", "remote",
    "static", "dynamic", "public", "private", "internal", "external", "raw",
    "safe", "unsafe", "strict", "loose", "hard", "soft", "fast", "slow",
    "new", "old", "active", "inactive", "valid", "invalid", "empty",
    "partial", "complete", "final", "initial", "in", "to", "on", "by", "of",
    "or", "is", "it", "at", "as", "so", "if", "up", "out", "des", "asc",
})

_QUOTED_CAPTURE_RX = re.compile(
    r"[\"'`‘’“”]([^\"'`‘’“”]{2,60})[\"'`‘’“”]"
)

_NON_TOOL_EXT = (
    ".env", ".json", ".txt", ".py", ".js", ".ts", ".md", ".yml", ".yaml",
    ".csv", ".log", ".pem", ".key", ".xml", ".html", ".css", ".pdf",
    ".cfg", ".ini", ".toml", ".sh", ".bat", ".sql", ".db",
)


def _looks_like_quoted_tool_name(token: str) -> bool:
    """Structural shape test: does this quoted/backticked prose token read
    as a TOOL IDENTIFIER (snake_case, kebab-case or camelCase — rule 1.3 drops
    dotted from this list, see below) — as opposed to an ordinary quoted
    English word or phrase? Deliberately conservative: a bare single word
    never qualifies whatever its case, a multi-part token whose every part
    is ordinary English/technical vocabulary is rejected ("Content-Type",
    "well-known", "config.json"), and file-path/URL/version-number shaped
    tokens are excluded.

    rule 1.3 — a DOTTED token is excluded outright: real MCP tool identifiers
    are essentially always snake_case/kebab-case, never dotted, while a
    dotted quoted token in ordinary prose is overwhelmingly a JSON/response
    FIELD PATH used in an example ("the result's ``data.items.id`` field")
    — exactly the shape the improvement guide calls out to exclude, not a
    tool name."""
    t = (token or "").strip().strip(".,;:!?)('\"")
    if not t or len(t) < 4 or len(t) > 64:
        return False
    if any(ch.isspace() for ch in t) or "/" in t or "@" in t or "://" in t or "." in t:
        return False
    low = t.lower()
    if low.endswith(_NON_TOOL_EXT):
        return False
    if re.fullmatch(r"[0-9.\-]+", t):
        return False
    parts = _split_ident_tokens(t)
    if len(parts) < 2:
        return False  # a bare single word is never "tool-identifier shaped"
    if all(p in _COMMON_ENGLISH_TOKENS for p in parts):
        return False  # ordinary hyphenated English phrase
    return True


def _normalize_ident(s: str) -> str:
    return re.sub(r"[_\-]+", "_", (s or "").strip().lower())


# rule 1.3 — a quoted tool-shaped token only counts when it is directly
# GOVERNED by an invoke verb (call/use/invoke/run/execute/trigger) or the
# word "tool" nearby — e.g. `call "get_user"` or `the "get_user" tool` — not
# merely co-present anywhere in the same clause. Excludes an example value
# quoted next to an unrelated verb ("returns a `record_id` like `abc-123`").
_GOVERN_RX = re.compile(
    r"\b(call(?:s|ing|ed)?|invok(?:e|es|ed|ing)|us(?:e|es|ed|ing)|"
    r"run(?:s|ning)?|execut(?:e|es|ed|ing)|trigger(?:s|ed|ing)?|tool)\b",
    re.IGNORECASE)
_GOVERN_WINDOW = 25


def _quoted_tool_shaped_clauses(text: str, own_props: Optional[frozenset] = None):
    """Yield (clause, [quoted tool-shaped tokens]) for every clause in
    ``text`` that contains at least one quoted token shaped like a tool
    identifier -- independent of whether it names a current sibling.

    rule 1.3 — excludes the tool's OWN schema property names (``own_props``,
    normalized) — a description honestly quoting its own parameter name is
    not naming a different tool — and requires the token be directly
    governed by an invoke verb or the word "tool" nearby, not merely
    co-present anywhere in the clause."""
    if not text:
        return
    own_props = own_props or frozenset()
    for clause in _clauses(text):
        toks = []
        for m in _QUOTED_CAPTURE_RX.finditer(clause):
            cand = m.group(1)
            if not _looks_like_quoted_tool_name(cand):
                continue
            if _normalize_ident(cand) in own_props:
                continue
            window = (clause[max(0, m.start() - _GOVERN_WINDOW):m.start()] + " "
                      + clause[m.end():m.end() + _GOVERN_WINDOW])
            if not _GOVERN_RX.search(window):
                continue
            toks.append(cand.strip())
        if toks:
            yield clause, toks


def _check_cross_tool_call_quoted(text: str, own_props: Optional[frozenset] = None
                                  ) -> List[Dict[str, str]]:
    out = []
    for clause, toks in _quoted_tool_shaped_clauses(text, own_props):
        if _SAFE_PRECONDITION_RX.search(clause):
            continue
        pat = _name_pattern(toks[0])
        if _OBLIGATION_RX.search(clause) and _invoke_in_clause(clause, pat, toks[0]):
            governs = bool(_STRONG_OBLIGATION_RX.search(clause)) and _strong_word_governs(
                clause, pat, toks[0])
            reason = _actionable_reason(clause, toks[0], pat, frozenset(), own_props or frozenset(),
                                        strong_governs=governs)
            out.append({"clause": clause[:200], "sibling": toks[0], "mode": "quoted-name",
                        "tier": "actionable" if reason else "informational",
                        "reason": reason})
    return out


def _check_param_tampering_quoted(text: str, own_props: Optional[frozenset] = None
                                  ) -> List[Dict[str, str]]:
    out = []
    for clause, toks in _quoted_tool_shaped_clauses(text, own_props):
        if _TAMPER_RX.search(clause) and _ARG_WORD_RX.search(clause):
            reason = _actionable_reason(clause, toks[0], _name_pattern(toks[0]))
            # v3-2.7 — a quoted literal that is one of THIS tool's own
            # parameters is a description of its own modes, not a value
            # aimed at the other tool.
            if reason == "tamper-verb-with-literal-value":
                named = _argument_names_in_clause(clause)
                if own_props and named and named <= (own_props | {_normalize_ident(toks[0])}):
                    reason = ""
            out.append({"clause": clause[:200], "sibling": toks[0], "mode": "quoted-name",
                        "tier": "actionable" if reason else "informational",
                        "reason": reason})
    return out


def _dedup_matches(matches: List[Dict[str, str]]) -> List[Dict[str, str]]:
    seen = set()
    out = []
    for m in matches:
        k = m["clause"]
        if k in seen:
            continue
        seen.add(k)
        out.append(m)
    return out


def _texts_for(c: ToolContract):
    """Yield (location, text) for a contract's description(s) and every
    schema-field description. v3-4.3 — every duplicate definition's
    description is yielded too. v5-6 — and every other string of the live
    listing entry: ``schema-path:<json path>`` for a standard description
    slot nested in the input schema, ``field:<json path>`` for any other
    field (graded one confidence step lower, see ``_loc_info``)."""
    for d in contract_descriptions(c):
        yield "description", (d or "")
    props = (c.input_schema or {}).get("properties") or {}
    if isinstance(props, dict):
        for pname, pspec in props.items():
            if isinstance(pspec, dict):
                pdesc = pspec.get("description")
                yield f"schema:{pname}", (pdesc if isinstance(pdesc, str) else "")
    try:
        extra = listing_entry_strings(c)
    except Exception:
        extra = []  # a malformed entry never costs the description its own scan
    for json_path, text, standard in extra:
        yield ("schema-path:" if standard else "field:") + json_path, text


def _loc_info(loc: str):
    """(evidence_location, non_standard_field, json_path) of a ``_texts_for``
    location."""
    if loc == "description":
        return "description", False, None
    if loc.startswith("field:"):
        path = loc[len("field:"):]
        return ("schema" if listing_path_under_schema(path) else "description"), True, path
    if loc.startswith("schema-path:"):
        return "schema", False, loc[len("schema-path:"):]
    return "schema", False, None


def _graded_confidence(confidence: str, non_standard: bool) -> str:
    """v5-6 — a hit in a non-standard listing field is one confidence step
    lower than the same hit in the description."""
    return step_down_confidence(confidence) if non_standard else confidence


def _path_evidence(evidence: dict, json_path: Optional[str], non_standard: bool) -> dict:
    if json_path:
        evidence["json_path"] = json_path
        evidence["field_class"] = "non-standard" if non_standard else "standard"
    return evidence


def _own_prop_names(c: ToolContract) -> frozenset:
    """rule 1.3 — this contract's OWN parameter names, normalized, so a quoted
    reference to one of its own parameters is never misread as naming a
    different tool: the schema properties, plus (v4-6) every parameter of
    the tool's own source signature and every name its docstring argument
    section (``Args:`` / ``Parameters`` / ``:param x:``) or
    ``Field(description=...)`` documents — a tool whose live schema is
    empty or whose handler takes ``**kwargs`` still knows its own
    parameters."""
    names = set()
    props = (c.input_schema or {}).get("properties") or {}
    if isinstance(props, dict):
        names |= set(props)
    td = getattr(getattr(c, "source", None), "tool_def", None)
    if td is not None:
        names |= set(getattr(td, "params", None) or [])
        names |= set(getattr(td, "doc_param_docs", None) or {})
    return frozenset(_normalize_ident(p) for p in names if p)


def _source_param_doc(c: ToolContract, pname: str) -> str:
    """v4-4 — the description the SOURCE gives a parameter when the schema
    carries none (docstring argument section / ``Field(description=...)``)."""
    td = getattr(getattr(c, "source", None), "tool_def", None)
    docs = getattr(td, "doc_param_docs", None) or {}
    return docs.get(pname) or ""


def _split_tiers(matches: List[Dict[str, str]]):
    actionable = [m for m in matches if m.get("tier") == "actionable"]
    informational = [m for m in matches if m.get("tier") != "actionable"]
    return actionable, informational


def _run_cross_tool_redirect(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    # v3-2.7 — every sibling's own schema property names (see
    # ``_actionable_reason``'s tamper-literal reason).
    sibling_props: Dict[str, frozenset] = {}
    for c2 in ctx.all_contracts():
        if c2.name:
            sibling_props[c2.name.lower()] = _own_prop_names(c2)
    for c in ctx.all_contracts():
        try:
            siblings = _sibling_names(ctx, c.name)
            own_props = _own_prop_names(c)
            seen_actionable, seen_info = set(), set()
            for loc, text in _texts_for(c):
                if not text:
                    continue
                ev_loc, non_std, json_path = _loc_info(loc)
                seen_key = (ev_loc, non_std)
                crosscall = (_check_cross_tool_call(text, siblings, sibling_props, own_props)
                             if siblings else [])
                # v5-2 — a third-party pair outranks any other reading of
                # the same clause (``_dedup_matches`` keeps the first).
                crosscall = _dedup_matches(
                    _check_third_party_pair(text, siblings, own_props, c.name or "")
                    + crosscall + _check_cross_tool_call_quoted(text, own_props))
                actionable, informational = _split_tiers(crosscall)
                if actionable and seen_key not in seen_actionable:
                    seen_actionable.add(seen_key)
                    modes = {m["mode"] for m in actionable}
                    quoted_only = modes == {"quoted-name"}
                    reasons = sorted({m["reason"] for m in actionable if m.get("reason")})
                    rationale = (
                        f"{c.kind} '{c.name}' {loc if loc != 'description' else 'description'} "
                        f"names a {'quoted, tool-identifier-shaped token' if quoted_only else 'SIBLING tool'} "
                        f"('{actionable[0]['sibling']}'"
                        + ("" if quoted_only else ", present in this server's own listing")
                        + ") together with an invoke verb in the same sentence, and the "
                        f"sentence is FORCEFUL ({', '.join(reasons)}) -- directing the agent "
                        "toward invoking a different, specifically-named tool. A "
                        "description's only legitimate job is to describe its OWN tool; "
                        "steering the agent toward another tool's invocation is that "
                        "other tool's job to describe, not this tool's."
                        + (" The named tool is not a current sibling of this server -- it is "
                           "referenced only as a quoted/backticked identifier-shaped literal in "
                           "the prose, the shape MCPTox-style victim-by-name redirects commonly "
                           "use when the victim tool is not co-listed."
                           if quoted_only else "")
                        + (" The sentence relates TWO tools that are both different from "
                           "the one being described ("
                           + ", ".join(sorted({f"'{m['anchor']}' -> '{m['sibling']}'"
                                               for m in actionable if m.get("anchor")}))
                           + "): one anchors a sequence/condition word and the other is "
                           "the call prescribed around it -- an instruction about OTHER "
                           "tools' flow, actionable even without a strong obligation "
                           "word (v5-2)."
                           if "third-party-pair" in reasons else "")
                    )
                    out.append(mk(
                        ctx, detector_id="cross-tool-redirect", category="confused-deputy",
                        evidence_location=ev_loc, severity="high",
                        confidence=_graded_confidence(
                            "medium" if quoted_only else "high", non_std),
                        detection_method="cross-tool-structure-rule" if not quoted_only
                        else "quoted-tool-name-structure-rule",
                        rationale=rationale,
                        evidence=_path_evidence(
                            {"matches": actionable[:5], "sibling_count": len(siblings),
                             "modes": sorted(modes), "reasons": reasons},
                            json_path, non_std),
                        source_kind=_listing_kind(ctx), tool_name=c.name,
                    ))
                elif (informational and seen_key not in seen_info
                      and seen_key not in seen_actionable):
                    # rule 1.1 — the INFORMATIONAL "workflow reference" tier: a
                    # sentence names a sibling/quoted-tool-shaped token with
                    # only a sequence word or a plain imperative (no strong
                    # obligation word, threat of failure, sensitive target,
                    # or "conditions on a different tool" direction) — honest
                    # workflow advice far more often than an attack. Reported
                    # at low severity/confidence (never actionable) so it is
                    # still visible without inflating the precision-relevant
                    # finding count.
                    seen_info.add(seen_key)
                    modes = {m["mode"] for m in informational}
                    out.append(mk(
                        ctx, detector_id="cross-tool-redirect", category="confused-deputy",
                        evidence_location=ev_loc, severity="low", confidence="low",
                        detection_method="cross-tool-workflow-reference",
                        rationale=(
                            f"{c.kind} '{c.name}' {loc if loc != 'description' else 'description'} "
                            f"names another tool ('{informational[0]['sibling']}') alongside a "
                            "plain sequence word/imperative -- honest workflow advice far more "
                            "often than an attack. Reported as an informational workflow "
                            "reference (not actionable) because the sentence carries none of "
                            "the forceful signals (a strong obligation word, a threat of "
                            "failure, a sensitive target, or conditioning on the other tool) "
                            "that would make it a real redirect."
                        ),
                        evidence=_path_evidence(
                            {"matches": informational[:5], "sibling_count": len(siblings),
                             "modes": sorted(modes)}, json_path, non_std),
                        source_kind=_listing_kind(ctx), tool_name=c.name,
                    ))
        except Exception:
            continue
    return out


def _run_param_tampering(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    # v3-2.7 — every sibling's own schema property names, so "the argument
    # named belongs to the OTHER tool" can be checked structurally.
    sibling_props: Dict[str, frozenset] = {}
    for c2 in ctx.all_contracts():
        if c2.name:
            sibling_props[c2.name.lower()] = _own_prop_names(c2)
    for c in ctx.all_contracts():
        try:
            siblings = _sibling_names(ctx, c.name)
            own_props = _own_prop_names(c)
            seen_actionable, seen_info = set(), set()
            for loc, text in _texts_for(c):
                if not text:
                    continue
                ev_loc, non_std, json_path = _loc_info(loc)
                seen_key = (ev_loc, non_std)
                tamper = (_check_param_tampering(text, siblings, sibling_props, own_props)
                          if siblings else [])
                tamper = _dedup_matches(
                    tamper + _check_param_tampering_quoted(text, own_props))
                actionable, informational = _split_tiers(tamper)
                if actionable and seen_key not in seen_actionable:
                    seen_actionable.add(seen_key)
                    modes = {m["mode"] for m in actionable}
                    quoted_only = modes == {"quoted-name"}
                    reasons = sorted({m["reason"] for m in actionable if m.get("reason")})
                    rationale = (
                        f"{c.kind} '{c.name}' {loc if loc != 'description' else 'description'} "
                        f"names a {'quoted, tool-identifier-shaped token' if quoted_only else 'SIBLING tool'} "
                        f"('{actionable[0]['sibling']}') together with a "
                        "tamper verb (modify/change/set/replace/append/redirect/add/insert/"
                        "inject/remove/prepend/...) and an argument word or quoted literal in "
                        f"the same sentence, forcefully framed ({', '.join(reasons)}) -- "
                        "instructing the agent to alter a DIFFERENT tool's own arguments. "
                        "One tool's description has no legitimate authority over another "
                        "tool's parameters."
                        + (" The named tool is not a current sibling of this server -- it is "
                           "referenced only as a quoted/backticked identifier-shaped literal in "
                           "the prose."
                           if quoted_only else "")
                    )
                    out.append(mk(
                        ctx, detector_id="param-tampering", category="confused-deputy",
                        evidence_location=ev_loc, severity="high",
                        confidence=_graded_confidence(
                            "medium" if quoted_only else "high", non_std),
                        detection_method="cross-tool-structure-rule" if not quoted_only
                        else "quoted-tool-name-structure-rule",
                        rationale=rationale,
                        evidence=_path_evidence(
                            {"matches": actionable[:5], "sibling_count": len(siblings),
                             "modes": sorted(modes), "reasons": reasons},
                            json_path, non_std),
                        source_kind=_listing_kind(ctx), tool_name=c.name,
                    ))
                elif (informational and seen_key not in seen_info
                      and seen_key not in seen_actionable):
                    seen_info.add(seen_key)
                    modes = {m["mode"] for m in informational}
                    out.append(mk(
                        ctx, detector_id="param-tampering", category="confused-deputy",
                        evidence_location=ev_loc, severity="low", confidence="low",
                        detection_method="cross-tool-workflow-reference",
                        rationale=(
                            f"{c.kind} '{c.name}' {loc if loc != 'description' else 'description'} "
                            f"names another tool ('{informational[0]['sibling']}') alongside a "
                            "tamper verb and a generic argument word, but with no strong "
                            "obligation word, threat, sensitive target, quoted literal value, "
                            "or conditioning direction -- reported as an informational workflow "
                            "reference, not an actionable parameter-tampering redirect."
                        ),
                        evidence=_path_evidence(
                            {"matches": informational[:5], "sibling_count": len(siblings),
                             "modes": sorted(modes)}, json_path, non_std),
                        source_kind=_listing_kind(ctx), tool_name=c.name,
                    ))
        except Exception:
            continue
    return out


register(Detector(
    id="cross-tool-redirect",
    category="confused-deputy",
    evidence_location="description",
    phase="listing",
    run=_run_cross_tool_redirect,
    requires={CAP_MANIFEST},
    rationale=(
        "A tool's description should describe its own tool. A sentence that "
        "names a sibling tool from the same server's listing, plus an "
        "obligation/sequence word, plus an invoke verb, directs the agent "
        "toward a different tool's invocation -- the classic MCPTox "
        "implicit/explicit hijack shape, detected structurally (the sibling "
        "list, never a hardcoded name) rather than by vocabulary alone."
    ),
))
register(Detector(
    id="param-tampering",
    category="confused-deputy",
    evidence_location="description",
    phase="listing",
    run=_run_param_tampering,
    requires={CAP_MANIFEST},
    rationale=(
        "A sentence names a sibling tool together with a tamper verb "
        "(modify/change/set/replace/append/redirect) and an argument word or "
        "quoted literal -- instructing the agent to alter a different tool's "
        "own arguments. No tool's description has legitimate authority over "
        "another tool's parameters."
    ),
))


# ---------------------------------------------------------------------------
# v5-4 — OUTPUT SUBSTITUTION. A description that tells the agent to run the
# described tool before/after another operation AND to replace, overwrite
# or use that operation's inputs or result with this tool's output is
# steering another operation's data (``textrules.output_substitution_hits``
# holds the two-part shape). Actionable at medium/medium on its own; high
# when either clause carries a strong obligation word or names a sibling
# tool (the operation whose data is being steered is then a concrete,
# co-listed tool). A description that merely says what the tool returns
# has no substitution directive and is not affected.

def _run_output_substitution(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    for c in ctx.all_contracts():
        try:
            siblings = _sibling_names(ctx, c.name)
            patterns = [(nm, _name_pattern(nm)) for nm in siblings]
            seen = set()
            for loc, text in _texts_for(c):
                if not text:
                    continue
                ev_loc, non_std, json_path = _loc_info(loc)
                seen_key = (ev_loc, non_std)
                if seen_key in seen:
                    continue
                hits = output_substitution_hits(text, [c.name or ""])
                if not hits:
                    continue
                seen.add(seen_key)
                scope = " ".join(h["sequence_clause"] + " " + h["substitution_clause"]
                                 for h in hits)
                named = sorted({nm for nm, pat in patterns if pat.search(scope)})
                strong = bool(_STRONG_OBLIGATION_RX.search(scope))
                forceful = strong or bool(named)
                grade = "high" if forceful else "medium"
                reasons = (["strong-obligation-word"] if strong else []) + (
                    ["named-sibling"] if named else [])
                out.append(mk(
                    ctx, detector_id="output-substitution", category="confused-deputy",
                    evidence_location=ev_loc, severity=grade,
                    confidence=_graded_confidence(grade, non_std),
                    detection_method="output-substitution-rule",
                    rationale=(
                        f"{c.kind} '{c.name}' {loc if loc != 'description' else 'description'} "
                        "tells the agent to run this tool before/after another operation "
                        "AND to replace, overwrite or use that operation's inputs or result "
                        "with this tool's output -- steering another operation's data. A "
                        "description may say what its tool returns; it has no authority "
                        "over what the agent does with a different operation's values."
                        + (f" Forceful ({', '.join(reasons)}"
                           + (f": {', '.join(named)}" if named else "") + ")."
                           if forceful else "")
                    ),
                    evidence=_path_evidence(
                        {"matches": hits[:5], "reasons": reasons,
                         "named_siblings": named, "sibling_count": len(siblings)},
                        json_path, non_std),
                    source_kind=_listing_kind(ctx), tool_name=c.name,
                ))
        except Exception:
            continue
    return out


register(Detector(
    id="output-substitution",
    category="confused-deputy",
    evidence_location="description",
    phase="listing",
    run=_run_output_substitution,
    requires={CAP_MANIFEST},
    rationale=(
        "A description that sequences its own tool around another operation "
        "and directs the agent to substitute that operation's inputs or result "
        "with the tool's output is steering data that belongs to a different "
        "operation -- detected by the two-part structure (self-sequencing + a "
        "substitution directive), not by any payload wording."
    ),
))


# ---------------------------------------------------------------------------
# rule 1.6 out-of-scope parameter — a schema field that asks the CALLER for
# information about its own context rather than for a domain input.

# Deliberately narrower than "any bigram containing 'model'/'agent'": a bare
# {"model","name"} or {"agent","name"} is a very common, entirely legitimate
# DOMAIN field (which ML model to invoke, a CRM/support "agent" record) —
# exactly the same "auth" vs "author" collision class Phase 0 fixed (rule P0.1).
# Every bigram below pairs the concept word with a token that specifically
# means "the thing calling/invoking ME" (llm, caller, calling, invoking) or
# is otherwise unambiguous (system+prompt, conversation/chat/message+history,
# tool+list) — a real domain field essentially never uses these compounds.
_SCOPE_CONCEPT_BIGRAMS = [
    {"llm", "name"}, {"llm", "model"}, {"llm", "identity"}, {"llm", "id"},
    {"caller", "model"}, {"calling", "model"}, {"invoking", "model"},
    {"caller", "identity"}, {"caller", "context"},
    {"system", "prompt"},
    {"conversation", "history"}, {"chat", "history"}, {"message", "history"},
    {"tool", "list"}, {"tool", "names"}, {"available", "tools"},
]


def _is_caller_context_name(name: str) -> bool:
    tokens = set(_split_ident_tokens(name))
    if not tokens:
        return False
    for bigram in _SCOPE_CONCEPT_BIGRAMS:
        if bigram.issubset(tokens):
            return True
    return False


# rule P6.7 — a GENERIC side-channel-shaped name (unlike the unambiguous bigrams
# above, one of these words alone is just as often an ordinary, legitimate
# domain field — "context" to search within, a "debug" flag, a "trace" id) is
# only suspicious when source CONFIRMS the parameter is never referenced in
# the tool body at all: a declared field that does nothing but ask is the
# harvesting shape; the identical name genuinely CONSULTED by the body is
# ordinary domain usage and must not be treated the same way.
_GENERIC_SIDE_CHANNEL_TOKENS = frozenset({
    "context", "metadata", "internal", "debug", "trace",
})


def _is_generic_side_channel_name(name: str) -> bool:
    return bool(set(_split_ident_tokens(name)) & _GENERIC_SIDE_CHANNEL_TOKENS)


# v4-4 — a generic side-channel NAME fires only when the parameter is
# unused in source AND its description is empty or is itself caller-context
# shaped: either the explicit caller-context patterns below, or a text whose
# content words (after a closed filler vocabulary) are nothing but the
# side-channel/caller vocabulary ("Debug context.", "Opaque metadata blob
# from the caller."). A described DOMAIN parameter that happens to be unused
# ("The folder to search within") is informational.
_DESC_FILLER_TOKENS = frozenset({
    "the", "a", "an", "of", "for", "to", "from", "any", "optional", "additional",
    "extra", "info", "information", "data", "string", "value", "values", "field",
    "object", "json", "blob", "payload", "arbitrary", "free", "form", "freeform",
    "opaque", "misc", "miscellaneous", "other", "if", "needed", "available",
    "provided", "supplied", "passed", "by", "with", "this", "that", "and", "or",
    "about", "your", "you", "current", "session", "call", "tool", "request", "as",
    "is", "are", "be", "can", "may", "in", "on", "at", "it", "its", "s", "id",
    "ids", "details", "attributes", "key", "keys", "pairs", "map", "dict",
    "dictionary", "set", "list", "array", "include", "included", "when",
    "relevant", "applicable", "useful", "none", "null", "empty", "default",
    "defaults", "anything", "something", "whatever", "else", "more", "extra",
})
_CALLER_WORDS = frozenset({
    "caller", "callers", "calling", "client", "clients", "agent", "agents",
    "model", "models", "assistant", "llm", "invoking", "invoker", "runtime",
    "environment", "env", "system", "prompt", "prompts", "conversation",
    "chat", "history", "diagnostic", "diagnostics", "tracing", "telemetry",
    "logging", "logs", "log", "verbose", "flags", "flag", "mode", "level",
    "hints", "hint", "tags", "tag", "labels", "label", "notes", "note",
    "comments", "comment", "annotations", "annotation", "properties",
    "props", "params", "parameters", "options", "settings", "config",
    "configuration", "state", "stuff", "things", "bag", "extras",
})


def _desc_is_caller_context_shaped(desc: str) -> bool:
    if not (desc or "").strip():
        return True
    if any(p.search(desc) for p in _CALLER_CONTEXT_DESC_PATTERNS):
        return True
    tokens = {t.lower() for t in re.findall(r"[A-Za-z][A-Za-z'\-]*", desc)}
    content = tokens - _DESC_FILLER_TOKENS
    return content <= (_GENERIC_SIDE_CHANNEL_TOKENS | _CALLER_WORDS)


_CALLER_CONTEXT_DESC_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\bname of the (calling|invoking)\s+(model|llm|agent|assistant)\b",
        r"\b(model|llm)\s+name\b[^.!?\n]{0,20}\b(calling|invoking|using)\b",
        r"\bwhich\s+(model|llm|agent)\s+is\s+(calling|invoking|using)\b",
        r"\b(your|the)\s+(system\s+prompt|conversation\s+history|chat\s+history|"
        r"message\s+history)\b",
        r"\blist\s+of\s+(available\s+)?tools\b[^.!?\n]{0,25}\b(you|the\s+agent|the\s+assistant|"
        r"available\s+to\s+you)\b",
        r"\b(caller'?s?|invoking)\s+(model|identity|context)\b",
    ]
]


def _run_scope(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    for c in ctx.tools:  # a "parameter" is a tool-input concept; skip resources/prompts
        try:
            props = (c.input_schema or {}).get("properties") or {}
            if not isinstance(props, dict) or not props:
                continue
            unused = set()
            if c.source is not None and c.source.facts is not None:
                unused = set(getattr(c.source.facts, "unused_params", None) or [])
            have_source = c.source is not None and c.source.facts is not None
            for pname, pspec in props.items():
                if not isinstance(pspec, dict):
                    continue
                pdesc = pspec.get("description") or ""
                # v4-4 — the source's own parameter documentation stands in
                # for an empty schema description.
                if not pdesc.strip():
                    pdesc = _source_param_doc(c, pname)
                name_hit = _is_caller_context_name(pname)
                desc_hit = any(p.search(pdesc) for p in _CALLER_CONTEXT_DESC_PATTERNS)
                never_read = pname in unused
                generic_hit = False
                generic_described = False
                if not (name_hit or desc_hit):
                    # rule P6.7 — a generic side-channel-shaped name is only
                    # even CONSIDERED when source confirms it as unused; a
                    # generic name that's never checked and have_source is
                    # False (no source to confirm either way) is not
                    # reported at all -- the whole point is requiring that
                    # structural corroboration, not guessing from the name
                    # alone. v4-4 — and it is actionable only when the
                    # description is empty or itself caller-context shaped;
                    # a described domain parameter that is unused is
                    # informational.
                    if _is_generic_side_channel_name(pname) and have_source and never_read:
                        if _desc_is_caller_context_shaped(pdesc):
                            generic_hit = True
                        else:
                            generic_described = True
                    else:
                        continue
                if generic_hit:
                    sev, conf = "medium", "medium"
                elif generic_described:
                    sev, conf = "low", "low"
                elif name_hit or desc_hit:
                    # rule P6.7 — an unambiguous caller-context name/description
                    # that the body DOES consult is informational: the body
                    # genuinely using it is evidence of ordinary domain
                    # usage, not harvesting, even though the name/
                    # description still reads as caller-context-shaped.
                    if have_source and not never_read:
                        sev, conf = "low", "low"
                    else:
                        sev = "high" if never_read else "medium"
                        conf = "high" if never_read else "medium"
                out.append(mk(
                    ctx, detector_id="out-of-scope-param", category="information-disclosure",
                    evidence_location="schema", severity=sev, confidence=conf,
                    detection_method="schema-caller-context-rule",
                    rationale=(
                        f"Parameter '{pname}' asks the CALLER (the agent) for information "
                        "about its own context -- the invoking model's name/identity, its "
                        "system prompt, its conversation history, its own tool list, or a "
                        "generic side-channel (context/metadata/internal/debug/trace) -- "
                        "which is out of scope for a tool input; a tool takes domain data, "
                        "it does not harvest facts about the thing calling it."
                        + (" Source confirms the parameter is never referenced anywhere in "
                           "the tool body, so it serves no declared function at all -- the "
                           "harvesting is its only observable purpose."
                           if never_read else "")
                        + (" Source shows the tool body DOES consult this parameter -- "
                           "reported as an informational note, since genuine usage is "
                           "ordinary domain behavior, not harvesting."
                           if (have_source and not never_read and not generic_hit
                               and not generic_described) else "")
                        + (" The parameter is described as a DOMAIN input (its "
                           "description names something other than caller context), "
                           "so an unused generic name is reported as an informational "
                           "note only."
                           if generic_described else "")
                    ),
                    evidence={"param": pname, "description_excerpt": pdesc[:200],
                              "name_shaped": name_hit, "description_shaped": desc_hit,
                              "generic_side_channel": generic_hit or generic_described,
                              "described_domain_param": generic_described,
                              "confirmed_unused_in_source": never_read},
                    source_kind=_listing_kind(ctx), tool_name=c.name,
                ))
        except Exception:
            continue
    return out


register(Detector(
    id="out-of-scope-param",
    category="information-disclosure",
    evidence_location="schema",
    phase="listing",
    run=_run_scope,
    requires={CAP_MANIFEST},
    rationale=(
        "A schema parameter whose name or description asks the calling agent "
        "for information about ITS OWN context (model name, system prompt, "
        "conversation history, tool list) rather than for a domain input is "
        "backwards -- that is caller-context harvesting, not a legitimate "
        "tool argument. Raised to high confidence when source shows the "
        "parameter is never referenced in the function body at all."
    ),
))
