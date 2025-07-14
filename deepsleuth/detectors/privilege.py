"""rule 5.4 — privilege / scope-creep / hint violations.

This is the sharpest, most-generalizing signal in the brief: the tool's *declared
contract* (readOnlyHint / destructiveHint, or a read-only-shaped tool description)
versus the *behavior its implementation actually exhibits*. A tool that declares
``readOnlyHint: true`` but writes files, deletes, spawns processes, executes code
or mutates server state is a confirmed contradiction — high confidence, and it
does not depend on any specific wording, so it generalizes.
"""
from __future__ import annotations

import re
from typing import List

from ..analysis.pyast import collect_exposed_state_globals
from ..context import ScanContext, ToolContract
from ..models import Finding
from .base import CAP_SOURCE, Detector, register
from ._util import mk

# description "shape" verbs (over normalized-ish lowercase text). v3 — the
# verb classes are INFLECTED (gets/runs/deletes/executing/...): the base-
# form-only lists read "Runs a maintenance command ... from the routine
# list" as read-shaped (only "list" matched), so an honest exec tool whose
# description happened to be written in the third person fired scope-creep.
READ_VERBS = re.compile(
    r"\b(get|gets|getting|list|lists|tool listing|read|reads|reading|fetch|fetches|"
    r"fetching|show|shows|showing|search|searches|searching|query|queries|"
    r"querying|look\s?up|looks\s?up|retriev\w+|view|views|viewing|display|"
    r"displays|displaying|describe|describes|describing|check|checks|checking|"
    r"find|finds|finding|count|counts|counting|summar\w+|report|reports|"
    r"reporting|inspect|inspects|inspecting|analyz\w+|analys\w+|calculate|"
    r"calculates|calculating|convert|converts|converting)\b",
    re.IGNORECASE)
WRITE_VERBS = re.compile(
    r"\b(write|writes|writing|create|creates|creating|update|updates|updating|"
    r"delete|deletes|deleting|remove|removes|removing|modify|modifies|modifying|"
    r"edit|edits|editing|set|sets|insert|inserts|inserting|drop|drops|dropping|"
    r"send|sends|sending|post|posts|posting|execute|executes|executing|run|runs|"
    r"running|install|installs|installing|deploy|deploys|deploying|move|moves|"
    r"moving|rename|renames|renaming|upload|uploads|uploading|purge|purges|"
    r"purging|truncate|truncates|truncating|reset|resets|resetting|revoke|"
    r"revokes|revoking|revoked|"
    # v4-2 — write verbs the read-shape test used to miss (the
    # unambiguous ones; see ``_AMBIGUOUS_WRITE_RX`` for record/mark/credit/
    # debit/charge/grant, which are just as often nouns).
    r"apply|applies|applied|applying|register|registers|registered|"
    r"registering|assign|assigns|assigned|assigning|submit|submits|"
    r"submitted|submitting|increment|increments|incremented|incrementing|"
    r"enroll|enrolls|enrolled|enrolling|activate|activates|activated|"
    r"activating|deactivate|deactivates|deactivated|deactivating)\b",
    re.IGNORECASE)

# v4-2 — write verbs that are equally common as NOUNS in a description
# ("a customer record", "the mark", "store credit", "a service charge",
# "a grant"). They count as a write verb only in VERB POSITION, decided by
# the word that precedes them in the clause: nothing (clause-initial
# imperative / third person: "Records the ...", "Marks it reviewed"), or a
# conjunction / modal / infinitive marker / subject pronoun ("and marks",
# "will charge", "to record", "it credits"). Their -ed/-ing forms count
# after an auxiliary or the same leaders ("is recorded", "and marked",
# "after charging"), never after a determiner or a noun ("the recorded
# value", "items marked done" — adjectival).
_AMBIGUOUS_WRITE_RX = re.compile(
    r"\b(record|records|mark|marks|credit|credits|debit|debits|charge|charges|"
    r"grant|grants)\b", re.IGNORECASE)
_AMBIGUOUS_WRITE_PARTICIPLE_RX = re.compile(
    r"\b(recorded|recording|marked|marking|credited|crediting|debited|debiting|"
    r"charged|charging|granted|granting)\b", re.IGNORECASE)
_VERB_POSITION_LEADERS = frozenset({
    "and", "or", "then", "also", "to", "will", "can", "may", "must", "should",
    "shall", "would", "could", "it", "that", "which", "automatically",
    "optionally", "silently", "always", "never", "additionally", "finally",
    "first", "not", "does", "do", "doesn't", "don't", "may", "might",
})
_PARTICIPLE_LEADERS = _VERB_POSITION_LEADERS | frozenset({
    "is", "are", "be", "been", "being", "was", "were", "get", "gets", "got",
    "has", "have", "had", "after", "before", "while", "by", "without", "when",
    "upon", "once",
})
_CLAUSE_BREAK = ".;:!?()[]{}\n-\u2013\u2014"


def _prev_word(text: str, idx: int):
    """The word right before ``text[idx]`` in the same clause, lowercased;
    None when the match opens the clause."""
    i = idx - 1
    while i >= 0 and text[i].isspace():
        i -= 1
    if i < 0 or text[i] in _CLAUSE_BREAK:
        return None
    j = i
    while j >= 0 and (text[j].isalnum() or text[j] in "'_"):
        j -= 1
    word = text[j + 1:i + 1].lower()
    return word or None


def _write_verb_present(desc: str) -> bool:
    if WRITE_VERBS.search(desc):
        return True
    for m in _AMBIGUOUS_WRITE_RX.finditer(desc):
        prev = _prev_word(desc, m.start())
        if prev is None or prev in _VERB_POSITION_LEADERS:
            return True
    for m in _AMBIGUOUS_WRITE_PARTICIPLE_RX.finditer(desc):
        prev = _prev_word(desc, m.start())
        if prev is None or prev in _PARTICIPLE_LEADERS:
            return True
    return False

# behaviors that contradict a read-only claim
MUTATING = {"writes-filesystem", "deletes-files", "spawns-process",
            "code-execution", "mutates-server-state"}


def _desc_is_read_shaped(desc: str) -> bool:
    """Read-shaped = contains a read verb and NO write verb (v4-2: the
    write-verb class covers apply/register/record/mark/grant/revoke/assign/
    submit/increment/charge/credit/debit/enroll/activate/deactivate and
    their inflections too)."""
    if not desc:
        return False
    return bool(READ_VERBS.search(desc)) and not _write_verb_present(desc)


def _run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    # rule 2.5 — every module-global ANY tool in this server actually returns,
    # computed once. A tool whose only "mutation" touches a global no tool
    # ever exposes is pure bookkeeping (a call counter, an internal cache),
    # not a domain-visible side effect a read-only/non-mutating claim would
    # contradict.
    exposed_globals: set = set()
    for _path, tree, _text, _g in getattr(ctx, "source_modules", []):
        try:
            exposed_globals |= collect_exposed_state_globals(tree)
        except Exception:
            continue
    for c in ctx.all_contracts():
        if not c.source:
            continue
        labels = c.source.facts.behavior_labels()
        if c.source.facts.network:
            labels_with_net = labels | {"network-access"}
        else:
            labels_with_net = labels
        mutating = labels & MUTATING

        ro = c.declared_readonly()
        destructive = c.declared_destructive()

        # 1) explicit readOnlyHint contradicted by mutating behavior
        if ro is True and (mutating or c.source.facts.network):
            offend = sorted(mutating) or (["network-access"] if c.source.facts.network else [])
            sev = "high" if mutating else "medium"
            out.append(mk(
                ctx, detector_id="hint-violation", category="excessive-privilege",
                evidence_location="source", severity=sev, confidence="high",
                detection_method="hint-vs-behavior-diff",
                rationale=("Tool declares readOnlyHint=true but its implementation "
                           f"performs {', '.join(offend)} — declared contract "
                           "contradicts implemented behavior."),
                evidence={"declared": {"readOnlyHint": True},
                          "observed_behavior": sorted(labels_with_net),
                          "offending_behavior": offend,
                          "module": c.source.module_path},
                source_kind="static-code", tool_name=c.name,
            ))
            continue

        # 2) explicit destructiveHint=false contradicted by deletion/overwrite.
        # rule 2.4 widens this past file-deletion to any DOMAIN-state overwrite/
        # deletion ("mutates-server-state") too — "non-destructive" is a
        # claim about the tool's *effect*, not just about the filesystem, and
        # a hidden overwrite of an existing record is exactly as destructive
        # as deleting it (mcp02-m03: a "refresh cache" tool that silently
        # overwrites the real content it claims only to refresh a view of).
        if destructive is False and ("deletes-files" in labels
                                     or "mutates-server-state" in labels):
            offend = sorted(labels & {"deletes-files", "mutates-server-state"})
            out.append(mk(
                ctx, detector_id="hint-violation", category="excessive-privilege",
                evidence_location="source", severity="high", confidence="high",
                detection_method="hint-vs-behavior-diff",
                rationale=("Tool declares destructiveHint=false but its "
                           f"implementation performs {', '.join(offend)} — an "
                           "overwrite/deletion of existing state is exactly as "
                           "destructive as deleting a file, whatever the "
                           "description calls it."),
                evidence={"declared": {"destructiveHint": False},
                          "observed_behavior": sorted(labels),
                          "offending_behavior": offend,
                          "module": c.source.module_path},
                source_kind="static-code", tool_name=c.name,
            ))
            continue

        # rule 2.4 — idempotentHint=true contradicted by an ACCUMULATING update:
        # a counter/balance incremented in place (``credits += 5``) or a
        # collection grown (``.append``/``.extend``/``.insert``/``.add`` on
        # state) means calling the SAME tool with the SAME arguments twice
        # does NOT leave the server in the same state as calling it once —
        # the literal definition idempotentHint asserts is false of.
        idempotent = c.hints.get("idempotentHint")
        if idempotent is True and c.source.facts.accumulates_state:
            out.append(mk(
                ctx, detector_id="hint-violation", category="excessive-privilege",
                evidence_location="source", severity="high", confidence="high",
                detection_method="hint-vs-behavior-diff",
                rationale=("Tool declares idempotentHint=true but its "
                           "implementation accumulates state (an in-place "
                           "increment/decrement or a collection append/extend/"
                           "insert/add on server state) — repeating the same "
                           "call changes the result again each time, which is "
                           "the definition idempotentHint claims does not hold."),
                evidence={"declared": {"idempotentHint": True},
                          "accumulation_snippets": c.source.facts.accumulation_snippets[:3],
                          "module": c.source.module_path},
                source_kind="static-code", tool_name=c.name,
            ))
            continue

        # rule 2.4 — openWorldHint=false contradicted by an actual network call.
        # openWorldHint=false asserts the tool operates in a closed, known
        # universe (no reaching out to the open internet) — network access is
        # a direct contradiction of that claim, independent of read/write
        # shape.
        open_world = c.hints.get("openWorldHint")
        if open_world is False and c.source.facts.network:
            out.append(mk(
                ctx, detector_id="hint-violation", category="excessive-privilege",
                evidence_location="source", severity="medium", confidence="high",
                detection_method="hint-vs-behavior-diff",
                rationale=("Tool declares openWorldHint=false (a closed, known "
                           "universe of effects) but its implementation makes a "
                           "network call — a direct contradiction of that claim."),
                evidence={"declared": {"openWorldHint": False},
                          "observed_behavior": sorted(labels_with_net),
                          "module": c.source.module_path},
                source_kind="static-code", tool_name=c.name,
            ))
            continue

        # 3) no hints, but a read-shaped description contradicted by mutation.
        # rule 2.5 — when the ONLY mutating label is "mutates-server-state" (no
        # file write/delete/exec/network alongside it), check whether it is
        # DOMAIN-visible: does the specific global(s) this tool touched get
        # returned by ANY tool at all? A counter/cache no tool ever exposes
        # is bookkeeping, not a contradiction of a read-only claim.
        bookkeeping_only = False
        if mutating == {"mutates-server-state"}:
            touched = set(c.source.facts.mutated_state_names)
            bookkeeping_only = bool(touched) and not (touched & exposed_globals)
        if ro is None and _desc_is_read_shaped(c.description) and mutating and not bookkeeping_only:
            out.append(mk(
                ctx, detector_id="scope-creep", category="excessive-privilege",
                evidence_location="source", severity="medium", confidence="medium",
                detection_method="contract-vs-behavior-diff",
                rationale=("Description reads as a read-only/query operation but the "
                           f"implementation performs {', '.join(sorted(mutating))} — "
                           "capability exceeds the described scope."),
                evidence={"description_excerpt": c.description[:200],
                          "observed_behavior": sorted(labels),
                          "module": c.source.module_path},
                source_kind="static-code", tool_name=c.name,
            ))
    return out


register(Detector(
    id="hint-violation",
    category="excessive-privilege",
    evidence_location="source",
    phase="listing",
    run=_run,
    requires={CAP_SOURCE},
    rationale=(
        "Annotation hints and descriptions are self-asserted; cross-checking them "
        "against what the implementation actually does turns a self-report into a "
        "verifiable contradiction. Because it keys on the *mismatch* rather than any "
        "particular behavior or phrase, a benign tool that writes files for its "
        "stated purpose is not flagged, while a 'read-only' tool that mutates is."
    ),
))
