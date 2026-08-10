"""rule 4.1 — cross-server tool-name identity check (the name_overlap/typosquat
class no single-server rule can see).

Every per-server detector in this package reasons about ONE server's own
tool tool listing at a time. When a caller scans SEVERAL servers together (one
``mcp.json`` with multiple entries, or any list of ``ScanContext``s handed
to :func:`compare_tool_names`), this pass instead compares tool names
ACROSS servers: normalize (lowercase, strip non-alphanumerics), strip a
known version/variant suffix (``_v1``, ``-v2``, ``-old``, ``-copy``, ...),
and flag when two DIFFERENT servers expose tool names that are either

* identical once a version/variant suffix is stripped but NOT identical as
  raw strings — one server's tool reads as a suffixed clone of another
  server's tool (the MSB ``name_overlap`` shape: an honestly-described tool
  renamed with a trailing ``_v1``), or
* a genuine character-level near miss (Damerau-Levenshtein distance 1,
  transposition-aware) of a longer tool name on a different server.

Two servers sharing an EXACT, un-suffixed tool name (``search``,
``get_user``) is extremely common and usually entirely benign — many
independent, honest MCP servers implement a `search` or `get_user` tool.
It is still recorded, at LOW severity/confidence and purely informational
(never blocking), because a client that resolves a tool by name alone
cannot otherwise tell the two apart (rule P6.9).

A suffixed-clone match (same base name once a trailing version/variant
marker is stripped, e.g. ``search`` vs. ``search_v1``) is a stronger signal,
but by itself an honest ``search_v2`` can coincidentally sit beside an
unrelated ``search`` on another server. rule P6.9 therefore only flags a
suffix match when the two tools' DESCRIPTIONS are ALSO near-identical —
the shape a genuine copy-with-a-new-suffix clone actually has, since it
carries the original's description text near verbatim. A near-miss
(genuine character-level typo, Damerau-Levenshtein distance 1) is flagged
regardless of description, since that shape has no honest explanation.

This is not a registered per-context ``Detector`` (the registry's contract
is one ``ScanContext`` in, findings out) — it is called once by
``scanner.scan()`` after every target in one batch has its own listing.
"""
from __future__ import annotations

import difflib
import re
from typing import List, Tuple

from ..analysis.editdist import damerau_levenshtein
from ..context import ScanContext
from ..models import Finding
from ._util import mk

# rule P6.9 — a suffix clone is only a real clone when the two tools' DESCRIPTIONS
# are also near-identical (a genuine copy carries the original's description
# text, near verbatim); two unrelated tools that merely happen to normalize
# to the same base name after a version/variant suffix is stripped (e.g. an
# honest "search_v2" alongside a completely different "search" on another
# server) are not a clone. difflib's ratio is a reasonable, dependency-free
# stand-in for "near-identical prose".
_NEAR_IDENTICAL_DESC_THRESHOLD = 0.85


def _desc_similarity(a: str, b: str) -> float:
    a = (a or "").strip().lower()
    b = (b or "").strip().lower()
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()

_VARIANT_SUFFIX_RX = re.compile(
    r"[-_.](?:v\d+|copy|old|new|bak|backup|alt|dup|duplicate|final|draft|test|\d+)$",
    re.IGNORECASE)


def _strip_variant_suffix(name: str) -> str:
    prev = None
    n = name
    while prev != n:
        prev = n
        n = _VARIANT_SUFFIX_RX.sub("", n)
    return n


def _normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (name or "").lower())


def _server_label(ctx: ScanContext) -> str:
    if ctx.server_info and isinstance(ctx.server_info, dict):
        n = ctx.server_info.get("name")
        if isinstance(n, str) and n.strip():
            return n.strip()
    return ctx.target.server_name or ctx.target.target_id or "?"


def _listing_kind(ctx: ScanContext) -> str:
    return "dynamic-runtime" if "dynamic" in ctx.layers else "static-manifest"


def _finding_suffix_clone(ctx_a: ScanContext, name_a: str,
                          ctx_b: ScanContext, name_b: str) -> Finding:
    # attribute the finding to the LONGER (suffixed-looking) side — that is
    # the tool name carrying the extra variant marker.
    if len(name_a) < len(name_b):
        ctx_a, name_a, ctx_b, name_b = ctx_b, name_b, ctx_a, name_a
    return mk(
        ctx_a, detector_id="cross-server-name-overlap", category="tool-shadowing",
        evidence_location="server-identity", severity="high", confidence="medium",
        detection_method="cross-server-suffix-clone",
        rationale=(
            f"Tool '{name_a}' on server '{_server_label(ctx_a)}' normalizes to "
            f"the SAME base name as tool '{name_b}' on a DIFFERENT server "
            f"('{_server_label(ctx_b)}') once a version/variant suffix "
            "(_v1/-copy/-old/-new/...) is stripped — a renamed/suffixed clone "
            "of another server's tool. This is the structural shape behind "
            "the name_overlap attack: a poisoned clone of an honestly-named "
            "tool, distinguished from the original only by a trailing "
            "variant marker most agents/clients never surface to a user."
        ),
        evidence={"tool": name_a, "other_server": _server_label(ctx_b), "other_tool": name_b},
        source_kind=_listing_kind(ctx_a), tool_name=name_a,
    )


def _finding_exact_name_share(ctx_a: ScanContext, name_a: str,
                              ctx_b: ScanContext, name_b: str) -> Finding:
    # rule P6.9 — an EXACT shared tool name across two independently configured
    # servers is extremely common and usually entirely benign (many honest
    # servers implement a "search"/"get_user"); still worth a low-severity
    # informational record (a client that resolves a tool purely by name
    # cannot otherwise tell the two apart), never blocked outright.
    return mk(
        ctx_a, detector_id="cross-server-name-overlap", category="tool-shadowing",
        evidence_location="server-identity", severity="low", confidence="low",
        detection_method="cross-server-exact-name-share",
        rationale=(
            f"Tool '{name_a}' on server '{_server_label(ctx_a)}' shares its "
            f"EXACT declared name with a tool on a DIFFERENT server "
            f"('{_server_label(ctx_b)}') — usually benign (an ordinary verb "
            "name reused by two independent honest servers), recorded as an "
            "informational note since a client resolving a tool purely by "
            "name cannot otherwise distinguish them."
        ),
        evidence={"tool": name_a, "other_server": _server_label(ctx_b), "other_tool": name_b},
        source_kind=_listing_kind(ctx_a), tool_name=name_a,
    )


def _finding_near_miss(ctx_a: ScanContext, name_a: str,
                       ctx_b: ScanContext, name_b: str, dist: int) -> Finding:
    return mk(
        ctx_a, detector_id="cross-server-name-overlap", category="tool-shadowing",
        evidence_location="server-identity", severity="medium", confidence="low",
        detection_method="cross-server-typosquat-editdistance",
        rationale=(
            f"Tool '{name_a}' on server '{_server_label(ctx_a)}' is a "
            f"character-level near miss (edit distance {dist}, transposition-"
            f"aware) of tool '{name_b}' on a DIFFERENT server "
            f"('{_server_label(ctx_b)}') — a typosquat-shaped tool-name "
            "collision between two independently configured servers."
        ),
        evidence={"tool": name_a, "other_server": _server_label(ctx_b),
                  "other_tool": name_b, "distance": dist},
        source_kind=_listing_kind(ctx_a), tool_name=name_a,
    )


def compare_tool_names(ctxs: List[ScanContext]) -> List[Finding]:
    """Pairwise cross-server tool-name comparison over every ``ScanContext``
    in one batch scan. A no-op when fewer than two servers were scanned
    together (the overwhelmingly common single-target case)."""
    out: List[Finding] = []
    if len(ctxs) < 2:
        return out
    entries: List[Tuple[int, str, str]] = []
    for i, ctx in enumerate(ctxs):
        for c in ctx.tools:
            if c.name:
                entries.append((i, c.name, c.description or ""))
    seen_pairs = set()
    for ai in range(len(entries)):
        ia, na, da = entries[ai]
        for bi in range(ai + 1, len(entries)):
            ib, nb, db = entries[bi]
            if ia == ib:
                continue  # same server — a naming-overlap-family concern, not this pass
            key = tuple(sorted([(ia, na), (ib, nb)]))
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            raw_a, raw_b = _normalize(na), _normalize(nb)
            if not raw_a or not raw_b:
                continue
            if raw_a == raw_b:
                # rule P6.9 — exact cross-server name reuse is common and usually
                # benign (two honest servers both naming a tool "search"), but
                # still worth a LOW informational record: a client that
                # resolves a tool purely by name cannot otherwise tell the
                # two apart.
                out.append(_finding_exact_name_share(ctxs[ia], na, ctxs[ib], nb))
                continue
            stripped_a = _normalize(_strip_variant_suffix(na))
            stripped_b = _normalize(_strip_variant_suffix(nb))
            if stripped_a and stripped_b and stripped_a == stripped_b:
                # rule P6.9 — a suffix clone (same base name once a version/variant
                # suffix is stripped) is only flagged when the descriptions are
                # ALSO near-identical. A genuine clone copies the original's
                # description near verbatim; an honest "search_v2" sitting
                # beside an unrelated "search" on another server, with its own
                # distinct description, is not a clone and must not be flagged.
                if _desc_similarity(da, db) >= _NEAR_IDENTICAL_DESC_THRESHOLD:
                    out.append(_finding_suffix_clone(ctxs[ia], na, ctxs[ib], nb))
                continue
            if len(raw_a) >= 6 and len(raw_b) >= 6:
                d = damerau_levenshtein(raw_a, raw_b, cap=2)
                if d == 1:
                    out.append(_finding_near_miss(ctxs[ia], na, ctxs[ib], nb, d))
    return out
