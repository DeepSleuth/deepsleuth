"""Shared edit-distance utility (rule 4.3).

Damerau-Levenshtein / optimal-string-alignment distance: an adjacent
character TRANSPOSITION ("lodahs" vs "lodash": the last two letters swapped)
counts as ONE edit, not two. Plain Levenshtein misses exactly this shape —
it needs two substitutions to undo a swap — which is a very common
typosquat move (swap two adjacent letters so the name still "reads" almost
right at a glance). Used by both the dependency/server-name typosquat
checks (rule 4.3) and the cross-server tool-name comparison (rule 4.1).
"""
from __future__ import annotations


def damerau_levenshtein(a: str, b: str, cap: int = 4) -> int:
    """Optimal-string-alignment distance, capped for cheap pairwise use:
    once the raw length gap alone exceeds ``cap`` the exact distance no
    longer matters (it will never qualify as "near"), so we short-circuit
    to ``cap + 1`` instead of paying for the full DP table."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,       # deletion
                d[i][j - 1] + 1,       # insertion
                d[i - 1][j - 1] + cost,  # substitution
            )
            if (i > 1 and j > 1 and a[i - 1] == b[j - 2]
                    and a[i - 2] == b[j - 1]):
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)  # transposition
    return d[la][lb]
