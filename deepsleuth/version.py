"""Version / provenance helpers.

The output schema requires ``source.version_or_commit`` to be the git sha of
the scanner. We resolve it deterministically at runtime, falling back to a pinned
string when git metadata is unavailable (e.g. when shipped as a tarball).
"""
from __future__ import annotations

import os
import subprocess
import functools

SCANNER_NAME = "deepsleuth"
PINNED_VERSION = "0.3.0"


@functools.lru_cache(maxsize=1)
def git_commit() -> str:
    """Return the current git sha, or the pinned version if git is unavailable."""
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=here,
            capture_output=True,
            text=True,
            timeout=5,
        )
        sha = out.stdout.strip()
        if out.returncode == 0 and sha:
            return sha
    except Exception:
        pass
    return PINNED_VERSION
