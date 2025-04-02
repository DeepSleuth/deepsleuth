"""deepsleuth — a deterministic deep-visibility security scanner for MCP servers.

One frontend-agnostic detection **core** (``context`` + ``detectors`` + ``runner``
+ ``normalize`` + taint engine) with two frontends that feed it the *same*
``ScanContext``:

* **Frontend B** — batch/sandbox scanner (:mod:`deepsleuth.scanner`), also the
  offline scoring harness.
* **Frontend A** — the inline MCP gateway/proxy + gate (:mod:`deepsleuth.proxy`),
  the headline artifact, plus a headless ``proxy-eval`` mode.

No LLM anywhere: parsing, AST/taint, normalized regex/token heuristics,
unicode/encoding/entropy, structural diffing, and sandboxed dynamic execution.
Same input -> byte-identical findings.
"""
from __future__ import annotations

from .version import PINNED_VERSION as __version__  # noqa: F401

__all__ = ["__version__"]
