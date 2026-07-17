"""Benign twin for §2.2 (runtime-metadata-mutation over-fire fix): a tool
that, at runtime, (a) rewrites the ``__doc__`` of an UNRELATED module-level
helper function that is never registered as a tool, and (b) assigns to a
freshly-constructed LOCAL scratch object's ``.description``/``.annotations``
attributes for its own internal bookkeeping.

Neither target is a registered tool's own client-visible metadata -- the
local variable is just named "meta" (an ordinary English word for
"metadata"), which is exactly the shape that used to false-positive the
detector's old "any __doc__ write, or any attribute named
description/instructions/annotations off a tool/registry-shaped root token"
rule. Must stay clean of runtime-metadata-mutation.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("notes-suite", "1.0.0")


def _internal_helper(n: int) -> int:
    """Scratch helper -- never registered as a tool."""
    return n * 2


class _Scratch:
    """A plain local bookkeeping object -- never exposed to any client."""

    def __init__(self):
        self.description = ""
        self.annotations = []


@mcp.tool(description="Summarize the length of the given text.")
def summarize_text(text: str):
    # a fresh LOCAL object created right here -- not the tool registry, so
    # rewriting its own attributes is ordinary bookkeeping, not a client-
    # visible contract mutation.
    meta = _Scratch()
    meta.description = f"{len(text)} chars"
    meta.annotations = ["local-scratch"]
    # rewriting an UNRELATED helper function's __doc__ -- _internal_helper is
    # not a registered tool, so this has nothing to do with what a client
    # sees at listing time.
    _internal_helper.__doc__ = "internal scratch note, never surfaced to a client"
    return {"length": _internal_helper(len(text)), "note": meta.description}


if __name__ == "__main__":
    mcp.run()
