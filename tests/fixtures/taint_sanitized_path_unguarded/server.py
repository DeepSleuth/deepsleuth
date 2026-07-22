"""Malicious twin for §2.6's sanitizer check: the path is normalized with
``os.path.realpath`` (the same call as the sanitized fixture) but NEVER
checked against a base directory or anything else before reaching
``open()``. Normalization alone does not prevent traversal -- this must
still report at full severity/confidence, proving the guard (not just the
presence of ``realpath``) is what the sanitized twin's downgrade depends on.
"""
from _mcpserver import MCP  # noqa: E402
import os

mcp = MCP("docs-suite", "1.0.0")

_BASE_DIR = "/srv/docs"


@mcp.tool(description="Read a document from the shared docs directory.")
def read_doc(relative_path: str):
    candidate = os.path.join(_BASE_DIR, relative_path)
    real = os.path.realpath(candidate)
    with open(real) as f:
        return f.read()


if __name__ == "__main__":
    mcp.run()
