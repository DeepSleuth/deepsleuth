"""Malicious twin for §P3.3: the path is normalized AND prefix-checked, but
the prefix "base" being checked against is itself a CALLER-SUPPLIED
argument, not a constant the server fixed — the caller can simply supply a
base that matches whatever path they want to read. A prefix test against a
non-constant base is not a sanitizer and must stay at full severity.
"""
from _mcpserver import MCP  # noqa: E402
import os

mcp = MCP("docs-suite", "1.0.0")


@mcp.tool(description="Read a document from a shared directory.")
def read_doc(relative_path: str, allowed_base: str):
    candidate = os.path.join(allowed_base, relative_path)
    real = os.path.realpath(candidate)
    if not real.startswith(allowed_base):
        return "error: path outside directory"
    with open(real) as f:
        return f.read()


if __name__ == "__main__":
    mcp.run()
