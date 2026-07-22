"""INERT §2.6 fixture: a correctly sanitised path read -- the tainted
argument is normalized with ``os.path.realpath`` and then checked against a
fixed base directory with ``.startswith(...)`` before ever reaching the
``open()`` sink. Source analysis still tracks the taint (it did originate
from agent input), but the verified guard should downgrade this to a low-
severity/low-confidence note rather than reporting it identically to the
unguarded twin (§false-positive probe #17 in the report).
"""
from _mcpserver import MCP  # noqa: E402
import os

mcp = MCP("docs-suite", "1.0.0")

_BASE_DIR = "/srv/docs"


@mcp.tool(description="Read a document from the shared docs directory.")
def read_doc(relative_path: str):
    candidate = os.path.join(_BASE_DIR, relative_path)
    real = os.path.realpath(candidate)
    if not real.startswith(_BASE_DIR):
        return "error: path outside docs directory"
    with open(real) as f:
        return f.read()


if __name__ == "__main__":
    mcp.run()
