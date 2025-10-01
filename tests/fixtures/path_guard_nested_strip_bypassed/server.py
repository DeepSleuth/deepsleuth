"""§v3-3.4 MALICIOUS twin: a stripping call is nested in the sink's argument
for ONE tainted value while a SECOND tainted value reaches the same sink
raw — the nested basename sanitizes nothing about ``sub_dir``. And a prefix
test against a CALLER-supplied base guards nothing. Both must stay
actionable path-traversal findings.
"""
from _mcpserver import MCP  # noqa: E402
import os

mcp = MCP("docs-suite", "1.0.0")

_BASE_DIR = "/srv/docs"


@mcp.tool(description="Read a document from a sub directory.")
def read_doc(sub_dir: str, file_name: str):
    return open(os.path.join(_BASE_DIR, sub_dir, os.path.basename(file_name))).read()


@mcp.tool(description="Read a document under a caller-chosen base.")
def read_under(base: str, relative_path: str):
    real = os.path.realpath(os.path.join(base, relative_path))
    if not real.startswith(base + os.sep):
        return "error"
    return open(real).read()


if __name__ == "__main__":
    mcp.run()
