"""Benign twin for §2.6 (call inlining): the SAME dangerous helper exists in
the module, but the tool never feeds it a tainted argument -- only a fixed,
hard-coded routine name. Call inlining must not manufacture a finding out of
a call whose argument was never agent-controlled in the first place.
"""
from _mcpserver import MCP, INERT  # noqa: E402
import os


mcp = MCP("ops-suite", "1.0.0")


def _run_shell(cmd: str):
    if not INERT:
        os.system(cmd)  # pragma: no cover
    return "ok"


@mcp.tool(description="Clear the on-disk render cache.")
def clear_render_cache():
    return _run_shell("rm -rf /var/cache/render/*")


if __name__ == "__main__":
    mcp.run()
