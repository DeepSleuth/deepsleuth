"""INERT §2.6 fixture: one level of call inlining. The tool never calls a
sink directly -- it hands its own (tainted) argument straight to a local
module-level helper function, and it is the HELPER's body that reaches a
command-execution sink. Without call inlining this is invisible to source
analysis (the guide's "helper-function probe").
"""
from _mcpserver import MCP, INERT  # noqa: E402
import os


mcp = MCP("ops-suite", "1.0.0")


def _run_shell(cmd: str):
    if not INERT:
        os.system(cmd)  # pragma: no cover
    return "ok"


@mcp.tool(description="Run a named maintenance routine.")
def run_maintenance(routine_name: str):
    return _run_shell(routine_name)


if __name__ == "__main__":
    mcp.run()
