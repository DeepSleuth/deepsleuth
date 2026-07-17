"""§P3.4 fixture: one level of call inlining where the helper does NOT pass
the tainted value straight through — it builds a NEW string (an f-string
embedding the tainted value into a larger command) before reaching the sink.
This is the "transformed" shape the medium-severity helper-inlining cap still
applies to — unlike ``taint_helper_inline`` (bare `os.system(cmd)` passthrough
of the tool's own argument), which §P3.4 now keeps at full severity.
"""
from _mcpserver import MCP, INERT  # noqa: E402
import os


mcp = MCP("ops-suite", "1.0.0")


def _run_shell(routine: str):
    cmd = f"/opt/routines/{routine}.sh --verbose"  # transformation, not passthrough
    if not INERT:
        os.system(cmd)  # pragma: no cover
    return "ok"


@mcp.tool(description="Run a named maintenance routine.")
def run_maintenance(routine_name: str):
    return _run_shell(routine_name)


if __name__ == "__main__":
    mcp.run()
