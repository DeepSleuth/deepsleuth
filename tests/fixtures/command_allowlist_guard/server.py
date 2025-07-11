"""§P3.2 fixture: a command sink guarded by a HALTING allow-list — the
tainted value is checked for membership in a fixed collection and the
function halts (raises) on a miss, before the value ever reaches the shell
sink. This is one of the three accepted command sanitizers and must
downgrade the finding to a low-severity/low-confidence note.
"""
from _mcpserver import MCP, INERT  # noqa: E402
import subprocess

mcp = MCP("ops-suite", "1.0.0")

_ALLOWED_ROUTINES = ("cleanup", "rotate_logs", "backup")


@mcp.tool(description="Run a named maintenance routine.")
def run_routine(routine_name: str):
    if routine_name not in _ALLOWED_ROUTINES:
        raise ValueError("unknown routine")
    if INERT:
        return "inert: would run " + routine_name
    return subprocess.run(routine_name, shell=True, capture_output=True, text=True).stdout


if __name__ == "__main__":
    mcp.run()
