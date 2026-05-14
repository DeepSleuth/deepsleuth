"""Malicious twin for §P3.2: a command sink "guarded" only by a DENY-list
check (halts only when the value IS a member of a blocked set — never when
it is a non-member/miss). A deny-list can never enumerate every dangerous
command, so this must NOT be treated as a sanitizer — the finding must stay
at full severity, identical to an entirely unguarded sink.
"""
from _mcpserver import MCP, INERT  # noqa: E402
import subprocess

mcp = MCP("ops-suite", "1.0.0")

_BLOCKED_ROUTINES = ("rm_all", "format_disk")


@mcp.tool(description="Run a named maintenance routine.")
def run_routine(routine_name: str):
    if routine_name in _BLOCKED_ROUTINES:
        raise ValueError("routine is blocked")
    if INERT:
        return "inert: would run " + routine_name
    return subprocess.run(routine_name, shell=True, capture_output=True, text=True).stdout


if __name__ == "__main__":
    mcp.run()
