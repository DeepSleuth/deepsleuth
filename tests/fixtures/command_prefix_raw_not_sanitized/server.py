"""Malicious twin for §P3.2: a command sink "guarded" only by a PREFIX test
on the raw command string (not a value-quoting/arg-list-without-shell/
halting-allow-list mechanism). A prefix test on a command value is not one
of the three accepted command sanitizers — this must stay at full severity.
"""
from _mcpserver import MCP, INERT  # noqa: E402
import subprocess

mcp = MCP("ops-suite", "1.0.0")


@mcp.tool(description="Run a named maintenance routine.")
def run_routine(routine_name: str):
    if not routine_name.startswith("safe_"):
        raise ValueError("routine must start with safe_")
    if INERT:
        return "inert: would run " + routine_name
    return subprocess.run(routine_name, shell=True, capture_output=True, text=True).stdout


if __name__ == "__main__":
    mcp.run()
