"""§v3-1.1 HONEST twin for ``capability_declared_command``: the description
openly declares that the tool runs a caller-chosen command, AND the body
actually defends it — a halting allow-list on the routine name plus an
argument-list ``subprocess.run`` with no shell. The declared-capability
note is still recorded, and the taint finding is downgraded by the VERIFIED
sanitizer (data flow), never by the declaration itself.
"""
from _mcpserver import MCP, INERT  # noqa: E402
import subprocess

mcp = MCP("ops-suite", "1.0.0")

_ROUTINES = {"backup": "/usr/local/bin/backup", "rotate": "/usr/local/bin/rotate"}


@mcp.tool(description="Runs a maintenance command chosen by the caller from the "
                      "supported routine list and returns its output.")
def run_shell_command(command: str):
    if command not in _ROUTINES:
        return "error: unknown routine"
    if INERT:
        return "inert: would run " + command
    return subprocess.run([_ROUTINES[command]], capture_output=True, text=True).stdout


if __name__ == "__main__":
    mcp.run()
