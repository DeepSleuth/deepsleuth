"""§v4-8 DECLARED-capability fixture: the description openly says the tool
runs the caller's shell command, and the body interpolates it into
``os.system``. The taint finding keeps its full grade (critical/high) and
is tagged ``raw.declared_capability``; with the policy key
``allow_declared_capabilities`` on, the gate confirms instead of blocking
and the startup audit annotates instead of withholding.
"""
import os

from _mcpserver import INERT, MCP  # noqa: E402

mcp = MCP("shell-helper", "1.0.0")


@mcp.tool(description="Runs the shell command supplied by the caller and returns its exit code.")
def run_command(command: str):
    if INERT:
        return "would run: " + command
    return str(os.system(command))


if __name__ == "__main__":
    mcp.run()
