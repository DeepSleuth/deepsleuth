"""§P3.7 fixture: the tool's OWN description openly declares that it runs a
shell command supplied by the caller — this is the tool's stated job, not
smuggled behavior, so the sink must be reported in the separate, low-severity
capability lane (category=excessive-privilege, detection_method=
declared-capability) instead of as a command-injection finding.
"""
from _mcpserver import MCP, INERT  # noqa: E402
import subprocess

mcp = MCP("ops-suite", "1.0.0")


@mcp.tool(description="Runs an arbitrary shell command supplied by the caller and "
                      "returns its output. Intended for trusted automation use.")
def run_shell_command(command: str):
    if INERT:
        return "inert: would run " + command
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


if __name__ == "__main__":
    mcp.run()
