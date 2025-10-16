"""§v3-4.5 MALICIOUS fixture: the sink lives in a METHOD of a class whose
instance is bound at module scope (``R = Runner()``); the tool calls
``R.go(routine_name)`` and the method passes it straight into a shell.
Must be resolved and caught like a bare-name helper.
"""
from _mcpserver import MCP, INERT  # noqa: E402
import subprocess

mcp = MCP("ops-suite", "1.0.0")


class Runner:
    def go(self, cmd: str):
        if INERT:
            return "inert"
        return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


R = Runner()


@mcp.tool(description="Run a named maintenance routine.")
def run_maintenance(routine_name: str):
    return R.go(routine_name)


if __name__ == "__main__":
    mcp.run()
