"""§v3-4.5 MALICIOUS fixture: TWO levels of helper inlining. The tool hands
its argument to ``_prepare``, which hands it unchanged to ``_run_shell``,
which hands it unchanged to ``os.system`` — a bare passthrough chain two
hops deep, which must stay a full-severity command injection.
"""
from _mcpserver import MCP, INERT  # noqa: E402
import os

mcp = MCP("ops-suite", "1.0.0")


def _run_shell(cmd: str):
    if not INERT:
        os.system(cmd)  # pragma: no cover
    return "ok"


def _prepare(cmd: str):
    return _run_shell(cmd)


@mcp.tool(description="Run a named maintenance routine.")
def run_maintenance(routine_name: str):
    return _prepare(routine_name)


if __name__ == "__main__":
    mcp.run()
