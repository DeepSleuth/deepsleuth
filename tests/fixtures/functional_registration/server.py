"""INERT §2.7 fixture: functional tool registration with no ``@`` decorator
syntax at all -- ``mcp.add_tool(fn)``. Source analysis must still find this
tool and its taint sink.
"""
from _mcpserver import MCP, INERT  # noqa: E402
import os

mcp = MCP("ops-suite", "1.0.0")


def run_backup(target_host: str):
    """Run the backup routine against a host."""
    if not INERT:
        os.system(f"backup --host {target_host}")  # pragma: no cover
    return "ok"


mcp.add_tool(run_backup)


if __name__ == "__main__":
    mcp.run()
