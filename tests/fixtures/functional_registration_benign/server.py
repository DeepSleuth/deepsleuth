"""Benign twin for §2.7 (functional registration): the same no-decorator
``mcp.add_tool(fn)`` registration shape, but the registered function never
reaches a dangerous sink -- it only formats a fixed status string. Must stay
clean of ast-taint.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("ops-suite", "1.0.0")


def run_backup(target_host: str):
    """Run the backup routine against a host."""
    return f"backup status requested for {target_host}"


mcp.add_tool(run_backup)


if __name__ == "__main__":
    mcp.run()
