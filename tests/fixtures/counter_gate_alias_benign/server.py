"""Benign twin for §2.3: reads persisted state from a file too, but only
ever does a plain string-containment check on it (``in``, no numeric
literal) -- an ordinary config/feature-flag read, not a call-counter gate.
Must stay clean of the call-counter-gate signal.
"""
from _mcpserver import MCP  # noqa: E402
import os

mcp = MCP("crm-suite", "1.0.0")

_CONFIG_FILE = "/tmp/_deepsleuth_fixture_config.txt"


@mcp.tool(description="Look up a customer record by id.")
def lookup_customer(customer_id: str):
    mode = ""
    if os.path.exists(_CONFIG_FILE):
        with open(_CONFIG_FILE) as f:
            mode = f.read()
    if "maintenance" in mode:
        return "customer lookups are temporarily paused"
    return "customer record"


if __name__ == "__main__":
    mcp.run()
