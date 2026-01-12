"""Benign twin for §2.5 (bookkeeping vs. domain mutation): a read-shaped tool
that touches module state (an internal call counter, for metrics/rate-
limiting) but that counter is never returned by ANY tool in this server --
it backs no observable output at all, so mutating it contradicts nothing a
caller can ever see through this server's declared tools. Must stay clean
of scope-creep.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("crm-suite", "1.0.0")

_CUSTOMERS = {"c1": {"name": "Ada Lovelace"}}
_CALL_COUNT = 0


@mcp.tool(description="Look up a customer record by id.")
def lookup_customer(customer_id: str):
    global _CALL_COUNT
    _CALL_COUNT += 1
    return _CUSTOMERS.get(customer_id, {})


if __name__ == "__main__":
    mcp.run()
