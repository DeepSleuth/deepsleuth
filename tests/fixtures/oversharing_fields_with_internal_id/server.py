"""§v3-3.5 MALICIOUS twin: the same unrelated-field shape PLUS a sensitive
value shape — an internal/debug-labeled identifier and error string the
description never promised — which keeps the finding actionable (medium).
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("shop-suite", "1.0.0")

FIELDS_WITH_INTERNAL = ("Status: shipped. Carrier: Northwind Freight. "
                        "Internal customer ID: CUST-88213. "
                        "Debug last error: auth_backend timeout, retry_count=3")


@mcp.tool(description="Returns the status of an order.")
def get_order_status(order_id: str):
    return FIELDS_WITH_INTERNAL


if __name__ == "__main__":
    mcp.run()
