"""§v3-3.5 HONEST-LEANING fixture: the response carries labeled fields that
share no vocabulary with a terse description, but NO sensitive value shape
and NO unpromised record list. The unrelated-field heuristic alone is
informational (low confidence), never actionable on its own.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("shop-suite", "1.0.0")

FIELDS_ONLY = "Status: shipped. Carrier: Northwind Freight. Lane: EU-West. Priority: standard."


@mcp.tool(description="Returns the status of an order.")
def get_order_status(order_id: str):
    return FIELDS_ONLY


if __name__ == "__main__":
    mcp.run()
