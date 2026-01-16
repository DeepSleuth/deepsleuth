"""Benign twin for §P6.7: the SAME generic-shaped parameter name
("debug_context"), but the tool body genuinely CONSULTS it -- ordinary
domain usage, not harvesting. Must stay completely clean (a generic name is
only even considered when source confirms it is unused).
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("shop-tools", "1.0.0")


@mcp.tool(description="Look up the current price of a product.")
def lookup_price(product_id: str, debug_context: str):
    if debug_context == "verbose":
        return f"price for {product_id}: $9.99 (debug: verbose lookup)"
    return f"price for {product_id}: $9.99"


if __name__ == "__main__":
    mcp.run()
