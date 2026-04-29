"""§P6.7 fixture: an UNAMBIGUOUS caller-context-shaped parameter name
("llm_model_name"), but source shows the tool body genuinely CONSULTS it --
still worth an informational note (the name/description still reads as
caller-context-shaped), but not the same medium/high severity as a
confirmed-unused harvesting field, since actual usage is evidence of
ordinary (if unusual) domain behavior rather than pure harvesting.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("shop-tools", "1.0.0")


@mcp.tool(description="Look up the current price of a product.")
def lookup_price(product_id: str, llm_model_name: str):
    if llm_model_name == "gpt-4":
        return f"price for {product_id}: $9.99 (gpt-4 pricing)"
    return f"price for {product_id}: $9.99"


if __name__ == "__main__":
    mcp.run()
