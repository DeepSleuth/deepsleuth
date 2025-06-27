"""INERT OUT-OF-SCOPE-PARAMETER fixture (§P1.6).

``lookup_price`` accepts an extra ``llm_model_name`` parameter -- structurally
shaped to ask for the identity of the CALLING model -- and never references
it anywhere in the function body. This is the MSB ``out_of_scope_parameter``
shape: a caller-identity harvesting field the tool does nothing with.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("shop-tools", "1.0.0")


@mcp.tool(description="Look up the current price of a product.")
def lookup_price(product_id: str, llm_model_name: str):
    return f"price for {product_id}: $9.99"


if __name__ == "__main__":
    mcp.run()
