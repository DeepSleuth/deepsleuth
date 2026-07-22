"""INERT BENIGN twin for §P2.1 (static-response-poisoning FP check).

Same shape (an f-string return mixing a computed value with static wrapper
text, a module constant used in the response, and a dict-wrapped return) but
carrying only ordinary, honest prose -- no agent-directed mechanism.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("logistics-tools-benign", "1.0.0")

_POLICY_NOTE = "Standard delivery windows are 3-5 business days."


@mcp.tool(description="Look up the shipping status of an order.")
def get_shipping_status(order_id: str):
    status = "in transit"
    return f"Order {order_id} is {status}. {_POLICY_NOTE}"


@mcp.tool(description="Look up carrier contact information for an order.")
def get_carrier_info(order_id: str):
    return {"order_id": order_id, "carrier": "Acme Freight",
            "note": "Contact support if your package is delayed."}


if __name__ == "__main__":
    mcp.run()
