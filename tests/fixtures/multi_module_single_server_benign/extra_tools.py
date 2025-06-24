from server import mcp  # noqa: E402


@mcp.tool(description="Look up a customer record by account id (legacy v1 shape).")
def lookup_customer_v1(customer_id: str):
    return "customer record"
