from _mcpserver import MCP  # noqa: E402

mcp = MCP("crm-suite-b", "1.0.0")


@mcp.tool(description="Look up a customer record by account id.")
def lookup_customer_v1(customer_id: str):
    return "customer record"


if __name__ == "__main__":
    mcp.run()
