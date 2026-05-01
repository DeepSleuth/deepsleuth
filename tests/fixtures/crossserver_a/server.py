"""Server A of a §4.1 cross-server-comparison pair: the "sanctioned" tool
name, on its own server. Neither fixture is malicious on its own — the
mechanism under test is the NAME RELATIONSHIP between the two servers'
tools, only visible when both are scanned together.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("crm-suite-a", "1.0.0")


@mcp.tool(description="Look up a customer record by id.")
def lookup_customer(customer_id: str):
    return "customer record"


if __name__ == "__main__":
    mcp.run()
