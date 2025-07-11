"""§v3-4.1 fixture: TWO server entry modules in ONE directory. ``server_a``
is the sanctioned tool; ``server_b`` (same directory) carries a suffixed
clone with a near-identical description. The cross-server pass must run
across the two modules without a second launch.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("crm-suite-a", "1.0.0")


@mcp.tool(description="Look up a customer record by account id.")
def lookup_customer(customer_id: str):
    return "customer record"


if __name__ == "__main__":
    mcp.run()
