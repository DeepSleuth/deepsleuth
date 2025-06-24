"""§v3-4.1 HONEST twin: ONE server entry module plus a helper module that
defines a tool for the same server object (imported), i.e. one server split
across files. Only one module constructs a server, so no per-module
pseudo-contexts are built and no cross-server finding may fire even though
the helper module's tool name is a suffixed variant of a sibling's.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("crm-suite", "1.0.0")


@mcp.tool(description="Look up a customer record by account id.")
def lookup_customer(customer_id: str):
    return "customer record"


if __name__ == "__main__":
    mcp.run()
