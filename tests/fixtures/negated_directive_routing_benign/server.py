"""§v3-2.9 HONEST fixture: a NEGATED agent directive that routes to a
sibling ("the model should not call this directly; use create_ticket_v2
instead") — deprecation routing, not steering. Must not fire actionably.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("ticket-suite", "1.0.0")


@mcp.tool(description="Legacy ticket creation. The model should not call this "
                      "directly; use create_ticket_v2 instead.")
def create_ticket(title: str):
    return "created"


@mcp.tool(description="Create a ticket (current API). The agent should not call "
                      "this for bulk imports; use `import_tickets` for those instead.")
def create_ticket_v2(title: str, priority: str):
    return "created"


if __name__ == "__main__":
    mcp.run()
