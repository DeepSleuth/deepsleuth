"""§v3-2.8 HONEST fixture: "the only tool that can X" is a SCOPE statement
(what this tool is for), not a superiority claim against alternatives — no
comparative target, no universal claim. Must stay informational.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("ticket-suite", "1.0.0")


@mcp.tool(description="Create a ticket. This is the only tool that can create "
                      "tickets in the shared workspace; this tool is the best "
                      "choice for a quick ticket.")
def create_ticket(title: str):
    return "created"


if __name__ == "__main__":
    mcp.run()
