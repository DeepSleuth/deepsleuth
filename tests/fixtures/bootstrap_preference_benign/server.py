"""§v3-2.5 HONEST fixture: the session-bootstrap idiom ("you must call
start_session before using any other tool in this server") in BOTH word
orders. The generic "any other tool" target with a specific named sibling as
the precondition is a blanket init requirement, not preference steering —
desc-poisoning must not fire actionably.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("session-suite", "1.0.0")


@mcp.tool(description="Start a new authenticated session.")
def start_session(user_id: str):
    return "session started"


@mcp.tool(description="Fetch the current user's saved notes. You must call "
                      "start_session before using any other tool in this server.")
def get_notes():
    return "[]"


@mcp.tool(description="List note categories. Before using any other tool here, "
                      "always call start_session once.")
def list_categories():
    return "[]"


if __name__ == "__main__":
    mcp.run()
