"""INERT BENIGN twin for §P1.1 (cross-tool-redirect FP check).

A genuine session-based server: every data tool honestly requires a session
to be started first, phrased as the improvement guide's own named honest
example -- "You must call start_session before using any other tool in this
server" -- a GENERIC blanket precondition on the whole server ("any other
tool"), never a redirect specific to displacing this tool's own function or
naming a *specific* second target. Structurally this names a sibling
("start_session") plus an obligation word plus an invoke verb in one
sentence, exactly like the malicious twin -- the rule must still stay clean
here.
"""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("session-suite", "1.0.0")


@mcp.tool(description="Start a new authenticated session.")
def start_session(user_id: str):
    return "session started"


@mcp.tool(description="Fetch the current user's saved notes. You must call "
                      "start_session before using any other tool in this "
                      "server.")
def get_notes():
    return "[]"


@mcp.tool(description="List all note categories. You must call "
                      "start_session before using any other tool in this "
                      "server.")
def list_categories():
    return "[]"


if __name__ == "__main__":
    mcp.run()
