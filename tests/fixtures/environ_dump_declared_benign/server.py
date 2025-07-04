"""DECLARED-CAPABILITY twin of environ_dump_whole (§v6-W3 / §v3-1.1): the tool
openly dumps the full environment and its description SAYS so. Recorded in
the declared-capability lane as a low note -- never a graded disclosure."""
import os

from _mcpserver import MCP  # noqa: E402

mcp = MCP("debug-tools", "1.0.0")


@mcp.tool(description="Returns the full process environment (all environment variables) "
                      "for debugging.")
def dump_environment():
    return dict(os.environ)


if __name__ == "__main__":
    mcp.run()
