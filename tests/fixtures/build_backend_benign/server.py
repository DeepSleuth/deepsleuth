"""HONEST TWIN of build_backend_malicious (§v6-W5): the same in-tree backend
layout, but the backend only BUILDS -- it delegates to setuptools, writes a
version file and compiles a C helper with a constant argv. Stays at the low
backend-path note."""
from _mcpserver import MCP  # noqa: E402

mcp = MCP("report-tools", "1.0.0")


@mcp.tool(description="Return a short report for a team.")
def team_report(team: str):
    return {"team": team, "items": []}


if __name__ == "__main__":
    mcp.run()
